/**
 * File: stsh.cc
 * -------------
 * Defines the entry point of the stsh executable.
 */

#include "stsh.h"

#include <assert.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>  // for fork
#include <algorithm>
#include <array>
#include <csignal>  // for kill
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include "fork-utils.h"  // this needs to be the last #include in the list
#include "stsh-exception.h"
#include "stsh-job-list.h"
#include "stsh-job.h"
#include "stsh-parser/stsh-parse-exception.h"
#include "stsh-parser/stsh-readline.h"
#include "stsh-process.h"
#include "stsh-parse-utils.h"

using namespace std;

#define READ_END 0
#define WRITE_END 1

/**
 * Function: configureSignals
 *
 * This function sets up the signal handling behavior of the shell before it is launched.
 */
void STSHShell::configureSignals() {
  signal(SIGQUIT, [](int sig) { exit(0); });
  signal(SIGTTIN, SIG_IGN);
  signal(SIGTTOU, SIG_IGN);

  sigemptyset(&blocklist);
  sigaddset(&blocklist, SIGINT);
  sigaddset(&blocklist, SIGTSTP);
  sigaddset(&blocklist, SIGCHLD);
  sigprocmask(SIG_BLOCK, &blocklist, NULL);
}

/**
 * map: kBuiltInCommands
 *
 * Defines a mapping of commands as typed by the user to the Builtin enum
 * (defined in stsh.h). Any aliases are defined here (e.g. "quit" and "exit"
 * are the same).
 */
const map<string, STSHShell::Builtin> STSHShell::kBuiltinCommands = {
    {"quit", STSHShell::Builtin::QUIT},
    {"exit", STSHShell::Builtin::QUIT},
    {"fg", STSHShell::Builtin::FG},
    {"bg", STSHShell::Builtin::BG},
    {"slay", STSHShell::Builtin::SLAY},
    {"halt", STSHShell::Builtin::HALT},
    {"cont", STSHShell::Builtin::CONT},
    {"jobs", STSHShell::Builtin::JOBS},
};

/**
 * Function: run
 *
 * Runs the REPL loop: take input from the user, executes commands, and repeats.
 */
void STSHShell::run(int argc, char *argv[]) {
  pid_t stshpid = getpid();
  rlinit(argc, argv);
  while (true) {
    string line;
    if (!readline(line)) break;
    if (line.empty()) continue;
    try {
      pipeline p(line);
      if (kBuiltinCommands.contains(p.commands[0].command)) {
        Builtin command = kBuiltinCommands.at(p.commands[0].command);
        handleBuiltin(command, p.commands[0].tokens);
      } else {
        createJob(p);
      }
    } catch (const STSHException &e) {
      cerr << e.what() << endl;
      if (getpid() != stshpid) exit(0);  // if exception is thrown from child process, kill it
    }
  }
}

/**
 * Function: createJob
 *
 * Creates a new job for the provided pipeline. Spawns child processes with input/output redirected
 * to the appropriate pipes and/or files, and updates the joblist to keep track of these processes.
 */
void STSHShell::createJob(const pipeline &p) {
  STSHJob &job = joblist.addJob(kForeground);
  if (p.background) {
    job.setState(kBackground);
  }

  pid_t pid;
  pid_t pgid = 0;
  size_t commandCount = p.commands.size();

  vector<array<int, 2>> multifds(commandCount);
  if (commandCount > 1) {
    pipeAllfds(commandCount, multifds);
  }

  for (size_t processIndex = 0; processIndex < commandCount; processIndex++) {
    pid = fork();
    if (pid == 0) {
      sigprocmask(SIG_UNBLOCK, &blocklist, NULL);
      childGroupSetup(processIndex, pid, pgid);
      if (!p.background && tcsetpgrp(STDIN_FILENO, pgid) == -1) {
      throw STSHException("Error: tcsetpgrp failed to grant the job control upon creation.");
      }
      buildPipeMechanics(p, processIndex, commandCount, multifds);
      launchCommand(p, processIndex);
    }
    job.addProcess(STSHProcess(pid, p.commands[processIndex]));
    parentGroupSetup(processIndex, pid, pgid);
    
  }

  

  if (commandCount > 1) {
    closeAllfds(commandCount, multifds);
  }

  if (job.getState() == kForeground) {
    waitJobSignals();
  } 
  else {
    cout << "[" << job.getNum() << "] " << flush;
    vector<STSHProcess> &currentProcesses = job.getProcesses();
    for (STSHProcess &currentProcess : currentProcesses) {
      cout << currentProcess.getID() << " " << flush;
    }
    cout << endl;
  }
}

/**
 * function: setupOutputfd
 *
 * Sets up the file descriptor needed to push the output of the shell to a file.
 */
int STSHShell::setupOutputfd(const pipeline &p) {
  int outputfd;
  outputfd = open(p.output.c_str(), O_WRONLY | O_TRUNC);
  if (outputfd == -1 && errno == ENOENT) {
    outputfd = open(p.output.c_str(), O_WRONLY | O_CREAT, 0644);
  }
  return outputfd;
}

/**
 * function: pipeAllfds
 *
 * Opens the appropriate number of pipes for the command sequence recieved by the shell.
 */
void STSHShell::pipeAllfds(const size_t &commandCount, vector<array<int, 2>> &multifds) {
  for (size_t commandIndex = 0; commandIndex < commandCount; commandIndex++) {
    pipe2(multifds[commandIndex].data(), O_CLOEXEC);
  }
}

/**
 * function: buildPipeMechanics
 *
 * Chains the file descriptors together to allow for chains of any length to pass information.
 */
void STSHShell::buildPipeMechanics(const pipeline &p, const size_t processIndex, const size_t commandCount, vector<array<int, 2>> &multifds) {
  if (processIndex == 0) {  // Case: first executable in chain.
    if (!p.input.empty()) {
      int inputfd;
      inputfd = open(p.input.c_str(), O_RDONLY);
      dup2(inputfd, STDIN_FILENO);
      close(inputfd);
    }
    if (commandCount > 1) {  // Only need to make changes if there is another executable.
      dup2(multifds[processIndex][WRITE_END], STDOUT_FILENO);
    } 
    else if (!p.output.empty()) {  // Only need to setup output file here in single-command case.
      int outputfd = setupOutputfd(p);
      dup2(outputfd, STDOUT_FILENO);
      close(outputfd);
    }
  } 
  else if (processIndex == commandCount - 1) {  // Case: final executable in chain.
    if (!p.output.empty()) {
      int outputfd = setupOutputfd(p);
      dup2(outputfd, STDOUT_FILENO);
      close(outputfd);
    }
    dup2(multifds[processIndex - 1][READ_END], STDIN_FILENO);
  } 
  else {  // Case: middle executable in chain.
    dup2(multifds[processIndex - 1][READ_END], STDIN_FILENO);
    dup2(multifds[processIndex][WRITE_END], STDOUT_FILENO);
  }
}

/**
 * function: closeAllfds
 *
 * Closes the pipes for the command sequence recieved by the shell.
 */
void STSHShell::closeAllfds(const size_t &commandCount, vector<array<int, 2>> &multifds) {
  for (size_t commandIndex = 0; commandIndex < commandCount; commandIndex++) {
    close(multifds[commandIndex][READ_END]);
    close(multifds[commandIndex][WRITE_END]);
  }
}

/**
 * function: launchCommand
 *
 * Parses the arguments passed to the shell and calls execvp to convert the child process to the desired program.
 */
void STSHShell::launchCommand(const pipeline &p, const size_t processIndex) {
  char *process_argv[kMaxArguments + 1] = {NULL};
  process_argv[0] = (char *)(p.commands[processIndex].command);
  for (size_t argIndex = 0; p.commands[processIndex].tokens[argIndex] != NULL; argIndex++) {
    process_argv[argIndex + 1] = p.commands[processIndex].tokens[argIndex];
  }
  if (execvp(process_argv[0], process_argv) == -1) {
    string execName(process_argv[0]);
    throw STSHException(execName + ": Command not found.");
  }
}

/**
 * function: parentGroupSetup
 *
 * Sets up the process group for the shell commands on the parent side.
 */
void STSHShell::parentGroupSetup(const size_t processIndex, pid_t &pid, pid_t &pgid) {
  if (processIndex == 0) {
    pgid = pid;            // Set the pgid to the first command pid.
    setpgid(pid, pid);     // Create the pgid with the first command pid.
  } 
  else if (pgid != 0) {  // Make sure pgid has been set.
    setpgid(pid, pgid);    // Add pid to the pgid.
  }
}

/**
 * function: childGroupSetup
 *
 * Sets up the process group for the shell commands on the child side.
 */
void STSHShell::childGroupSetup(const size_t processIndex, pid_t &pid, pid_t &pgid) {
  if (processIndex == 0) {
    pgid = getpid();          // Set the pgid to the first command pid.
    setpgid(pgid, pgid);      // Create the pgid with the first command pid.
  } 
  else if (pgid != 0) {     // Make sure pgid has been set.
    setpgid(getpid(), pgid);  // Add pid to the pgid.
  }
}

/**
 * function: pidLookup
 *
 * Accepts an array of string arguments and returns the pid associated with the arguments.
 * Provides a usage guide string to the user in the case of invalid input.
 */
pid_t STSHShell::pidLookup(const char *const arguments[], const string &usageGuide) {
  if (arguments[0] == NULL || arguments[2] != NULL) { // Case 1: 0 or > 2 arguments (error).
    throw STSHException(usageGuide);
  }

  if (arguments[1] != NULL) { // Case 2: 2 arguments.
    const size_t jobNum = jobLookup(arguments, 2, usageGuide);
    if (!joblist.containsJob(jobNum)) {
      throw STSHException("No job with id of " + to_string(jobNum) + ".");
    }
    vector<STSHProcess> &processes = joblist.getJob(jobNum).getProcesses();
    const size_t desiredProcess = parseNumber(arguments[1], usageGuide);

    if (desiredProcess >= processes.size()) {
      throw STSHException("Job " + to_string(jobNum) + " doesn't have a process at index " + to_string(desiredProcess) + ".");
    }
    return processes[desiredProcess].getID();
  }
  
  // Case 3: One argument.
  const size_t desiredpid = parseNumber(arguments[0], usageGuide);
  if (!joblist.containsProcess(desiredpid)) {
    throw STSHException("No process with pid " + to_string(desiredpid) + ".");
  }
  return joblist.getJobWithProcess(desiredpid).getProcess(desiredpid).getID();
}

/**
 * function: jobLookup
 *
 * Accepts an array of string arguments and a max argument count.
 * Determines the intended format of the user arguments and returns the job number referred to.
 * Provides a usage guide string to the user in the case of invalid input.
 */
size_t STSHShell::jobLookup(const char *const arguments[], const int maxArgs, const string &usageGuide) {
  if (arguments[maxArgs] != NULL) {
    throw STSHException(usageGuide);
  }
  const size_t jobNum = parseNumber(arguments[0], usageGuide);
  return jobNum;
}

/**
 * function: continueJob
 *
 * Accepts a job number and a foreground/background status and resumes the job with the given status.
 * Returns control of the terminal to the job if foreground.
 */
void STSHShell::continueJob(const bool foreground, const size_t jobNum) {
  // Ensures that the requested job is a match for an existing job.
  if (!joblist.containsJob(jobNum)) {
    const string message = (foreground ? "fg " : "bg ") + to_string(jobNum) + ": No such job.";
    throw STSHException(message);
  }

  // Continues the job and sets its state as appropriate.
  STSHJob &job = joblist.getJob(jobNum);
  killpg(job.getGroupID(), SIGCONT);
  foreground ? job.setState(kForeground) : job.setState(kBackground);

  // Returns control of the terminal to the job upon job continuation.
  if (foreground) {
    if (tcsetpgrp(STDIN_FILENO, joblist.getJob(jobNum).getGroupID()) == -1) {
      throw STSHException("Error: tcsetpgrp failed to grant the job control upon continuation.");
    }
  }
}

/**
 * function: waitJobSignals
 *
 * Clears all pending SIGINT and SIGTSTP signals and then waits for the child or user to send a signal.
 * Handles SIGINT, SIGTSTP, and SIGCHLD signals (the last with the help of function updateChildrenStatus).
 */
void STSHShell::waitJobSignals() {
  signal(SIGINT, SIG_IGN);
  signal(SIGTSTP, SIG_IGN);
  signal(SIGINT, SIG_DFL);
  signal(SIGTSTP, SIG_DFL);
  while (joblist.hasForegroundJob()) {
    int sigNum;
    sigwait(&blocklist, &sigNum);
    if (sigNum == SIGINT || sigNum == SIGTSTP) {
      STSHJob &currentJob = joblist.getForegroundJob();
      killpg(currentJob.getGroupID(), sigNum);
    } 
    else {
      updateChildrenStatus();
    }
  }

  // Returns control of the terminal to the shell upon conclusion of the fg job.
  if (tcsetpgrp(STDIN_FILENO, getpgrp()) == -1) {
    throw STSHException("Error: tcsetpgrp failed to grant the shell control.");
  }
}

/**
 * function: updateChildrenStatus
 *
 * Called when the parent recieves a SIGCHLD to update the status of all children.
 */
void STSHShell::updateChildrenStatus() {
  while (true) {
    int status;
    pid_t childpid = waitpid(-1, &status, WUNTRACED | WCONTINUED | WNOHANG);
    if (childpid <= 0) {
      break;
    }

    STSHJob &currentJob = joblist.getJobWithProcess(childpid);
    assert(currentJob.containsProcess(childpid));
    STSHProcess &currentProcess = currentJob.getProcess(childpid);

    if (WIFCONTINUED(status)) {
      currentProcess.setState(kRunning);
    } 
    else if (WIFSTOPPED(status)) {
      currentProcess.setState(kStopped);
    } 
    else if (WIFEXITED(status) || WIFSIGNALED(status)) {
      currentProcess.setState(kTerminated);
    }
    joblist.synchronize(currentJob);
  }
}

/**
 * function: handleBuiltIn
 *
 * Handles execution of builtin commands as defined in the STSHShell::Builtin enum.
 */
void STSHShell::handleBuiltin(Builtin command, const char *const arguments[]) {
  // Program-level commands.
  if (command == Builtin::QUIT) {
    exit(0);
  } 
  else if (command == Builtin::JOBS) {
    updateChildrenStatus();
    cout << joblist;
  }
  // Job-level commands. 
  else if (command == Builtin::FG) {
    continueJob(true, jobLookup(arguments, 1, "Usage: fg <jobid>."));
    waitJobSignals();
  } 
  else if (command == Builtin::BG) {
    continueJob(false, jobLookup(arguments, 1, "Usage: bg <jobid>."));
  } 
  // Process-level commands.
  else if (command == Builtin::SLAY) {
    kill(pidLookup(arguments, "Usage: slay <jobid> <index> | <pid>."), SIGKILL);
  } 
  else if (command == Builtin::HALT) {
    kill(pidLookup(arguments, "Usage: halt <jobid> <index> | <pid>."), SIGTSTP);
  } 
  else if (command == Builtin::CONT) {
    kill(pidLookup(arguments, "Usage: cont <jobid> <index> | <pid>."), SIGCONT);
  }
}

/**
 * Defines the entry point for a process running stsh.
 */
int main(int argc, char *argv[]) {
  STSHShell shell;
  shell.configureSignals();
  shell.run(argc, argv);
  return 0;
}
