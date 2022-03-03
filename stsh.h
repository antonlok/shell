#pragma once

#include "stsh-job-list.h"
#include "stsh-parser/stsh-parse.h"

#include <vector>
#include <array>

using namespace std;

class STSHShell {
public:
  void configureSignals();
  void run(int argc, char *argv[]);

private:
  enum Builtin {QUIT, FG, BG, SLAY, HALT, CONT, JOBS};
  static const map<string, Builtin> kBuiltinCommands;
  sigset_t blocklist;

  STSHJobList joblist;

  // Job creation helper functions.
  void createJob(const pipeline& p);
  int setupOutputfd(const pipeline &p);
  void pipeAllfds(const size_t &commandCount, vector<array<int, 2>>& multifds);
  void buildPipeMechanics(const pipeline &p, const size_t processIndex, const size_t commandCount, vector<array<int, 2>>& multifds);
  void closeAllfds(const size_t &commandCount, vector<array<int, 2>>& multifds);
  void launchCommand(const pipeline &p, const size_t processIndex);

  // Process group ID handling functions.
  void parentGroupSetup(const size_t processIndex, pid_t &pid, pid_t &pgid);
  void childGroupSetup(const size_t processIndex, pid_t &pid, pid_t &pgid);

  // Job control helper functions.
  pid_t pidLookup(const char *const arguments[], const string &usageGuide);
  size_t jobLookup(const char *const arguments[], const int maxArgs, const string &usageGuide);
  void continueJob(const bool foreground, const size_t jobNum);
  void waitJobSignals();
  void updateChildrenStatus();

  // User interface helper function.
  void handleBuiltin(Builtin command, const char *const arguments[]);
  
  
  
  
  
  

  
  

};
