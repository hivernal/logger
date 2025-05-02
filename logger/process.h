#ifndef LOGGER_EXECVE_H_
#define LOGGER_EXECVE_H_

#include "task.h"

#define ARGSIZE 128
#define TOTAL_MAX_ARGS 60
#define DEFAULT_MAXARGS 20
#define FULL_MAX_ARGS_ARR (TOTAL_MAX_ARGS * ARGSIZE)
#define LAST_ARG (FULL_MAX_ARGS_ARR - ARGSIZE)
#define PATH_MAX 4096

struct sys_execve {
  struct task task;
  char pwd[PATH_MAX];
  char argv[FULL_MAX_ARGS_ARR];
  int pwd_size;
  int ret;
};

struct sched_process_exit {
  struct task task;
  int exit_code;
};

#endif  // LOGGER_EXECVE_H_
