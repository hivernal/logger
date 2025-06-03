#ifndef LOGGER_BPF_EXECVE_H_
#define LOGGER_BPF_EXECVE_H_

#include "logger/bpf/task.h"

#define ARG_SIZE 128
#define MAX_ARGS 64
#define ARGS_SIZE (ARG_SIZE * MAX_ARGS)
#define LAST_ARG_OFFSET (ARGS_SIZE - ARG_SIZE)

/* Struct contains execve args. */
struct sys_execve_args {
  int dfd;
  char filename[PATH_SIZE];
  char argv[ARGS_SIZE];
};

struct sys_execve {
  int ret;
  struct task task;
  struct sys_execve_args args;
  enum path_type filename_type;
  struct path_name cwd;
};

struct sys_execveat {
  struct sys_execve sys_execve;
  struct path_name dir;
};

struct sched_process_exit {
  int exit_code;
  struct task task;
};

#endif  // LOGGER_BPF_EXECVE_H_
