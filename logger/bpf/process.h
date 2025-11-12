#ifndef LOGGER_BPF_PROCESS_H_
#define LOGGER_BPF_PROCESS_H_

#include "logger/bpf/task.h"

#define ARG_SIZE 128
#define MAX_ARGS 64
#define ARGS_SIZE (ARG_SIZE * MAX_ARGS)
#define LAST_ARG_OFFSET (ARGS_SIZE - ARG_SIZE)

/* Struct contains sys_enter_execve and sys_enter_execveat data. */
struct sys_enter_process {
  int error;
  /*
   * The file descriptor of the  directory of the executable file.
   * Can be the current working directory.
   */
  int fd;
  /*
   * A binary executable, or a script name.
   * Relative to the directory reffered to by the file descriptor dfd.
   */
  char filename[PATH_SIZE];
  /* sys_enter_execve, sys_enter_execveat argv. */ 
  char argv[ARGS_SIZE];
  /* sys_enter_clone, sys_enter_clone3 flags. */
  uint64_t flags;
  /* Flag for checking errors. */
  int is_correct;
};

/* Struct contains sys_enter_execve and sys_enter_execveat data. */
struct sys_enter_execve {
  int error;
  /*
   * The file descriptor of the parent directory of the executable file.
   * Can be the current working directory.
   */
  int dfd;
  /*
   * A binary executable, or a script name.
   * Relative to the directory reffered to by the file descriptor dfd.
   */
  char filename[PATH_SIZE];
  /* Arguments. */ 
  char argv[ARGS_SIZE];
  /* Flag for checking errors. */
  int is_correct;
};

/*
 * P'(ambient) = (file is privileged) ? 0 : P(ambient)
 * P'(permitted) = (P(inheritable) & F(inheritable)) | (F(permitted) & P(bounding)) | P'(ambient)
 * P'(effective) = F(effective) ? P'(permitted) : P'(ambient)
 * P'(inheritable) = P(inheritable) [i.e., unchanged]
 * P'(bounding) = P(bounding) [i.e., unchanged]
 */

/* P() denotes the value of a thread capability set before the execve.
 * P'() denotes the value of a thread capability set after the execve.
 * F() denotes a file capability set.
 */

struct task_caps {
  /* Caps that can be inherited by the child task. */
  unsigned long long inheritable;
  /* Caps that can be used by the task. */
  unsigned long long permitted; 
  /* Caps that are actually used by the task. */
  unsigned long long effective;
  /*
   * Bounding caps.
   * Can be used to limit the caps that are gained during execve.
   */
  unsigned long long bset;
  /* Ambient caps. Since linux 4.3 */
  unsigned long long ambient; 
};

/* Struct for execve syscall. */
struct sys_execve {
  /* execve returned value. */
  int ret;
  struct task task;
  /*
   * A binary executable, or a script name.
   * Relative to the directory reffered to by the file descriptor dfd.
   */
  char filename[PATH_SIZE];
  /* Arguments. */ 
  char argv[ARGS_SIZE];
  enum path_type filename_type;
  /* Task capabilities. */
  struct task_caps caps;
  /* Current working directory of the task. */
  struct path_dentries cwd;
  int error;
};

/* Struct for execveat syscall. */
struct sys_execveat {
  struct sys_execve sys_execve;
  /*
   * The parent directory of the executable file.
   * Can't be the current working directory.
   */
  struct path_dentries dir;
};

/* Struct for clone and clone3 syscalls. */
struct sys_clone {
  struct task task;
  uint64_t flags;
  int error;
  int ret;
};

/* Struct for sched_process_exit. Process exit. */
struct sched_process_exit {
  int exit_code;
  int group_dead;
  int error;
  struct task task;
};

#endif  // LOGGER_BPF_PROCESS_H_
