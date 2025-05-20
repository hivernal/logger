#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "logger/bpf/process.h"

int sys_execve_callback(void* ctx, void* data, size_t data_sz) {
  const struct sys_execve* sys_execve = (struct sys_execve*)data;
  printf("Execve: %d %d %d %d %d %s %s %s %d %s\n", sys_execve->task.uid,
         sys_execve->task.gid, sys_execve->task.pid, sys_execve->task.ppid,
         sys_execve->ret, sys_execve->task.comm, sys_execve->args.pathname,
         sys_execve->args.argv, sys_execve->cwd.offset,
         sys_execve->cwd.data + sys_execve->cwd.offset);
  return 0;
}
