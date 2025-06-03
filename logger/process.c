#include "logger/process.h"

#include <stdio.h>

#include "logger/helpers.h"
#include "logger/bpf/process.h"

void print_sys_execve(const struct sys_execve* sys_execve) {
  print_task(&sys_execve->task);
  const struct sys_execve_args* args =
      (struct sys_execve_args*)&sys_execve->args;
  printf("Execve:\nfilename: ");
  switch (sys_execve->filename_type) {
    case PATH_ABSOLUTE:
      printf("%s\n", args->filename);
      break;
    case PATH_RELATIVE_CWD:
      print_relative_filename(args->filename, &sys_execve->cwd);
      break;
    case PATH_RELATIVE_FD:
      const struct sys_execveat* sys_execveat =
          (struct sys_execveat*)sys_execve;
      print_relative_filename(args->filename, &sys_execveat->dir);
      break;
  }
  printf("argv: %s\ncwd: %s\nret: %d\n\n", args->argv,
         sys_execve->cwd.data + sys_execve->cwd.offset, sys_execve->ret);
}

int sys_execve_callback(void* ctx UNUSED, void* data UNUSED,
                        size_t data_sz UNUSED) {
  // const struct sys_execve* sys_execve = (struct sys_execve*)data;
  // print_sys_execve(sys_execve);
  return 0;
}
