#include "logger/file.h"

#include <stdio.h>

#include "logger/helpers.h"
#include "logger/bpf/file.h"

#define O_ACCMODE	00000003
#define O_RDONLY	00000000
#define O_WRONLY	00000001
#define O_RDWR		00000002
#define O_CREAT 00000100
#define O_EXCL 00000200
#define O_TRUNC 00001000
#define O_APPEND 00002000
#define O_DIRECTORY 00200000
#define __O_TMPFILE 020000000
#define O_TMPFILE (__O_TMPFILE | O_DIRECTORY)

int file_callback(void* ctx UNUSED, void* data UNUSED, size_t data_sz UNUSED) {
  const struct write* write = (struct write*)data;
  print_task(&write->task);
  printf("Write:\npath: %s\nbuffer:\n%s\ncount: %lu\nret: %d\nflags: 0x%x 0x%x\npos: %ld\n",
         write->path_name.data + write->path_name.offset, write->args.buffer,
         write->args.count, write->ret, write->args.flags, write->args.mode, write->args.pos);
  if (write->args.flags & O_CREAT) printf("O_CREAT ");
  if (write->args.flags & O_EXCL) printf("O_EXCL ");
  if (write->args.flags & O_TRUNC) printf("O_TRUNC ");
  if (write->args.flags & O_APPEND) printf("O_APPEND ");
  if (write->args.flags & O_TMPFILE) printf("O_TMPFILE ");
  if (write->args.flags & O_RDONLY) printf("O_RDONLY ");
  if (write->args.flags & O_WRONLY) printf("O_WRONLY ");
  if (write->args.flags & O_RDWR) printf("O_RDWR ");
  printf("\n");
  printf("\n");
  return 0;
}
