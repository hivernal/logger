#ifndef LOGGER_HELPERS_H_
#define LOGGER_HELPERS_H_

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <pwd.h>

#include "logger/bpf/task.h"
#include "logger/list.h"

#define UNUSED __attribute__((unused))

/* Prints substring to the file. */
static inline void fprint_substr(FILE* file, const char* start,
                                 const char* end) {
  for (; start <= end; ++start) fputc(*start, file);
}

static inline void fprint_task_cred(FILE* file, const struct task* task) {
  const struct task_cred* task_cred = &task->cred;
  // uid_t ids[sizeof(*task_cred) / sizeof(task_cred->uid) + 1];
  // struct passwd* getpwnam();
  fprintf(file,
          "loginuid: %u\nuid: %u\ngid: %u\nsuid: %u\nsgid: "
          "%u\neuid: %u\negid: %u\nfsuid: "
          "%u\nfsgid: %u\n",
          task->loginuid, task_cred->uid, task_cred->gid, task_cred->suid,
          task_cred->sgid, task_cred->euid, task_cred->egid, task_cred->fsuid,
          task_cred->fsgid);
}

/* Prints task struct to the file. */
static inline void fprint_task(FILE* file, const struct task* task) {
  fprintf(file,
          "time: %lu\npid: %d\nppid: %d\ntgid %d\ncomm: "
          "%s\nsessionid: %u\n",
          task->time_nsec, task->pid, task->ppid, task->tgid, task->comm,
          task->sessionid);
  fprint_task_cred(file, task);
}

static inline void fprint_hex(FILE* file, const unsigned char* data,
                              size_t len) {
  for (size_t i = 0; i < len; ++i) fprintf(file, "%02x", data[i]);
}

#define print_task(task) fprint_task(stdout, task)
#define print_substr(start, end) fprint_substr(stdout, start, end)

/* Prints filename relative to path_dentries to the file. */
void fprint_relative_filename(FILE* file, const char* filename,
                              const struct path_dentries* path_dentries);
#define print_relative_filename(filename, path_dentries) \
  fprint_relative_filename(stdout, filename, path_dentries)

/*
void fill_relative_filename(char* buffer_start, const char* buffer_end,
                            const char* filename,
                            const struct path_dentries* path_dentries);
*/

struct dentry_range {
  struct list_head node;
  const char* start;
  const char* end;
};

int dentry_ranges_init(struct list_head* list, const char* filename,
                       const struct path_dentries* path_dentries);
void dentry_ranges_delete(struct list_head* list);
void fprint_dentry_ranges(FILE* file, const struct list_head* list);

#endif  //  LOGGER_HELPERS_H_
