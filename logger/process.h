#ifndef LOGGER_PROCESS_H_
#define LOGGER_PROCESS_H_

#include <stddef.h>
#include <string.h>

#include "logger/hash.h"

/* Additional data for the sys_execve_cb function. */
struct sys_execve_cb_data {
  struct hash* hash;
  const char* filename;
};

static inline int sys_execve_cb_data_init(struct sys_execve_cb_data* data,
                                          const char* alg,
                                          const char* filename) {
  data->filename = filename;
  data->hash = hash_init(alg);
  return !data->hash;
};

static inline void sys_execve_cb_data_delete(struct sys_execve_cb_data* data) {
  if (data->hash) hash_delete_ptr(data->hash);
}

/* Callback function for sys_execve_rb ring buffer. */
int sys_execve_cb(void* ctx, void* data, size_t data_sz);

/* Callback function for sys_clone_rb ring buffer. */
int sys_clone_cb(void* ctx, void* data, size_t data_sz);

/* Callback function for sched_process_exit_rb ring buffer. */
int sched_process_exit_cb(void* ctx, void* data, size_t data_sz);

#endif  // LOGGER_PROCESS_H_
