#ifndef LOGGER_PROCESS_H_
#define LOGGER_PROCESS_H_

#include <stddef.h>
#include <string.h>

#include "logger/hash.h"
#include "logger/bpf/feature_probe.h"

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

/* Callback function for sys_execve_buf ring buffer. */
#ifdef HAVE_RINGBUF_MAP_TYPE
int sys_execve_cb(void* ctx, void* data, size_t data_sz);
#else
void sys_execve_cb(void* ctx, int cpu, void* data, unsigned data_sz);
#endif

/* Callback function for sys_clone_buf ring buffer. */
#ifdef HAVE_RINGBUF_MAP_TYPE
int sys_clone_cb(void* ctx, void* data, size_t data_sz);
#else
void sys_clone_cb(void* ctx, int cpu, void* data, unsigned data_sz);
#endif

/* Callback function for sched_process_exit_buf ring buffer. */
#ifdef HAVE_RINGBUF_MAP_TYPE
int sched_process_exit_cb(void* ctx, void* data, size_t data_sz);
#else
void sched_process_exit_cb(void* ctx, int cpu, void* data, unsigned data_sz);
#endif

#endif  // LOGGER_PROCESS_H_
