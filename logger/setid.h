#ifndef LOGGER_SETID_H_
#define LOGGER_SETID_H_

#include <stddef.h>
#include "logger/bpf/feature_probe.h"

#ifdef HAVE_RINGBUF_MAP_TYPE

/* Callback function for sys_setid_buf ring buffer. */
int sys_setid_cb(void* ctx, void* data, size_t data_sz);

#else

/* Callback function for sys_setid_buf perf buffer. */
void sys_setid_cb(void* ctx, int cpu, void* data, unsigned data_sz);

#endif

#endif  // LOGGER_SETID_H_
