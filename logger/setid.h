#ifndef LOGGER_SETID_H_
#define LOGGER_SETID_H_

#include <stddef.h>
#include "logger/bpf/feature_probe.h"

/* Callback function for sys_setid_buf ring buffer. */
#ifdef HAVE_RINGBUF_MAP_TYPE
int sys_setid_cb(void* ctx, void* data, size_t data_sz);
#else
void sys_setid_cb(void* ctx, int cpu, void* data, unsigned data_sz);
#endif

#endif  // LOGGER_SETID_H_
