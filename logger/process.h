#ifndef LOGGER_PROCESS_H_
#define LOGGER_PROCESS_H_

/* Callback function for sys_execve_rb ring buffer. */
int sys_execve_callback(void* ctx, void* data, size_t data_sz);

#endif  // LOGGER_PROCESS_H_
