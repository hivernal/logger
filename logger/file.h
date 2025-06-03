#ifndef LOGGER_FILE_H_
#define LOGGER_FILE_H_

#include <stddef.h>

/* Callback function for file_rb ring buffer. */
int file_callback(void* ctx, void* data, size_t data_sz);

#endif  //  LOGGER_FILE_H_
