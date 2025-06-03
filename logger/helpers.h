#ifndef LOGGER_HELPERS_H_
#define LOGGER_HELPERS_H_

#include <stdlib.h>
#include <stdint.h>

#include "logger/list.h"
#include "logger/bpf/task.h"

#define UNUSED __attribute__((unused))

void print_task(const struct task* task);

void print_substr(const char* start, const char* end);

void print_relative_filename(const char* filename,
                             const struct path_name* path_name);

struct text {
  size_t buffer_size;
  int lines_size;
  int lines_reserved;
  char* buffer;
  const char** lines;
};

struct text* text_file_init(const char* filename);
// struct text* text_buffer_init(const char* filename);
void text_delete(struct text* text);

#endif  //  LOGGER_HELPERS_H_
