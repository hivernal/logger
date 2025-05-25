#ifndef LOGGER_HELPERS_H_
#define LOGGER_HELPERS_H_

#include <stdlib.h>
#include <stdint.h>

#include "logger/list.h"
#include "logger/bpf/task.h"

void print_task(const struct task* task);
int get_path_name_cptrs(struct list* list, const char* path_name);
int print_path_name_cptr(void* node_data, void* data);
const char* get_dir_cptr(const struct path_name* path_name, int dir_index);
void print_substr(const char* start, const char* end);
void print_relative_filename(const char* filename,
                             const struct path_name* path_name);

#endif  //  LOGGER_HELPERS_H_
