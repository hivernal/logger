#include "logger/helpers.h"
#include <stdio.h>

void print_task(const struct task* task) {
  printf(
      "Task:\ntime: %lu\nuid: %d\ngid: %d\npid: %d\nppid: %d\ncomm: "
      "%s\nsessionid: %u\n",
      task->time_nsec, task->uid, task->gid, task->pid, task->ppid, task->comm,
      task->sessionid);
}

int get_path_name_cptrs(struct list* list, const char* path_name) {
  const char* offsets[2];
  int dir_index = 0, count = 0;
  while (*path_name != '\0') {
    if (*path_name == '.') {
      if (*(path_name + 1) == '/') {
        path_name += 2;
        continue;
      } else if (*(path_name + 1) == '.') {
        list->op->pop(list);
        --count;
        if (count < dir_index) dir_index = count;
        path_name += 3;
        continue;
      }
    }
    offsets[0] = path_name;
    for (; *path_name != '\0'; ++path_name) {
      if (*path_name == '/') {
        ++path_name;
        break;
      }
    }
    offsets[1] = path_name;
    list->op->push(list, &offsets, sizeof(offsets));
    ++count;
  }
  return dir_index;
}

const char* get_dir_cptr(const struct path_name* path_name, int dir_index) {
  const char* cptr = path_name->data + sizeof(path_name->data) - 3;
  const char* const start = path_name->data + path_name->offset;
  for (; cptr >= start; --cptr) {
    if (*cptr == '/') {
      if (!(++dir_index)) break;
    }
  }
  return cptr;
}

int print_path_name_cptr(void* node_data, void* data __attribute__((unused))) {
  const char** offsets = node_data;
  print_substr(offsets[0], offsets[1]);
  return 0;
}

void print_substr(const char* start, const char* end) {
  for (; start <= end; ++start) putchar(*start);
}

void print_relative_filename(const char* filename,
                             const struct path_name* path_name) {
  struct list* list = list_init();
  if (!list) return;
  int dir_index = get_path_name_cptrs(list, filename);
  const char* cptr = get_dir_cptr(path_name, dir_index);
  print_substr(path_name->data + path_name->offset, cptr);
  list->op->for_each(list, NULL, print_path_name_cptr);
  putchar('\n');
  list->op->delete(list);
}
