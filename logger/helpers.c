#include "list.h"

#include <stdio.h>
#include <stdlib.h>

void get_path_offsets(struct list* list, const char* path) {
  const char* offsets[2];
  while (*path != '\0') {
    if (*path == '.') {
      if (*(path + 1) == '/') {
        path += 2;
        continue;
      } else if (*(path + 1) == '.') {
        list->op->pop(list);
        path += 3;
        continue;
      }
    }
    offsets[0] = path;
    for (; *path != '\0'; ++path) {
      if (*path == '/') {
        ++path;
        break;
      }
    }
    if (*path == '/') ++path;
    offsets[1] = path;
    list->op->push(list, &offsets, sizeof(offsets));
  }
}

void print(void* node_data, void* data) {
  const char** offsets = node_data;
  const char* path = data;
  for (const char* ptr = offsets[0]; ptr != offsets[1]; ++ptr) putchar(*ptr);
}
