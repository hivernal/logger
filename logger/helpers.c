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
        list->vt->pop_back(list);
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
    list->vt->push_back(list, &offsets, sizeof(offsets));
    ++count;
  }
  return dir_index;
}

const char* get_dir_cptr(const struct path_name* path_name, int dir_index) {
  /* The last symbol before '\0'. */
  const char* cptr = path_name->data + sizeof(path_name->data) - 2;
  if (!dir_index) return cptr;
  --cptr;
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
  list->vt->for_each(list, NULL, print_path_name_cptr);
  putchar('\n');
  list->vt->delete(list);
}

#define LINES_RESERVED_DEFAULT 256

long read_text_file(struct text* text, FILE* file) {
  long pos = ftell(file);
  if (pos == -1) return pos;
  char* ptr;
  while ((ptr = fgets(text->buffer + pos,
                      (int)(text->buffer_size - (size_t)pos + 2), file))) {
    if (text->lines_size >= text->lines_reserved) {
      text->lines_reserved <<= 2;
      text->lines = realloc(text->lines,
                            sizeof(const char*) * (size_t)text->lines_reserved);
    }
    text->lines[text->lines_size] = ptr;
    ++text->lines_size;
    pos = ftell(file);
    if (pos == -1) return pos;
  }
  return pos;
}

struct text* text_file_init(const char* filename) {
  struct text* text = malloc(sizeof(struct text));
  if (!text) return NULL;
  FILE* file = fopen(filename, "r");
  if (!file) {
    free(text);
    return NULL;
  }
  if (fseek(file, 0, SEEK_END)) {
    free(text);
    fclose(file);
    return NULL;
  }
  long file_size = ftell(file);
  if (file_size == -1 || fseek(file, 0, SEEK_SET)) {
    free(text);
    fclose(file);
    return NULL;
  }
  text->buffer_size = (size_t)file_size;
  text->buffer = malloc(text->buffer_size);
  if (!text->buffer) {
    free(text);
    fclose(file);
    return NULL;
  }
  text->lines_reserved = LINES_RESERVED_DEFAULT;
  text->lines_size = 0;
  text->lines = malloc(sizeof(const char*) * LINES_RESERVED_DEFAULT);
  if (!text->lines || read_text_file(text, file) == -1) {
    free(text->buffer);
    if (text->lines) free(text->lines);
    free(text);
    fclose(file);
    return NULL;
  }
  fclose(file);
  return text;
}

void text_delete(struct text* text) {
  if (!text) return;
  if (text->lines) free(text->lines);
  if (text->buffer) free(text->buffer);
}
