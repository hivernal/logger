#include "logger/helpers.h"
#include "logger/list.h"

#define dentry_range_init() malloc(sizeof(struct dentry_range))
#define dentry_range_delete(ptr) free(ptr)

/* Gets const char pointers to each filename entry. */
int get_filename_cptrs(struct list_head* list, const char* filename) {
  int parent_dir_index = 0;
  while (*filename) {
    if (*filename == '.') {
      /* If current directory (./). */
      if (*(filename + 1) == '/') {
        filename += 2;
        continue;
        /* If parent directory (../). */
      } else if (*(filename + 1) == '.') {
        /* If list is not empty. */
        if (list != list->next) {
          struct dentry_range* p =
              list_last_entry(list, struct dentry_range, node);
          list_delete_tail(list);
          dentry_range_delete(p);
        } else {
          ++parent_dir_index;
        }
        filename += 3;
        continue;
      }
    }
    struct dentry_range* offsets = dentry_range_init();
    if (!offsets) return ~parent_dir_index + 1;
    offsets->start = filename;
    for (; *(filename + 1) && *filename != '/'; ++filename);
    offsets->end = filename;
    ++filename;
    list_add_tail(&offsets->node, list);
  }
  return parent_dir_index;
}

const char* get_dir_cptr(const struct path_dentries* path_dentries,
                         int parent_dir_index) {
  /* The last symbol before '\0'. */
  const char* cptr = path_dentries->data + sizeof(path_dentries->data) - 2;
  if (!parent_dir_index) return cptr;
  --cptr;
  const char* const start = path_dentries->data + path_dentries->offset;
  for (; cptr > start; --cptr) {
    if (*cptr == '/' && !(--parent_dir_index)) break;
  }
  return cptr;
}

int dentry_ranges_init(struct list_head* list, const char* filename,
                       const struct path_dentries* path_dentries) {
  int parent_dir_index = get_filename_cptrs(list, filename);
  if (parent_dir_index < 0) return -1;
  struct dentry_range* dir = dentry_range_init();
  dir->start = path_dentries->data + path_dentries->offset;
  dir->end = get_dir_cptr(path_dentries, parent_dir_index);
  list_add(&dir->node, list);
  return 0;
};

void dentry_ranges_delete(struct list_head* list) {
  struct dentry_range *c, *n;
  list_for_each_entry_safe(c, n, list, node) { dentry_range_delete(c); }
}

void fprint_dentry_ranges(FILE* file, const struct list_head* list) {
  const struct dentry_range* c;
  list_for_each_entry(c, list, node) { 
    fprint_substr(file, c->start, c->end);
  }
}

void fprint_relative_filename(FILE* file, const char* filename,
                              const struct path_dentries* path_dentries) {
  if (!*filename) return;
  struct list_head list = LIST_HEAD_INIT(list);
  int parent_dir_index = get_filename_cptrs(&list, filename);
  if (parent_dir_index < 0) return;
  const char* cptr = get_dir_cptr(path_dentries, parent_dir_index);
  fprint_substr(file, path_dentries->data + path_dentries->offset, cptr);
  struct dentry_range* c;
  list_for_each_entry(c, &list, node) { fprint_substr(file, c->start, c->end); }
  dentry_ranges_delete(&list);
}

/*
#include <string.h>

char* fill_substr(char* buffer_start, const char* buffer_end, const char* start,
                  const char* end) {
  size_t res = (size_t)(end - start + 1);
  if (buffer_start + res > buffer_end) return buffer_start;
  memcpy(buffer_start, start, res);
  return buffer_start + res;
};

void fill_relative_filename(char* buffer_start, const char* buffer_end,
                            const char* filename,
                            const struct path_dentries* path_dentries) {
  if (!*filename) return;
  struct list_head list = LIST_HEAD_INIT(list);
  int parent_dir_index = get_filename_cptrs(&list, filename);
  if (parent_dir_index < 0) return;
  const char* cptr = get_dir_cptr(path_dentries, parent_dir_index);
  buffer_start = fill_substr(buffer_start, buffer_end,
                             path_dentries->data + path_dentries->offset, cptr);
  struct dentry_range* c;
  list_for_each_entry(c, &list, node) {
    buffer_start = fill_substr(buffer_start, buffer_end, c->start, c->end);
  }
  *buffer_start = 0;
  dentry_ranges_delete(&list);
}
*/
