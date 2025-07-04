#ifndef LOGGER_LIST_H_
#define LOGGER_LIST_H_

#include <stddef.h>

struct list {
  void* data;
  const struct list_vtable* vt;
};

struct list_vtable {
  void (*delete)(struct list*);
  void* (*push_back)(struct list*, const void*, size_t);
  void (*pop_back)(struct list*);
  int (*for_each)(const struct list*, void*,
                  int (*)(void* node_data, void* data));
  int (*for_each_reverse)(const struct list*, void*,
                          int (*)(void* node_data, void* data));
  size_t (*size)(const struct list*);
  void* (*head)(const struct list*);
  void* (*tail)(const struct list*);
  void* (*next)(struct list*);
  void* (*prev)(struct list*);
  void* (*reset_pos)(struct list*);
  void* (*reset_pos_end)(struct list*);
};

struct list* list_init();

#endif  // LOGGER_LIST_H_
