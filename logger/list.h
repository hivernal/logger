#ifndef LOGGER_LIST_H_
#define LOGGER_LIST_H_

#include <stddef.h>

struct list {
  void* data;
  const struct list_op* op;
};

struct list_op {
  void (*delete)(struct list*);
  void (*push)(struct list*, void*, size_t);
  void (*pop)(struct list*);
  void (*for_each)(const struct list*, void*,
                   void (*)(void* node_data, void* data));
};

struct list* list_init();

#endif  // LOGGER_LIST_H_
