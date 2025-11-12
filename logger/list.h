#ifndef LOGGER_LIST_H_
#define LOGGER_LIST_H_

#include <stdint.h>

#ifndef offsetof
#define offsetof(type, member) ((size_t) &((type*)0)->member)
#endif

#ifndef container_of
#define container_of(ptr, type, member) \
  ((type*)((uintptr_t)(ptr) - offsetof(type, member)))
#endif

struct list_head {
  struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) struct list_head name = LIST_HEAD_INIT(name)

static inline void init_list_head(struct list_head* list) {
  list->next = list;
  list->prev = list;
}

#define list_entry(ptr, type, member) container_of(ptr, type, member)

#define list_first_entry(ptr, type, member) \
  list_entry((ptr)->next, type, member)

#define list_last_entry(ptr, type, member) \
  list_entry((ptr)->prev, type, member)

#define list_next_entry(pos, member) \
  list_entry((pos)->member.next, typeof(*(pos)), member)

#define list_for_each(pos, head) \
  for (pos = (head)->next; pos != (head); pos = pos->next)

#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; \
             pos != (head); \
             pos = n, n = pos->next)

#define list_for_each_entry(pos, head, member) \
  for (pos = list_first_entry(head, typeof(*pos), member); \
       &pos->member != (head); \
       pos = list_next_entry(pos, member))

#define list_for_each_entry_safe(pos, n, head, member) \
  for (pos = list_first_entry(head, typeof(*pos), member), \
       n = list_next_entry(pos, member); \
       &pos->member != (head); \
       pos = n, n = list_next_entry(n, member))

static inline void list_insert(struct list_head* new, struct list_head* prev,
                               struct list_head* next) {
  next->prev = new;
  new->next = next;
  new->prev = prev;
  prev->next = new;
}

static inline void list_add(struct list_head* new, struct list_head* head) {
  list_insert(new, head, head->next);
}

static inline void list_add_tail(struct list_head* new, struct list_head* head) {
  list_insert(new, head->prev, head);
}

static inline void list_delete(struct list_head* prev, struct list_head* next) {
  prev->next = next;
  next->prev = prev;
}

static inline void list_delete_tail(struct list_head* head) {
  list_delete(head->prev->prev, head);
}

static inline void list_delete_node(struct list_head* node) {
  list_delete(node->prev, node->next);
  node->prev = NULL;
  node->next = NULL;
}

#endif // LOGGER_LIST_H_
