#include "list.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct node {
  struct node* prev;
  struct node* next;
  void* data;
};

struct private_data {
  struct node *tail, *head, *current;
  size_t size;
};

void* list_push_back_item(struct list* list, const void* node_data,
                          size_t node_data_size) {
  if (!list || !list->data || !node_data) return NULL;
  struct node* node = malloc(sizeof(struct node));
  if (!node) return NULL;
  node->data = malloc(node_data_size);
  if (!node->data) return NULL;
  memcpy(node->data, node_data, node_data_size);
  struct private_data* list_data = list->data;
  node->prev = list_data->tail;
  node->next = NULL;
  if (list_data->tail) list_data->tail->next = node;
  list_data->tail = node;
  if (!list_data->head) {
    list_data->head = node;
    list_data->current = node;
  }
  ++(list_data->size);
  return node->data;
}
void list_pop_back_item(struct list* list) {
  if (!list || !list->data) return;
  struct private_data* data = list->data;
  if (!data->tail) return;
  struct node* old_tail = data->tail;
  struct node* new_tail = old_tail->prev;
  if (data->current == data->tail) data->current = new_tail;
  data->tail = new_tail;
  if (new_tail) {
    new_tail->next = NULL;
  } else {
    data->head = NULL;
  }
  if (old_tail->data) free(old_tail->data);
  free(old_tail);
  --(data->size);
  return;
}

void list_delete(struct list* list) {
  if (!list) return;
  struct private_data* data = list->data;
  for (struct node* node = data->head; node; node = data->head) {
    data->head = node->next;
    if (node->data) free(node->data);
    free(node);
  }
  free(list->data);
  free(list);
  list = NULL;
}

int list_for_each(const struct list* list, void* data,
                  int (*callback)(void* node_data, void* data)) {
  if (!list) return 1;
  struct private_data* list_data = list->data;
  int ret;
  for (struct node* node = list_data->head; node; node = node->next) {
    ret = callback(node->data, data);
    if (ret) return ret;
  }
  return 0;
}

int list_for_each_reverse(const struct list* list, void* data,
                          int (*callback)(void* node_data, void* data)) {
  if (!list) return 1;
  struct private_data* list_data = list->data;
  int ret;
  for (struct node* node = list_data->tail; node; node = node->prev) {
    ret = callback(node->data, data);
    if (ret) return ret;
  }
  return 0;
}

void* list_next(struct list* list) {
  if (!list || !list->data || !list->data) return NULL;
  struct private_data* data = list->data;
  if (!data->current) return NULL;
  data->current = data->current->next;
  return data->current->data;
}

void* list_prev(struct list* list) {
  if (!list || !list->data || !list->data) return NULL;
  struct private_data* data = list->data;
  if (!data->current) return NULL;
  data->current = data->current->prev;
  return data->current->data;
}

void* list_reset_pos(struct list* list) {
  if (!list || !list->data) return NULL;
  struct private_data* data = list->data;
  data->current = data->head;
  if (!data->current) return NULL;
  return data->current->data;
}

void* list_reset_pos_end(struct list* list) {
  if (!list || !list->data) return NULL;
  struct private_data* data = list->data;
  data->current = data->tail;
  if (!data->current) return NULL;
  return data->current->data;
}

size_t list_size(const struct list* list) {
  if (!list || !list->data) return 0;
  const struct private_data* data = list->data;
  return data->size;
}

void* list_head(const struct list* list) {
  if (!list || !list->data) return 0;
  const struct private_data* data = list->data;
  if (!data->head) return NULL;
  return data->head->data;
}

void* list_tail(const struct list* list) {
  if (!list || !list->data) return 0;
  const struct private_data* data = list->data;
  if (!data->tail) return NULL;
  return data->tail->data;
}

static const struct list_vtable list_vt_global = {&list_delete,
                                                  &list_push_back_item,
                                                  &list_pop_back_item,
                                                  &list_for_each,
                                                  &list_for_each_reverse,
                                                  &list_size,
                                                  &list_head,
                                                  &list_tail,
                                                  &list_next,
                                                  &list_prev,
                                                  &list_reset_pos,
                                                  &list_reset_pos_end};

struct list* list_init() {
  struct list* list = malloc(sizeof(struct list));
  if (!list) return NULL;
  struct private_data* data = malloc(sizeof(struct private_data));
  if (!data) return NULL;
  data->head = NULL;
  data->tail = NULL;
  data->current = NULL;
  data->size = 0;
  list->data = data;
  list->vt = &list_vt_global;
  return list;
}
