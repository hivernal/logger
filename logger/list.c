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
  struct node *tail, *head;
  int size;
};

void push_item(struct list* list, void* node_data, size_t node_data_size) {
  if (!node_data || !list || !list->data) return;
  struct node* node = malloc(sizeof(struct node));
  if (!node) return;
  node->data = malloc(node_data_size);
  if (!node->data) return;
  memcpy(node->data, node_data, node_data_size);
  struct private_data* list_data = list->data;
  node->prev = list_data->tail;
  node->next = NULL;
  if (list_data->tail) list_data->tail->next = node;
  list_data->tail = node;
  if (!list_data->head) list_data->head = node;
  ++(list_data->size);
}

void pop_item(struct list* list) {
  if (!list || !list->data) return;
  struct private_data* data = list->data;
  if (!data->tail) return;
  struct node* old_tail = data->tail;
  data->tail = data->tail->prev;
  if (data->tail) data->tail->next = NULL;
  if (old_tail->data) free(old_tail->data);
  free(old_tail);
  --(data->size);
  return;
}

void delete_list(struct list* list) {
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

void for_each(const struct list* list, void* data,
              void (*callback)(void* node_data, void* data)) {
  if (!list) return;
  struct private_data* list_data = list->data;
  for (struct node* node = list_data->head; node; node = node->next) {
    callback(node->data, data);
  }
}

const static struct list_op list_op_global = {delete_list, push_item, pop_item,
                                              for_each};

struct list* list_init() {
  struct list* list = malloc(sizeof(struct list));
  if (!list) return NULL;
  struct private_data* data = malloc(sizeof(struct private_data));
  if (!data) return NULL;
  data->head = NULL;
  data->tail = NULL;
  data->size = 0;
  list->data = data;
  list->op = &list_op_global;
  return list;
}
