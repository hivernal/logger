#ifndef LOGGER_FILE_H_
#define LOGGER_FILE_H_

#include <stddef.h>
#include <stdlib.h>
#include <pthread.h>

#include "logger/text.h"
#include "logger/bpf/feature_probe.h"

struct text_mutex {
  struct text* text;
  pthread_mutex_t mutex;
};

struct users_groups {
  struct text_mutex passwd, group, doas, sudoers;
};

static inline int users_groups_init(struct users_groups* users_groups) {
  users_groups->passwd.text = text_filename_init("/etc/passwd");
  pthread_mutex_init(&users_groups->passwd.mutex, NULL);
  users_groups->group.text = text_filename_init("/etc/group");
  pthread_mutex_init(&users_groups->group.mutex, NULL);
  users_groups->doas.text = text_filename_init("/etc/doas.conf");
  pthread_mutex_init(&users_groups->doas.mutex, NULL);
  users_groups->sudoers.text = text_filename_init("/etc/sudoers");
  pthread_mutex_init(&users_groups->sudoers.mutex, NULL);
  return (!users_groups->passwd.text || !users_groups->group.text ||
          !users_groups->doas.text || !users_groups->sudoers.text);
}

static inline void users_groups_delete(struct users_groups* users_groups) {
  if (users_groups->passwd.text) text_delete(users_groups->passwd.text);
  pthread_mutex_destroy(&users_groups->passwd.mutex);
  if (users_groups->group.text) text_delete(users_groups->group.text);
  pthread_mutex_destroy(&users_groups->group.mutex);
  if (users_groups->doas.text) text_delete(users_groups->doas.text);
  pthread_mutex_destroy(&users_groups->doas.mutex);
  if (users_groups->sudoers.text) text_delete(users_groups->sudoers.text);
  pthread_mutex_destroy(&users_groups->sudoers.mutex);
}

struct sys_write_rename_cb_data {
  struct users_groups* users_groups;
  const char* filename;
};

static inline int sys_write_rename_cb_data_init(
    struct sys_write_rename_cb_data* data, const char* filename,
    struct users_groups* users_groups) {
  data->users_groups = users_groups;
  data->filename = filename;
  return 0;
}

/* Callback function for sys_write_buf ring buffer. */
#ifdef HAVE_RINGBUF_MAP_TYPE
int sys_write_cb(void* ctx, void* data, size_t data_sz);
#else
void sys_write_cb(void* ctx, int cpu, void* data, unsigned data_sz);
#endif

/* Callback function for sys_read_buf ring buffer. */
#ifdef HAVE_RINGBUF_MAP_TYPE
int sys_read_cb(void* ctx, void* data, size_t data_sz);
#else
void sys_read_cb(void* ctx, int cpu, void* data, unsigned data_sz);
#endif

/* Callback function for sys_unlink_buf ring buffer. */
#ifdef HAVE_RINGBUF_MAP_TYPE
int sys_unlink_cb(void* ctx, void* data, size_t data_sz);
#else
void sys_unlink_cb(void* ctx, int cpu, void* data, unsigned data_sz);
#endif

/* Callback function for sys_chmod_buf ring buffer. */
#ifdef HAVE_RINGBUF_MAP_TYPE
int sys_chmod_cb(void* ctx, void* data, size_t data_sz);
#else
void sys_chmod_cb(void* ctx, int cpu, void* data, unsigned data_sz);
#endif

/* Callback function for sys_chown_buf ring buffer. */
#ifdef HAVE_RINGBUF_MAP_TYPE
int sys_chown_cb(void* ctx, void* data, size_t data_sz);
#else
void sys_chown_cb(void* ctx, int cpu, void* data, unsigned data_sz);
#endif

/* Callback function for sys_rename_buf ring buffer. */
#ifdef HAVE_RINGBUF_MAP_TYPE
int sys_rename_cb(void* ctx, void* data, size_t data_sz);
#else
void sys_rename_cb(void* ctx, int map, void* data, unsigned data_sz);
#endif

#endif  //  LOGGER_FILE_H_
