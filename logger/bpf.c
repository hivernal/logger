#include "logger/bpf.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include "logger/process.skel.h"
#include "logger/file.skel.h"
#include "logger/setid.skel.h"
#include "logger/sock.skel.h"
#pragma GCC diagnostic pop

#include <bpf/libbpf.h>
#include <unistd.h>
#include <sys/stat.h>

#include "logger/process.h"
#include "logger/file.h"
#include "logger/setid.h"
#include "logger/sock.h"
#include "logger/hash.h"
#include "logger/text.h"

#define BPF_OPEN_ERROR_MSG "Failed to open BPF skeleton\n"
#define BPF_LOAD_ERROR_MSG "Failed to load BPF skeleton\n"
#define BPF_ATTACH_ERROR_MSG "Failed to attach BPF skeleton\n"
#define BPF_CREATE_RB_ERROR_MSG "Failed to create BPF ringbuffer\n"

#define UNUSED __attribute__((unused))

static int libbpf_print_fn(enum libbpf_print_level level UNUSED,
                           const char* format, va_list args) {
  return vfprintf(stderr, format, args);
}

struct bpf {
  /* Skeletons. */
  /* sys_execve, sys_execveat, sys_clone, sched_process_exit skeleton object. */
  struct process_bpf* process_skel;
  /*
   * sys_write, sys_read, sys_unlink, sys_unlinkat, sys_chmod, sys_fchmodat,
   * sys_fchmodat2, sys_fchmod, sys_chown, sys_fchown, sys_fchownat, sys_rename,
   * sys_renameat, sys_renameat2, skeleton object.
   */
  struct file_bpf* file_skel;
  /*
   * sys_setuid, sys_setgid, sys_setreuid, sys_setregid, sys_setresuid,
   * sys_setresgid, sys_setfsuid, sys_setfsgid skeleton object.
   */
  struct setid_bpf* setid_skel;
  /* sys_connect, sys_accept, sys_accept4 skeleton object. */
  struct sock_bpf* sock_skel;

  /* Ring buffer manager. */
  struct ring_buffer* map_buffer;

  /* Data of users and groups system files. */
  struct users_groups users_groups;
  /* Additional data for the sys_execve_cb function. */
  struct sys_execve_cb_data sys_execve_cb_data;
  /* Additional data for the sys_write_cb function. */
  struct sys_write_rename_cb_data sys_write_cb_data;
  /* Additional data for the sys_rename_cb function. */
  struct sys_write_rename_cb_data sys_rename_cb_data;
};

#define PROCESS_SKEL_DISABLED(opts)                              \
  (!(opts)->sys_execve_enable && !(opts)->sys_execveat_enable && \
   !(opts)->sys_clone_enable && !(opts)->sys_clone3_enable &&    \
   !(opts)->sched_process_exit_enable)

#define FILE_SKEL_DISABLED(opts)                                    \
  (!(opts)->sys_write_enable && !(opts)->sys_read_enable &&         \
   !(opts)->sys_unlink_enable && !(opts)->sys_unlinkat_enable &&    \
   !(opts)->sys_chown_enable && !(opts)->sys_fchown_enable &&       \
   !(opts)->sys_fchownat_enable && !(opts)->sys_lchown_enable &&    \
   !(opts)->sys_chmod_enable && !(opts)->sys_fchmod_enable &&       \
   !(opts)->sys_fchmodat_enable && !(opts)->sys_fchmodat2_enable && \
   !(opts)->sys_rename_enable && !(opts)->sys_renameat_enable &&    \
   !(opts)->sys_renameat2_enable)

#define SETID_SKEL_DISABLED(opts)                                    \
  (!(opts)->sys_setuid_enable && !(opts)->sys_setgid_enable &&       \
   !(opts)->sys_setreuid_enable && !(opts)->sys_setregid_enable &&   \
   !(opts)->sys_setresuid_enable && !(opts)->sys_setresgid_enable && \
   !(opts)->sys_setfsuid_enable && !(opts)->sys_setfsgid_enable)

#define SOCK_SKEL_DISABLED(opts)                                \
  (!(opts)->sys_connect_enable && !(opts)->sys_accept_enable && \
   !(opts)->sys_accept4_enable)

#define WRITE_MAP_ENABLED(opts) ((opts)->sys_write_enable)

#define READ_MAP_ENABLED(opts) ((opts)->sys_read_enable)

#define UNLINK_MAP_ENABLED(opts) \
  ((opts)->sys_unlink_enable || (opts)->sys_unlinkat_enable)

#define CHOWN_MAP_ENABLED(opts)                             \
  ((opts)->sys_chown_enable || (opts)->sys_fchown_enable || \
   (opts)->sys_lchown_enable || (opts)->sys_fchownat_enable)

#define CHMOD_MAP_ENABLED(opts)                             \
  ((opts)->sys_chmod_enable || (opts)->sys_fchown_enable || \
   (opts)->sys_fchmodat2_enable || (opts)->sys_fchownat_enable)

#define RENAME_MAP_ENABLED(opts)                               \
  ((opts)->sys_rename_enable || (opts)->sys_renameat_enable || \
   (opts)->sys_renameat2_enable)

#define EXECVE_MAP_ENABLED(opts) \
  ((opts)->sys_execve_enable || (opts)->sys_execveat_enable)

#define CLONE_MAP_ENABLED(opts) \
  ((opts)->sys_clone_enable || (opts)->sys_clone3_enable)

#define SCHED_PROCESS_EXIT_MAP_ENABLED(opts) ((opts)->sched_process_exit_enable)

#define SETID_MAP_ENABLED(opts) !SETID_SKEL_DISABLED(opts)

#define SOCK_MAP_ENABLED(opts) !SOCK_SKEL_DISABLED(opts)

/* Opens BPF application. */
int bpf_open(struct bpf* bpf, const struct bpf_opts* opts) {
  if (PROCESS_SKEL_DISABLED(opts)) bpf->process_skel = NULL;
  else if (!(bpf->process_skel = process_bpf__open())) goto err;

  if (FILE_SKEL_DISABLED(opts)) bpf->file_skel = NULL;
  else if (!(bpf->file_skel = file_bpf__open())) goto err;

  if (SETID_SKEL_DISABLED(opts)) bpf->setid_skel = NULL;
  else if (!(bpf->setid_skel = setid_bpf__open())) goto err;

  if (SOCK_SKEL_DISABLED(opts)) bpf->sock_skel = NULL;
  else if (!(bpf->sock_skel = sock_bpf__open())) goto err;

  if (bpf->file_skel) bpf->file_skel->bss->logger_pid = getpid();
  return 0;
err:
  fprintf(stderr, BPF_OPEN_ERROR_MSG);
  return 1;
}

#define bpf_program_set_autoload_sys(skel, event)               \
  bpf_program__set_autoload(                                    \
      skel->progs.tracepoint__syscalls__sys_enter_##event,      \
      opts->sys_##event##_enable);                              \
  bpf_program__set_autoload(                                    \
      skel->progs.tracepoint__syscalls__sys_exit_##event,       \
      opts->sys_##event##_enable)

#define bpf_program_set_autoload_sched(skel, event)                      \
  bpf_program__set_autoload(skel->progs.tracepoint__sched__##event,      \
                            opts->event##_enable)

int set_autoload_file_skel(struct file_bpf* skel, const struct bpf_opts* opts) {
  if (!skel) return 0;
  bpf_program_set_autoload_sys(skel, read);
  bpf_program_set_autoload_sys(skel, write);
  bpf_program_set_autoload_sys(skel, unlink);
  bpf_program_set_autoload_sys(skel, unlinkat);
  bpf_program_set_autoload_sys(skel, chown);
  bpf_program_set_autoload_sys(skel, fchown);
  // bpf_program_set_autoload_sys(bpf->file_skel, lchown);
  bpf_program_set_autoload_sys(skel, fchownat);
  bpf_program_set_autoload_sys(skel, chmod);
  bpf_program_set_autoload_sys(skel, fchmod);
  bpf_program_set_autoload_sys(skel, fchmodat);
  bpf_program_set_autoload_sys(skel, fchmodat2);
  bpf_program_set_autoload_sys(skel, rename);
  bpf_program_set_autoload_sys(skel, renameat);
  bpf_program_set_autoload_sys(skel, renameat2);
  bpf_map__set_autocreate(skel->maps.sys_write_rb, WRITE_MAP_ENABLED(opts));
  bpf_map__set_autocreate(skel->maps.sys_read_rb, READ_MAP_ENABLED(opts));
  bpf_map__set_autocreate(skel->maps.sys_unlink_rb, UNLINK_MAP_ENABLED(opts));
  bpf_map__set_autocreate(skel->maps.sys_chmod_rb, CHMOD_MAP_ENABLED(opts));
  bpf_map__set_autocreate(skel->maps.sys_chown_rb, CHOWN_MAP_ENABLED(opts));
  bpf_map__set_autocreate(skel->maps.sys_rename_rb, RENAME_MAP_ENABLED(opts));
  return file_bpf__load(skel);
}

int set_autoload_process_skel(struct process_bpf* skel,
                              const struct bpf_opts* opts) {
  if (!skel) return 0;
  bpf_program_set_autoload_sys(skel, execve);
  bpf_program_set_autoload_sys(skel, execveat);
  bpf_program_set_autoload_sys(skel, clone);
  bpf_program_set_autoload_sys(skel, clone3);
  bpf_program_set_autoload_sched(skel, sched_process_exit);
  bpf_map__set_autocreate(skel->maps.sys_execve_rb, EXECVE_MAP_ENABLED(opts));
  bpf_map__set_autocreate(skel->maps.sys_clone_rb, CLONE_MAP_ENABLED(opts));
  bpf_map__set_autocreate(skel->maps.sched_process_exit_rb,
                          SCHED_PROCESS_EXIT_MAP_ENABLED(opts));
  return process_bpf__load(skel);
}

int set_autoload_sock_skel(struct sock_bpf* skel, const struct bpf_opts* opts) {
  if (!skel) return 0;
  bpf_program_set_autoload_sys(skel, connect);
  bpf_program__set_autoload(skel->progs.tracepoint__syscalls__sys_exit_accept,
                            opts->sys_accept_enable);
  bpf_program__set_autoload(skel->progs.tracepoint__syscalls__sys_exit_accept4,
                            opts->sys_accept4_enable);
  return sock_bpf__load(skel);
}

int set_autoload_setid_skel(struct setid_bpf* skel,
                            const struct bpf_opts* opts) {
  if (!skel) return 0;
  bpf_program_set_autoload_sys(skel, setuid);
  bpf_program_set_autoload_sys(skel, setgid);
  bpf_program_set_autoload_sys(skel, setreuid);
  bpf_program_set_autoload_sys(skel, setregid);
  bpf_program_set_autoload_sys(skel, setresuid);
  bpf_program_set_autoload_sys(skel, setresgid);
  bpf_program_set_autoload_sys(skel, setfsuid);
  bpf_program_set_autoload_sys(skel, setfsgid);
  return setid_bpf__load(skel);
}

/* Loads & verifies BPF programs. */
int bpf_load(struct bpf* bpf, const struct bpf_opts* opts) {
  if (set_autoload_file_skel(bpf->file_skel, opts) ||
      set_autoload_process_skel(bpf->process_skel, opts) ||
      set_autoload_sock_skel(bpf->sock_skel, opts) ||
      set_autoload_setid_skel(bpf->setid_skel, opts)) {
    fprintf(stderr, BPF_LOAD_ERROR_MSG);
    return 1;
  }
  return 0;
}

/* Attach tracepoint handler. */
int bpf_attach(struct bpf* bpf) {
  if (bpf->process_skel && process_bpf__attach(bpf->process_skel)) goto err;
  if (bpf->file_skel && file_bpf__attach(bpf->file_skel)) goto err;
  if (bpf->sock_skel && sock_bpf__attach(bpf->sock_skel)) goto err;
  if (bpf->setid_skel && setid_bpf__attach(bpf->setid_skel)) goto err;
  return 0;
err:
  fprintf(stderr, BPF_ATTACH_ERROR_MSG);
  return 1;
}

int ring_buffer_new_or_add(struct ring_buffer** ring_buffer, int map_fd,
                           ring_buffer_sample_fn sample_cb, void* ctx,
                           const struct ring_buffer_opts* opts) {
  if (!(*ring_buffer)) {
    *ring_buffer = ring_buffer__new(map_fd, sample_cb, ctx, opts);
    if (!(*ring_buffer)) return 1;
    return 0;
  }
  return ring_buffer__add(*ring_buffer, map_fd, sample_cb, ctx);
}

#define map_buffer_new_or_add(buffer, skel, event, data_ptr)         \
  ring_buffer_new_or_add(buffer, bpf_map__fd(skel->maps.event##_rb), \
                         event##_cb, data_ptr, NULL)

/* Create ring or perf buffers. */
int create_map_buffers(struct bpf* bpf, struct bpf_opts* opts) {
  bpf->map_buffer = NULL;
  if (bpf->process_skel) {
    if (EXECVE_MAP_ENABLED(opts) &&
        map_buffer_new_or_add(&bpf->map_buffer, bpf->process_skel, sys_execve,
                              &bpf->sys_execve_cb_data)) goto err;
    if (CLONE_MAP_ENABLED(opts) &&
        map_buffer_new_or_add(&bpf->map_buffer, bpf->process_skel, sys_clone,
                              &opts->sys_clone_log)) goto err;
    if (SCHED_PROCESS_EXIT_MAP_ENABLED(opts) &&
        map_buffer_new_or_add(&bpf->map_buffer, bpf->process_skel,
                              sched_process_exit,
                              &opts->sched_process_exit_log)) goto err;
  }

  if (bpf->file_skel) {
    if (WRITE_MAP_ENABLED(opts) &&
        map_buffer_new_or_add(&bpf->map_buffer, bpf->file_skel, sys_write,
                              &bpf->sys_write_cb_data)) goto err;
    if (READ_MAP_ENABLED(opts) &&
        map_buffer_new_or_add(&bpf->map_buffer, bpf->file_skel, sys_read,
                              &opts->sys_read_log)) goto err;
    if (UNLINK_MAP_ENABLED(opts) &&
        map_buffer_new_or_add(&bpf->map_buffer, bpf->file_skel, sys_unlink,
                              &opts->sys_unlink_log)) goto err;
    if (CHMOD_MAP_ENABLED(opts) &&
        map_buffer_new_or_add(&bpf->map_buffer, bpf->file_skel, sys_chmod,
                              &opts->sys_chmod_log)) goto err;
    if (CHOWN_MAP_ENABLED(opts) &&
        map_buffer_new_or_add(&bpf->map_buffer, bpf->file_skel, sys_chown,
                              &opts->sys_chown_log)) goto err;
    if (RENAME_MAP_ENABLED(opts) &&
        map_buffer_new_or_add(&bpf->map_buffer, bpf->file_skel, sys_rename,
                              &bpf->sys_rename_cb_data)) goto err;
  }

  if (bpf->setid_skel &&
      map_buffer_new_or_add(&bpf->map_buffer, bpf->setid_skel, sys_setid,
                            &opts->sys_setid_log)) goto err;

  if (bpf->sock_skel &&
      map_buffer_new_or_add(&bpf->map_buffer, bpf->sock_skel, sys_sock,
                            &opts->sys_sock_log)) goto err;
  return 0;
err:
  fprintf(stderr, BPF_CREATE_RB_ERROR_MSG);
  return 1;
}

#define map_buffer_poll(buffer, time) ring_buffer__poll(buffer, time)

/* Poll data from ring or perf buffers. */
int bpf_poll_map_buffers(struct bpf* bpf, int time_ms) {
  if (map_buffer_poll(bpf->map_buffer, time_ms) < 0) {
    return 1;
  }
  return 0;
}

/*
 * Open, load, verify BPF application, attach tracepoint handler and create ring or perf
 * buffers.
 */
struct bpf* bpf_init(struct bpf_opts* opts) {
  if (!opts) return NULL;
  struct bpf* bpf = malloc(sizeof(struct bpf));
  if (!bpf) return NULL;
  if (bpf_open(bpf, opts) || bpf_load(bpf, opts) || bpf_attach(bpf) ||
      create_map_buffers(bpf, opts)) {
    goto clean;
  }
  libbpf_set_print(libbpf_print_fn);
  users_groups_init(&bpf->users_groups);
  mkdir(opts->log_dir, 0600);
  sys_execve_cb_data_init(&bpf->sys_execve_cb_data, opts->hash_alg,
                          opts->sys_execve_log);
  sys_write_rename_cb_data_init(&bpf->sys_write_cb_data, opts->sys_write_log,
                                &bpf->users_groups);
  sys_write_rename_cb_data_init(&bpf->sys_rename_cb_data, opts->sys_rename_log,
                                &bpf->users_groups);
  return bpf;
clean:
  bpf_delete(bpf);
  return NULL;
}

#define map_buffer_free(buffer) ring_buffer__free(bpf->map_buffer)

/* Destroy BPF application. */
void bpf_delete(struct bpf* bpf) {
  if (bpf->process_skel) process_bpf__destroy(bpf->process_skel);
  if (bpf->file_skel) file_bpf__destroy(bpf->file_skel);
  if (bpf->setid_skel) setid_bpf__destroy(bpf->setid_skel);
  if (bpf->sock_skel) sock_bpf__destroy(bpf->sock_skel);
  if (bpf->map_buffer) map_buffer_free(bpf->map_buffer);
  sys_execve_cb_data_delete(&bpf->sys_execve_cb_data);
  users_groups_delete(&bpf->users_groups);
  if (bpf) free(bpf);
}
