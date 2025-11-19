#include "logger/bpf/helpers.h"
#include "logger/bpf/process.h"

/* Buffer for sending sys_execve data to userspace. */
struct {
#ifdef HAVE_RINGBUF_MAP_TYPE
  RINGBUF_BODY(NPROC * sizeof(struct sys_execveat));
#else
  PERF_EVENT_ARRAY_BODY;
#endif
} sys_execve_buf SEC(".maps");

/* Buffer for sending sys_clone data to the userspace. */
struct {
#ifdef HAVE_RINGBUF_MAP_TYPE
  RINGBUF_BODY(NPROC * sizeof(struct sys_clone));
#else
  PERF_EVENT_ARRAY_BODY;
#endif
} sys_clone_buf SEC(".maps");

/* Buffer for sending sched_process_exit data to the userspace. */
struct {
#ifdef HAVE_RINGBUF_MAP_TYPE
  RINGBUF_BODY(NPROC * sizeof(struct sched_process_exit));
#else
  PERF_EVENT_ARRAY_BODY;
#endif
} sched_process_exit_buf SEC(".maps");

/* Struct contains sys_enter_execve and sys_enter_execveat data. */
#ifdef HAVE_RINGBUF_MAP_TYPE
struct sys_enter_execve {
  /*
   * A binary executable, or a script name.
   * Relative to the directory reffered to by the file descriptor dfd.
   */
  char filename[PATH_SIZE]; /* Arguments. */
  char argv[ARGS_SIZE];
  int error;
  /*
   * The file descriptor of the parent directory of the executable file.
   * Can be the current working directory.
   */
  int fd;
};
#endif

/* Map for sharing data between enter and exit tracepoints. */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
#ifdef HAVE_RINGBUF_MAP_TYPE
  __type(value, struct sys_enter_execve);
#else
  __type(value, struct sys_execveat);
#endif
} sys_enter_execve_array SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 128);
  __type(key, u64);
#ifdef HAVE_RINGBUF_MAP_TYPE
  __type(value, struct sys_enter_execve);
#else
  __type(value, struct sys_execveat);
#endif
} sys_enter_execve_hash SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 128);
  __type(key, u64);
  __type(value, u64);
} sys_enter_clone_hash SEC(".maps");

/*
 * Copies two-dimensional array of src to one-dimensional.
 * Returns written bytes on success and negative on errors.
 */
FUNC_INLINE int read_argv(char* dst, const char** src) {
  const char* ptr;
  unsigned offset = 0;
#ifndef HAVE_BOUNDED_LOOPS
#pragma unroll
#endif
  for (int i = 0; i < MAX_ARGS; ++i) {
    long ret = bpf_probe_read_user(&ptr, sizeof(ptr), &src[i]);
    if (ret < 0) return -1;
    if (!ptr) break;
    if (offset > (ARGS_SIZE - ARG_SIZE)) break;
    ret = bpf_probe_read_user_str(&dst[offset], ARG_SIZE, ptr);
    if (ret < 0) return -1;
    if (offset - 1 < ARGS_SIZE) dst[offset - 1] = ' ';
    offset = offset + (unsigned)ret;
  }
  return (int)offset;
}

FUNC_INLINE long fill_task_caps(struct task_caps* caps) {
  const struct task_struct* task = (struct task_struct*)bpf_get_current_task();
  const struct cred* cred;
  long ret = bpf_core_read(&cred, sizeof(cred), &task->real_cred);
  if (ret < 0) return ret;
  return bpf_core_read(caps, sizeof(*caps), &cred->cap_inheritable);
}

#ifdef HAVE_RINGBUF_MAP_TYPE
FUNC_INLINE int on_sys_enter_execve(int fd, const char* filename,
                                    const char** argv) {
  const int array_index = 0;
  struct sys_enter_execve* enter =
      bpf_map_lookup_elem(&sys_enter_execve_array, &array_index);
  if (!enter) return 1;
  enter->error = 0;
  enter->fd = fd;
  long ret = bpf_probe_read_user_str(&enter->filename, sizeof(enter->filename),
                                     filename);
  if (ret < 0) enter->error |= ERROR_FILENAME;
  if (read_argv(enter->argv, argv) < 0) {
    enter->error |= ERROR_ARGV;
    ret = -1;
  }
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&sys_enter_execve_hash, &hash_id, enter, BPF_ANY);
  if (ret < 0) return 1;
  return 0;
}

FUNC_INLINE int on_sys_exit_execve(int ret, int event_type) {
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  struct sys_enter_execve* enter =
      bpf_map_lookup_elem(&sys_enter_execve_hash, &hash_id);
  if (!enter) return 1;
  size_t reserved = sizeof(struct sys_execve);
  enum path_type filename_type = PATH_RELATIVE_FD;
  if (enter->filename[0] == '/') {
    filename_type = PATH_ABSOLUTE;
  } else if (enter->fd == AT_FDCWD) {
    filename_type = PATH_RELATIVE_CWD;
  } else {
    reserved = sizeof(struct sys_execveat);
  }
  struct sys_execve* sys_execve =
      bpf_ringbuf_reserve(&sys_execve_buf, reserved, 0);
  if (!sys_execve) goto clean;
  int* error = &sys_execve->error;
  *error = enter->error;
  if (bpf_probe_read_kernel_str(&sys_execve->argv, sizeof(sys_execve->argv),
                                &enter->argv) < 0)
    *error |= ERROR_COPY_ENTER;
  if (bpf_probe_read_kernel_str(&sys_execve->filename,
                                sizeof(sys_execve->filename),
                                &enter->filename) < 0)
    *error |= ERROR_COPY_ENTER;
  if (filename_type == PATH_RELATIVE_FD &&
      (read_path_dentries_fd(
           enter->fd, &((struct sys_execveat*)sys_execve)->dir, 1) < 0)) {
    *error |= ERROR_READ_FD;
  }
  if (fill_task(&sys_execve->task) < 0) *error |= ERROR_FILL_TASK;
  if (read_cwd(&sys_execve->cwd) < 0) *error |= ERROR_READ_CWD;
  if (fill_task_caps(&sys_execve->caps) < 0) *error |= ERROR_FILL_TASK_CAPS;
  sys_execve->ret = ret;
  sys_execve->event_type = event_type;
  sys_execve->filename_type = filename_type;
  bpf_ringbuf_submit(sys_execve, 0);
clean:
  bpf_map_delete_elem(&sys_enter_execve_hash, &hash_id);
  return 0;
}

#else
FUNC_INLINE int on_sys_enter_execve(int fd, const char* filename,
                                    const char** argv) {
  const int array_index = 0;
  struct sys_execveat* sys_execveat =
      bpf_map_lookup_elem(&sys_enter_execve_array, &array_index);
  if (!sys_execveat) return 1;
  struct sys_execve* sys_execve = &sys_execveat->sys_execve;
  int* error = &sys_execve->error;
  *error = 0;
  if (bpf_probe_read_user_str(&sys_execve->filename,
                              sizeof(sys_execve->filename), filename) < 0)
    *error |= ERROR_FILENAME;
  if (read_argv(sys_execve->argv, argv) < 0) *error |= ERROR_ARGV;

  if (sys_execve->filename[0] == '/') {
    sys_execve->filename_type = PATH_ABSOLUTE;
  } else if (fd == AT_FDCWD) {
    sys_execve->filename_type = PATH_RELATIVE_CWD;
  } else {
    sys_execve->filename_type = PATH_RELATIVE_FD;
    if (read_path_dentries_fd(fd, &sys_execveat->dir, 1) < 0)
      *error |= ERROR_READ_FD;
  }
  if (fill_task(&sys_execve->task) < 0) *error |= ERROR_FILL_TASK;
  if (read_cwd(&sys_execve->cwd) < 0) *error |= ERROR_READ_CWD;
  if (fill_task_caps(&sys_execve->caps) < 0) *error |= ERROR_FILL_TASK_CAPS;
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&sys_enter_execve_hash, &hash_id, sys_execveat, BPF_ANY);
  return 0;
}

FUNC_INLINE int on_sys_exit_execve(struct syscall_trace_exit* ctx,
                                   int event_type) {
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  struct sys_execveat* sys_execveat =
      bpf_map_lookup_elem(&sys_enter_execve_hash, &hash_id);
  if (!sys_execveat) return 1;
  sys_execveat->sys_execve.ret = (int)ctx->ret;
  sys_execveat->sys_execve.event_type = event_type;
  size_t data_size = sizeof(sys_execveat->sys_execve);
  if (sys_execveat->sys_execve.filename_type == PATH_RELATIVE_FD)
    data_size = sizeof(*sys_execveat);
  bpf_perf_event_output(ctx, &sys_execve_buf, BPF_F_CURRENT_CPU, sys_execveat,
                        data_size);
  bpf_map_delete_elem(&sys_enter_execve_hash, &hash_id);
  return 0;
}
#endif

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct syscall_trace_enter* ctx) {
  return on_sys_enter_execve(AT_FDCWD, (const char*)ctx->args[0],
                             (const char**)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int tracepoint__syscalls__sys_enter_execveat(struct syscall_trace_enter* ctx) {
  return on_sys_enter_execve((int)ctx->args[0], (const char*)ctx->args[1],
                             (const char**)ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__syscalls__sys_exit_execve(struct syscall_trace_exit* ctx) {
#ifdef HAVE_RINGBUF_MAP_TYPE
  return on_sys_exit_execve((int)ctx->ret, SYS_EXECVE);
#else
  return on_sys_exit_execve(ctx, SYS_EXECVE);
#endif
}

SEC("tracepoint/syscalls/sys_exit_execveat")
int tracepoint__syscalls__sys_exit_execveat(struct syscall_trace_exit* ctx) {
#ifdef HAVE_RINGBUF_MAP_TYPE
  return on_sys_exit_execve((int)ctx->ret, SYS_EXECVEAT);
#else
  return on_sys_exit_execve(ctx, SYS_EXECVEAT);
#endif
}

FUNC_INLINE int on_sys_enter_clone(uint64_t flags) {
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  return (int)bpf_map_update_elem(&sys_enter_clone_hash, &hash_id, &flags,
                                  BPF_ANY);
}

SEC("tracepoint/syscalls/sys_enter_clone")
int tracepoint__syscalls__sys_enter_clone(struct syscall_trace_enter* ctx) {
  return on_sys_enter_clone((uint64_t)ctx->args[0]);
}

#ifdef SYS_CLONE3
SEC("tracepoint/syscalls/sys_enter_clone3")
int tracepoint__syscalls__sys_enter_clone3(struct syscall_trace_enter* ctx) {
  struct clone_args* args = (struct clone_args*)ctx->args[0];
  uint64_t flags;
  if (bpf_core_read_user(&flags, sizeof(flags), &args->flags) < 0) return 1;
  return on_sys_enter_clone(flags);
}
#endif

#ifdef HAVE_RINGBUF_MAP_TYPE
FUNC_INLINE int on_sys_exit_clone(int ret, int event_type) {
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  uint64_t* flags = bpf_map_lookup_elem(&sys_enter_clone_hash, &hash_id);
  if (!flags) return 1;
  struct sys_clone* sys_clone =
      bpf_ringbuf_reserve(&sys_clone_buf, sizeof(*sys_clone), 0);
  if (!sys_clone) goto clean;
  sys_clone->error = 0;
  sys_clone->flags = *flags;
  if (fill_task(&sys_clone->task) < 0) sys_clone->error |= ERROR_FILL_TASK;
  sys_clone->ret = ret;
  sys_clone->event_type = event_type;
  bpf_ringbuf_submit(sys_clone, 0);
clean:
  bpf_map_delete_elem(&sys_enter_clone_hash, &hash_id);
  return 0;
}

#else
FUNC_INLINE int on_sys_exit_clone(struct syscall_trace_exit* ctx,
                                  int event_type) {
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  uint64_t* flags = bpf_map_lookup_elem(&sys_enter_clone_hash, &hash_id);
  if (!flags) return 1;
  struct sys_clone sys_clone = {.error = 0,
                                .flags = *flags,
                                .ret = (int)ctx->ret,
                                .event_type = event_type};
  if (fill_task(&sys_clone.task) < 0) sys_clone.error |= ERROR_FILL_TASK;
  bpf_map_delete_elem(&sys_enter_clone_hash, &hash_id);
  bpf_perf_event_output(ctx, &sys_clone_buf, BPF_F_CURRENT_CPU, &sys_clone,
                        sizeof(sys_clone));
  return 0;
}
#endif

SEC("tracepoint/syscalls/sys_exit_clone")
int tracepoint__syscalls__sys_exit_clone(struct syscall_trace_exit* ctx) {
#ifdef HAVE_RINGBUF_MAP_TYPE
  return on_sys_exit_clone((int)ctx->ret, SYS_CLONE);
#else
  return on_sys_exit_clone(ctx, SYS_CLONE);
#endif
}

#ifdef SYS_CLONE3
SEC("tracepoint/syscalls/sys_exit_clone3")
int tracepoint__syscalls__sys_exit_clone3(struct syscall_trace_exit* ctx) {
#ifdef HAVE_RINGBUF_MAP_TYPE
  return on_sys_exit_clone((int)ctx->ret, SYS_CLONE3);
#else
  return on_sys_exit_clone(ctx, SYS_CLONE3);
#endif
}
#endif

SEC("tracepoint/sched/sched_process_exit")
int tracepoint__sched__sched_process_exit(
    struct trace_event_raw_sched_process_exit* ctx) {
#ifdef HAVE_RINGBUF_MAP_TYPE
  struct sched_process_exit* sched_process_exit = bpf_ringbuf_reserve(
      &sched_process_exit_buf, sizeof(*sched_process_exit), 0);
  if (!sched_process_exit) return 1;
#else
  struct sched_process_exit data;
  struct sched_process_exit* sched_process_exit = &data;
#endif
  sched_process_exit->error = 0;
  sched_process_exit->exit_code = 0;
  long ret = fill_task(&sched_process_exit->task);
  if (ret < 0) sched_process_exit->error |= ERROR_FILL_TASK;
  struct task_struct* task = (struct task_struct*)bpf_get_current_task();
  ret = bpf_core_read(&sched_process_exit->exit_code,
                      sizeof(sched_process_exit->exit_code), &task->exit_code);
  if (ret < 0) sched_process_exit->error |= ERROR_EXIT_CODE;
  sched_process_exit->group_dead = (int)ctx->group_dead;
#ifdef HAVE_RINGBUF_MAP_TYPE
  bpf_ringbuf_submit(sched_process_exit, 0);
#else
  bpf_perf_event_output(ctx, &sched_process_exit_buf, BPF_F_CURRENT_CPU,
                        sched_process_exit, sizeof(*sched_process_exit));
#endif
  return 0;
}
