#include "logger/bpf/helpers.h"
#include "logger/bpf/process.h"

/* Buffer for sending sys_execve data to userspace. */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, NPROC * sizeof(struct sys_execveat));
} sys_execve_rb SEC(".maps");

/* Buffer for sending sys_clone data to the userspace. */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, NPROC * sizeof(struct sys_clone));
} sys_clone_rb SEC(".maps");

/* Buffer for sending sched_process_exit data to the userspace. */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, NPROC * sizeof(struct sched_process_exit));
} sched_process_exit_rb SEC(".maps");

/* Map for sharing data between enter and exit tracepoints. */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct sys_enter_execve);
} sys_enter_execve_array SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 128);
  __type(key, u64);
  __type(value, struct sys_enter_execve);
} sys_enter_execve_hash SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 128);
  __type(key, u64);
  __type(value, u64);
} sys_enter_clone_hash SEC(".maps");

const int array_index = 0;

/*
 * Copies two-dimensional array of src to one-dimensional.
 * Returns written bytes on success and negative on errors.
 */
FUNC_INLINE int read_argv(char* dst, const char** src) {
  const char* ptr;
  unsigned offset = 0;
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

FUNC_INLINE int on_sys_enter_execve(int fd, const char* filename,
                                      const char** argv) {
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

FUNC_INLINE long fill_task_caps(struct task_caps* caps) {
  const struct task_struct* task = (struct task_struct*)bpf_get_current_task();
  const struct cred* cred;
  long ret = bpf_core_read(&cred, sizeof(cred), &task->real_cred);
  if (ret < 0) return ret;
  return bpf_core_read(caps, sizeof(*caps), &cred->cap_inheritable);
}

FUNC_INLINE int on_sys_exit_execve(struct syscall_trace_exit* ctx) {
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
      bpf_ringbuf_reserve(&sys_execve_rb, reserved, 0);
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
  sys_execve->ret = (int)ctx->ret;
  sys_execve->filename_type = filename_type;
  bpf_ringbuf_submit(sys_execve, 0);
clean:
  bpf_map_delete_elem(&sys_enter_execve_hash, &hash_id);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__syscalls__sys_exit_execve(struct syscall_trace_exit* ctx) {
  return on_sys_exit_execve(ctx);
}

SEC("tracepoint/syscalls/sys_exit_execveat")
int tracepoint__syscalls__sys_exit_execveat(struct syscall_trace_exit* ctx) {
  return on_sys_exit_execve(ctx);
}

FUNC_INLINE int on_sys_enter_clone(uint64_t flags) {
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  return (int)bpf_map_update_elem(&sys_enter_clone_hash, &hash_id, &flags, BPF_ANY);
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

FUNC_INLINE int on_sys_exit_clone(int ret) {
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  uint64_t* flags = bpf_map_lookup_elem(&sys_enter_clone_hash, &hash_id);
  if (!flags) return 1;
  struct sys_clone* sys_clone =
      bpf_ringbuf_reserve(&sys_clone_rb, sizeof(*sys_clone), 0);
  if (!sys_clone) goto clean;
  sys_clone->error = 0;
  sys_clone->flags = *flags;
  if (fill_task(&sys_clone->task) < 0) sys_clone->error |= ERROR_FILL_TASK;
  sys_clone->ret = ret;
  bpf_ringbuf_submit(sys_clone, 0);
clean:
  bpf_map_delete_elem(&sys_enter_clone_hash, &hash_id);
  return 0;
}

#ifdef SYS_CLONE3
SEC("tracepoint/syscalls/sys_exit_clone")
int tracepoint__syscalls__sys_exit_clone(struct syscall_trace_exit* ctx) {
  return on_sys_exit_clone((int)ctx->ret);
}
#endif

SEC("tracepoint/syscalls/sys_exit_clone3")
int tracepoint__syscalls__sys_exit_clone3(struct syscall_trace_exit* ctx) {
  return on_sys_exit_clone((int)ctx->ret);
}

SEC("tracepoint/sched/sched_process_exit")
int tracepoint__sched__sched_process_exit(
    struct trace_event_raw_sched_process_exit* ctx) {
  struct sched_process_exit* sched_process_exit = bpf_ringbuf_reserve(
      &sched_process_exit_rb, sizeof(*sched_process_exit), 0);
  if (!sched_process_exit) return 1;
  sched_process_exit->error = 0;
  sched_process_exit->exit_code = 0;
  long ret = fill_task(&sched_process_exit->task);
  if (ret < 0) sched_process_exit->error |= ERROR_FILL_TASK;
  struct task_struct* task = (struct task_struct*)bpf_get_current_task();
  ret = bpf_core_read(&sched_process_exit->exit_code,
                      sizeof(sched_process_exit->exit_code), &task->exit_code);
  if (ret < 0) sched_process_exit->error |= ERROR_EXIT_CODE;
  sched_process_exit->group_dead = (int)ctx->group_dead;
  bpf_ringbuf_submit(sched_process_exit, 0);
  return 0;
}
