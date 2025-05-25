#include "logger/bpf/vmlinux.h"
#include "logger/bpf/process.h"
#include "logger/bpf/helpers.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Buffer for sending data to user space. */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024 * 1024);
} sys_execve_rb SEC(".maps");

/* Map for sharing data between enter and exit syscalls
 * tracepoints. */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct sys_execve_args);
} sys_execve_args_array SEC(".maps");

/* Copies two-dimensional array of src to one-dimensional. Returns
 * written bytes on success and negative on errors. */
FUNC_INLINE int read_argv(char* dst, const char** src) {
  char* ptr;
  unsigned offset = 0;
  for (int i = 0; i < MAX_ARGS; ++i) {
    long ret = bpf_core_read_user(&ptr, sizeof(ptr), &src[i]);
    if (ret < 0) break;
    if (!ptr) break;
    if (offset > (ARGS_SIZE - ARG_SIZE)) break;
    ret = bpf_probe_read_user_str(&dst[offset], ARG_SIZE, ptr);
    if (ret < 0) return -1;
    if (offset - 1 < ARGS_SIZE) dst[offset - 1] = ' ';
    offset = offset + (unsigned)ret;
  }
  return (int)offset;
}

/* Read syscalls sys_execve or sys_exeve_at args. */
FUNC_INLINE int read_args(struct sys_execve_args* args, int dfd,
                          const char* filename, const char** argv) {
  args->dfd = dfd;
  long ret =
      bpf_core_read_user_str(&args->filename, sizeof(args->filename), filename);
  if (ret < 0) return -1;
  ret = (long)read_argv(args->argv, argv);
  if (ret < 0) return -1;
  return 0;
}

/* Copies the syscall args at the end of the syscall. */
FUNC_INLINE int copy_args(struct sys_execve* sys_execve,
                          const struct sys_execve_args* args,
                          const struct syscall_trace_exit* ctx) {
  if (!args || !ctx || !sys_execve) return -1;
  bpf_probe_read_kernel(&sys_execve->args, sizeof(sys_execve->args), args);
  int ret = fill_task(&sys_execve->task);
  if (ret < 0) return ret;
  sys_execve->ret = (int)ctx->ret;
  ret = read_cwd(&sys_execve->cwd);
  if (ret < 0) return ret;
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct syscall_trace_enter* ctx) {
  int i = 0;
  struct sys_execve_args* args =
      bpf_map_lookup_elem(&sys_execve_args_array, &i);
  if (!args) return 1;
  return read_args(args, AT_FDCWD, (const char*)ctx->args[0],
                   (const char**)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int tracepoint__syscalls__sys_enter_execveat(struct syscall_trace_enter* ctx) {
  int i = 0;
  struct sys_execve_args* args =
      bpf_map_lookup_elem(&sys_execve_args_array, &i);
  if (!args) return 1;
  return read_args(args, (int)ctx->args[0], (const char*)ctx->args[1],
                   (const char**)ctx->args[2]);
}

FUNC_INLINE int on_sys_exit_execve(struct syscall_trace_exit* ctx) {
  int i = 0;
  const struct sys_execve_args* args =
      bpf_map_lookup_elem(&sys_execve_args_array, &i);
  if (!args) return 1;
  struct sys_execve* sys_execve = NULL;

  if (args->filename[0] == '/') {
    sys_execve =
        bpf_ringbuf_reserve(&sys_execve_rb, sizeof(struct sys_execve), 0);
    if (!sys_execve) return 1;
    sys_execve->filename_type = PATH_ABSOLUTE;
  } else if (args->dfd == AT_FDCWD) {
    sys_execve =
        bpf_ringbuf_reserve(&sys_execve_rb, sizeof(struct sys_execve), 0);
    if (!sys_execve) return 1;
    sys_execve->filename_type = PATH_RELATIVE_CWD;
  } else {
    struct sys_execveat* sys_execveat =
        bpf_ringbuf_reserve(&sys_execve_rb, sizeof(struct sys_execveat), 0);
    if (!sys_execveat) return 1;
    sys_execve = &sys_execveat->sys_execve;
    sys_execve->filename_type = PATH_RELATIVE_FD;
    read_path_name_fd(args->dfd, &sys_execveat->dir, 1);
  }

  int ret = copy_args(sys_execve, args, ctx);
  if (ret < 0) {
    bpf_ringbuf_discard(sys_execve, 0);
    return 1;
  }
  bpf_ringbuf_submit(sys_execve, 0);
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
