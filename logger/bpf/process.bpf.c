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

/* Map for sharing data between sys_enter_execve and sys_exit_execve
 * tracepoints. */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct sys_execve_args);
} sys_execve_args_array SEC(".maps");

/* Copies two-dimensional array of src to one-dimensional args->data. Returns
 * written bytes on success and negative on errors. */
static __always_inline int read_argv(char* dst, const char** src) {
  char* ptr;
  unsigned offset = 0;
  for (int i = 0; i < MAX_ARGS; ++i) {
    int ret = bpf_core_read_user(&ptr, sizeof(ptr), &src[i]);
    if (ret < 0) return ret;
    if (!ptr) break;
    if (offset > (ARGS_SIZE - ARG_SIZE)) break;
    ret = bpf_probe_read_user_str(&dst[offset], ARG_SIZE, ptr);
    if (offset - 1 < ARGS_SIZE) dst[offset - 1] = ' ';
    if (ret < 0) return ret;
    offset = offset + (unsigned)ret;
  }
  return offset;
}

/* Copy sys_execve or sys_exeve_at args. */
int read_args(struct sys_execve_args* args, int dfd, const char* pathname,
              const char** argv) {
  args->dfd = dfd;
  int ret =
      bpf_core_read_user_str(&args->pathname, sizeof(args->pathname), pathname);
  if (ret < 0) return ret;
  ret = read_argv(args->argv, argv);
  if (ret < 0) return ret;
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int sys_enter_execve(struct syscall_trace_enter* ctx) {
  int i = 0;
  struct sys_execve_args* args =
      bpf_map_lookup_elem(&sys_execve_args_array, &i);
  if (!args) return 1;
  return read_args(args, AT_FDCWD, (const char*)ctx->args[0],
                   (const char**)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_exit_execve")
int sys_exit_execve(struct syscall_trace_exit* ctx) {
  struct sys_execve* sys_execve =
      bpf_ringbuf_reserve(&sys_execve_rb, sizeof(struct sys_execve), 0);
  if (!sys_execve) return 1;

  int i = 0;
  const struct sys_execve_args* args =
      bpf_map_lookup_elem(&sys_execve_args_array, &i);
  if (!args) goto cleanup;
  int ret = bpf_probe_read_kernel_str(
      &sys_execve->args.argv, sizeof(sys_execve->args.argv), &args->argv);
  if (!ret) goto cleanup;
  ret = bpf_probe_read_kernel_str(&sys_execve->args.pathname,
                                  sizeof(sys_execve->args.pathname),
                                  &args->pathname);
  if (!ret) goto cleanup;
  if (fill_task(&sys_execve->task)) goto cleanup;
  sys_execve->ret = ctx->ret;

  struct task_struct* task = (struct task_struct*)bpf_get_current_task();
  struct fs_struct* fs;
  ret = bpf_core_read(&fs, sizeof(fs), &task->fs);
  if (ret < 0) goto cleanup;
  struct path path;
  ret = bpf_core_read(&path, sizeof(path), &fs->pwd);
  if (ret < 0) goto cleanup;
  ret = read_path_name(&path, &sys_execve->cwd, 1);
  if (ret < 0) goto cleanup;

  bpf_ringbuf_submit(sys_execve, 0);
  return 0;
cleanup:
  bpf_ringbuf_discard(sys_execve, 0);
  return 1;
}
