#include "vmlinux.h"
#include "process.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024 * 1024);
} sys_execve_rb SEC(".maps");

struct sys_execve_argv {
  char argv[FULL_MAX_ARGS_ARR];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32);
  __type(value, struct sys_execve_argv);
} sys_execve_hash SEC(".maps");

static const struct sys_execve_argv empty_sys_execve_argv = {};

int copy_argv(char dst[], const char** src) {
  char* ptr;
  bpf_core_read_user(&ptr, sizeof(ptr), &src[0]);
  bpf_core_read_user_str(dst, FULL_MAX_ARGS_ARR, ptr);
  bpf_printk("%s\n", dst);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int sys_enter_execve(struct syscall_trace_enter* ctx) {
  pid_t pid = (pid_t)(bpf_get_current_pid_tgid() >> 32);
  if (bpf_map_update_elem(&sys_execve_hash, &pid, &empty_sys_execve_argv,
                          BPF_NOEXIST))
    return 1;
  struct sys_execve_argv* sys_execve_argv =
      bpf_map_lookup_elem(&sys_execve_hash, &pid);
  if (!sys_execve_argv) return 1;
  const char** argv = (const char**)ctx->args[1];
  copy_argv(&sys_execve_argv->argv, argv);
  bpf_map_delete_elem(&sys_execve_hash, &pid);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int sys_exit_execve(struct syscall_trace_exit* ctx) {
  struct sys_execve* sys_execve =
      bpf_ringbuf_reserve(&sys_execve_rb, sizeof(struct sys_execve), 0);
  if (!sys_execve) return 1;
  if (fill_task(&sys_execve->task)) goto cleanup;
  bpf_ringbuf_submit(sys_execve, 0);
  return 0;
cleanup:
  bpf_ringbuf_discard(sys_execve, 0);
  return 1;
}
