#include "vmlinux.h"
#include "process.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024 * 1024);
} sys_execve_rb SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int sys_enter_execve(struct syscall_trace_enter* ctx) {
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
