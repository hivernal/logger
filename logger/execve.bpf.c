#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tp/syscalls/sys_enter_execve")
int handle_tp(void *ctx) {
  int pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("BPF triggered from PID %d.\n", pid);
  return 0;
}
