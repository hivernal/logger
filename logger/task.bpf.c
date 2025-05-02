#include "vmlinux.h"
#include "task.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int fill_task(struct task* task) {
  if (!task) return 1;
  struct task_struct* current_task = (struct task_struct*)bpf_get_current_task();
  if (!current_task) return 1;
  task->time_nsec = bpf_ktime_get_tai_ns();
  uint64_t id = bpf_get_current_pid_tgid();
  task->pid = (pid_t)id;
  task->tgid = (uint32_t)(id >> 32);
  task->ppid = BPF_CORE_READ(current_task, real_parent, pid);
  int err = bpf_get_current_comm(&task->comm, TASK_COMM_LEN);
  if (err) return 1;
  id = bpf_get_current_uid_gid();
  task->uid = (uid_t)id;
  task->gid = (gid_t)(id >> 32);
  return 0;
}
