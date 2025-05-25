#include "logger/bpf/vmlinux.h"
#include "logger/bpf/file.h"
#include "logger/bpf/helpers.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define S_IFIFO 0x1000
#define S_IFCHR 0x2000
#define S_IFDIR 0x4000
#define S_IFBLK 0x6000
#define S_IFREG 0x8000
#define S_IFSOCK 0xC000

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct path_name);
} sys_execve_path SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_write")
int sys_enter_openat(struct syscall_trace_enter* ctx) {
  int fd = (int)ctx->args[0];
  if (fd == AT_FDCWD) return 0;
  int i = 0;
  struct path_name* path_name = bpf_map_lookup_elem(&sys_execve_path, &i);
  if (!path_name) return 1;

  struct path path;
  int ret = get_path_from_fd(fd, &path);
  if (ret < 0) return ret;
  umode_t mode = (umode_t)ret;
  if (!(mode & S_IFREG) || (mode & S_IFBLK)) return 0;

  ret = read_path_name(&path, path_name, 0);
  if (ret < 0) bpf_printk("error to read path_name");
  /*
  bpf_printk("write fd: %3d; path_name: %s", fd,
             path_name->data + path_name->offset);
	     */

  return 0;
}
