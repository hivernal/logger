#include "logger/bpf/vmlinux.h"
#include "logger/bpf/file.h"
#include "logger/bpf/helpers.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define S_IFMT 00170000
#define S_IFSOCK 0140000
#define S_IFLNK 0120000
#define S_IFREG 0100000
#define S_IFBLK 0060000
#define S_IFDIR 0040000
#define S_IFCHR 0020000
#define S_IFIFO 0010000
#define S_ISUID 0004000
#define S_ISGID 0002000
#define S_ISVTX 0001000

#define S_ISLNK(m) (((m) & S_IFMT) == S_IFLNK)
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m) (((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m) (((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct write_args);
} write_args_array SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024 * 1024);
} file_rb SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint__syscalls__sys_enter_write(struct syscall_trace_enter* ctx) {
  int fd = (int)ctx->args[0];
  const char* buffer = (const char*)ctx->args[1];
  size_t count = (size_t)ctx->args[2];
  int i = 0;
  struct write_args* args = bpf_map_lookup_elem(&write_args_array, &i);
  if (!args) return 1;
  args->fd = fd;
  args->count = count;
  if (count + 1 < sizeof(args->buffer)) {
    bpf_probe_read_user_str(&args->buffer, (unsigned)count + 1, buffer);
  } else {
    bpf_probe_read_user_str(&args->buffer, sizeof(args->buffer), buffer);
  }
  struct file* file;
  get_file_from_fd(args->fd, &file);
  args->pos = BPF_CORE_READ(file, f_pos);
  args->flags = BPF_CORE_READ(file, f_flags);
  args->mode = BPF_CORE_READ(file, f_mode);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int tracepoint__syscalls__sys_exit_write(struct syscall_trace_exit* ctx) {
  int i = 0;
  struct write_args* args = bpf_map_lookup_elem(&write_args_array, &i);
  if (!args) return 1;
  struct file* file;
  int ret = get_file_from_fd(args->fd, &file);
  if (ret < 0) return 1;
  struct path path = BPF_CORE_READ(file, f_path);
  umode_t mode = BPF_CORE_READ(file, f_inode, i_mode);
  if (!S_ISREG(mode)) return 0;
  struct write* write = bpf_ringbuf_reserve(&file_rb, sizeof(struct write), 0);
  if (!write) return 0;
  ret = read_path_name(&path, &write->path_name, 0);
  if (ret < 0) goto clean;
  ret = (int)bpf_probe_read_kernel(&write->args, sizeof(write->args), args);
  if (ret < 0) goto clean;
  write->ret = (int)ctx->ret;
  fill_task(&write->task);
  bpf_ringbuf_submit(write, 0);
  return 0;
clean:
  bpf_ringbuf_discard(write, 0);
  return 1;
}
