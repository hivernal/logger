#include "logger/bpf/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "logger/bpf/task.h"
#include "logger/bpf/helpers.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int fill_task(struct task* task) {
  if (!task) return 1;
  const struct task_struct* current_task =
      (struct task_struct*)bpf_get_current_task();
  if (!current_task) return 1;
  task->time_nsec = bpf_ktime_get_tai_ns();
  task->pid = BPF_CORE_READ(current_task, pid);
  task->tgid = BPF_CORE_READ(current_task, tgid);
  task->ppid = BPF_CORE_READ(current_task, real_parent, pid);
  int err = bpf_get_current_comm(&task->comm, TASK_COMM_LEN);
  if (err) return err;
  uint64_t id = bpf_get_current_uid_gid();
  task->uid = (uid_t)id;
  task->gid = (gid_t)(id >> 32);
  return 0;
}

/* Copies user/kernel string with an offset. Returns: 0 - no available space,
 * negative - errors, positive - written bytes. */
#define copy_str(type)                                               \
  int copy_##type##_str(char* dst, const char* src, unsigned offset, \
                        int dst_size, int size) {                    \
    if (!src) return -1;                                             \
    if (offset > (dst_size - size)) return 0;                        \
    return bpf_probe_read_##type##_str(&dst[offset], size, src);     \
  }
copy_str(kernel);
copy_str(user);

int get_file_from_fd(int fd, struct file** file) {
  if (!file || fd == AT_FDCWD) return -1;
  struct task_struct* task = (struct task_struct*)bpf_get_current_task();
  if (!task) return -1;
  struct files_struct* files;
  int ret = bpf_core_read(&files, sizeof(files), &task->files);
  if (ret < 0) return ret;
  struct fdtable* fdt;
  ret = bpf_core_read(&fdt, sizeof(fdt), &files->fdt);
  if (ret < 0) return ret;
  struct file** fds;
  ret = bpf_core_read(&fds, sizeof(fds), &fdt->fd);
  if (ret < 0) return ret;
  ret = bpf_core_read(file, sizeof(*file), &fds[fd]);
  if (ret < 0) return ret;
  return 0;
}

int get_path_from_fd(int fd, struct path* path) {
  if (!path) return -1;
  struct file* file;
  int ret = get_file_from_fd(fd, &file);
  if (ret < 0) return ret;
  ret = bpf_core_read(path, sizeof(*path), &file->f_path);
  if (ret < 0 || !file) return ret;
  umode_t mode = BPF_CORE_READ(file, f_inode, i_mode);
  return (int)mode;
}

int read_path_name(const struct path* path, struct path_name* path_name,
                   int is_dir) {
  if (!path || !path_name) return -1;
  unsigned size = sizeof(path_name->data);
  unsigned offset = size;
  if (is_dir) --offset;

  const struct dentry* dentry = BPF_CORE_READ(path, dentry);
  const struct dentry* dentry_parent;
  struct vfsmount* vfsmnt = BPF_CORE_READ(path, mnt);
  struct mount* mnt = container_of(vfsmnt, struct mount, mnt);
  struct mount* mnt_parent = BPF_CORE_READ(mnt, mnt_parent);

  for (int i = 0; i < MAX_DENTRIES; ++i) {
    dentry_parent = BPF_CORE_READ(dentry, d_parent);
    if (dentry == dentry_parent) {
      if (mnt == mnt_parent) break;
      dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
      dentry_parent = BPF_CORE_READ(dentry, d_parent);
      mnt = mnt_parent;
      mnt_parent = BPF_CORE_READ(mnt, mnt_parent);
    }

    struct qstr d_name = BPF_CORE_READ(dentry, d_name);
    unsigned len = (d_name.len + 1) & (DENTRY_NAME_SIZE - 1);
    if ((offset - len) > size) break;
    int ret = bpf_probe_read_kernel_str(&path_name->data[offset - len], len,
                                        (const char*)d_name.name);
    if (ret < 0) return ret;
    if (offset - 1 < size - 1) path_name->data[offset - 1] = '/';
    offset -= len;
    dentry = dentry_parent;
  }
  if (offset < size) path_name->data[offset] = '\0';
  ++offset;
  path_name->offset = offset;
  return (int)offset;
}
