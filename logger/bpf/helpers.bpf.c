#include "logger/bpf/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "logger/bpf/task.h"
#include "logger/bpf/helpers.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int fill_task(struct task* task) {
  if (!task) return -ENULLARG;
  const struct task_struct* current_task =
      (struct task_struct*)bpf_get_current_task();
  if (!current_task) return -ETASKEMPTY;
  task->time_nsec = bpf_ktime_get_tai_ns();
  long ret = bpf_core_read(&task->pid, sizeof(task->pid), &current_task->pid);
  ret |= bpf_core_read(&task->tgid, sizeof(task->tgid), &current_task->tgid);
  const struct task_struct* parent_task;
  ret |= bpf_core_read(&parent_task, sizeof(parent_task),
                       &current_task->real_parent);
  ret |= bpf_core_read(&task->ppid, sizeof(task->ppid), &parent_task->pid);
  u64 id = bpf_get_current_uid_gid();
  task->uid = (uid_t)id;
  task->gid = (gid_t)(id >> 32);
  ret |= bpf_core_read(&task->sessionid, sizeof(task->sessionid),
                       &current_task->sessionid);
  long comm_ret = bpf_get_current_comm(&task->comm, TASK_COMM_LEN);
  if (ret < 0) return -EBPF_PROBE_READ_KERNEL;
  if (comm_ret < 0) return -EGETCURRENTCOMM;
  return 0;
}

int get_file_from_fd(int fd, struct file** file) {
  if (!file) return -ENULLARG;
  if (fd == AT_FDCWD) return -EATFDCWD;
  const struct task_struct* task = (struct task_struct*)bpf_get_current_task();
  if (!task) return -ENULLARG;
  const struct files_struct* files;
  long ret = bpf_core_read(&files, sizeof(files), &task->files);
  if (ret < 0) return -EBPF_PROBE_READ_KERNEL;
  const struct fdtable* fdt;
  ret = bpf_core_read(&fdt, sizeof(fdt), &files->fdt);
  if (ret < 0) return -EBPF_PROBE_READ_KERNEL;
  const struct file** fds;
  ret = bpf_core_read(&fds, sizeof(fds), &fdt->fd);
  if (ret < 0) return -EBPF_PROBE_READ_KERNEL;
  ret = bpf_core_read(file, sizeof(*file), &fds[fd]);
  if (ret < 0) return -EBPF_PROBE_READ_KERNEL;
  return 0;
}

int get_path_from_fd(int fd, struct path* path) {
  if (!path) return -ENULLARG;
  struct file* file;
  int ret = get_file_from_fd(fd, &file);
  if (ret < 0) return ret;
  ret = (int)bpf_core_read(path, sizeof(*path), &file->f_path);
  if (ret < 0 || !file) return -EBPF_PROBE_READ_KERNEL;
  umode_t mode = BPF_CORE_READ(file, f_inode, i_mode);
  return (int)mode;
}

int get_task_pwd(struct path* path) {
  if (!path) return -ENULLARG;
  const struct task_struct* task = (struct task_struct*)bpf_get_current_task();
  const struct fs_struct* fs;
  long ret = bpf_core_read(&fs, sizeof(fs), &task->fs);
  if (ret < 0) return -EBPF_PROBE_READ_KERNEL;
  ret = bpf_core_read(path, sizeof(*path), &fs->pwd);
  if (ret < 0) return -EBPF_PROBE_READ_KERNEL;
  return 0;
}

int read_cwd(struct path_name* path_name) {
  struct path path;
  int ret = get_task_pwd(&path);
  if (ret < 0) return ret;
  return read_path_name(&path, path_name, 1);
}

int read_path_name_fd(int fd, struct path_name* path_name, int is_dir) {
  struct path path;
  int ret = get_path_from_fd(fd, &path);
  if (ret < 0) return ret;
  ret = read_path_name(&path, path_name, is_dir);
  if (ret < 0) return ret;
  return 0;
}

#define CHECK_SET_BREAK_ERROR(statement, error, value) \
  if (statement) {                                     \
    error = value;                                     \
    break;                                             \
  }

int read_path_name(const struct path* path, struct path_name* path_name,
                   int is_dir) {
  if (!path || !path_name) return -ENULLARG;
  const unsigned size = sizeof(path_name->data);
  unsigned offset = size - (unsigned)is_dir;
  const struct dentry *dentry, *dentry_parent;
  long ret = bpf_core_read(&dentry, sizeof(dentry), &path->dentry);
  if (ret < 0) return -EBPF_PROBE_READ_KERNEL;
  const struct vfsmount* vfsmnt;
  ret = bpf_core_read(&vfsmnt, sizeof(vfsmnt), &path->mnt);
  if (ret < 0) return -EBPF_PROBE_READ_KERNEL;
  const struct mount* mnt = container_of(vfsmnt, struct mount, mnt);
  const struct mount* mnt_parent;
  ret = bpf_core_read(&mnt_parent, sizeof(mnt_parent), &mnt->mnt_parent);
  if (ret < 0) return -EBPF_PROBE_READ_KERNEL;
  int error = -EDENTRIESTOOMUCH;
  for (int i = 0; i < MAX_DENTRIES; ++i) {
    ret =
        bpf_core_read(&dentry_parent, sizeof(dentry_parent), &dentry->d_parent);
    CHECK_SET_BREAK_ERROR(ret < 0, error, -EBPF_PROBE_READ_KERNEL);
    if (dentry == dentry_parent) {
      CHECK_SET_BREAK_ERROR(mnt == mnt_parent, error, 0);
      /*
        if (mnt == mnt_parent) {
          error = 0;
          break;
        }
      */
      ret = bpf_core_read(&dentry, sizeof(dentry), &mnt->mnt_mountpoint);
      ret |= bpf_core_read(&dentry_parent, sizeof(dentry_parent),
                           &dentry->d_parent);
      mnt = mnt_parent;
      ret |= bpf_core_read(&mnt_parent, sizeof(mnt_parent), &mnt->mnt_parent);
      CHECK_SET_BREAK_ERROR(ret < 0, error, -EBPF_PROBE_READ_KERNEL);
    }
    struct qstr d_name = BPF_CORE_READ(dentry, d_name);
    unsigned len = (d_name.len + 1) & (DENTRY_NAME_SIZE - 1);
    CHECK_SET_BREAK_ERROR((offset - len) > size, error, -ENAMETOOLONG);
    ret = bpf_probe_read_kernel_str(&path_name->data[offset - len], len,
                                    (const char*)d_name.name);
    CHECK_SET_BREAK_ERROR(ret < 0, error, -EBPF_PROBE_READ_KERNEL);
    if (offset - 1 < size - 1) path_name->data[offset - 1] = '/';
    offset -= len;
    dentry = dentry_parent;
  }
  if (offset < size) path_name->data[offset] = '\0';
  ++offset;
  path_name->offset = offset;
  if (error) return error;
  return (int)offset;
}
