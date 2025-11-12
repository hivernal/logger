#ifndef LOGGER_BPF_HELPERS_H_
#define LOGGER_BPF_HELPERS_H_

#include "logger/bpf/vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "logger/bpf/task.h"

#define FUNC_INLINE static inline __attribute__((always_inline))
#define AT_FDCWD -100

char LICENSE[] SEC("license") = "Dual BSD/GPL";

enum helper_error {
  ENULLARG = 1,
  EATFDCWD,
  EBPF_PROBE_READ_KERNEL,
  EBPF_PROBE_READ_USER,
  ENAMETOOLONG,
  EDENTRIESTOOMUCH,
  ETASKEMPTY,
  EGETCURRENTCOMM,
  EBPFMAPLOOKUP,
};

FUNC_INLINE int fill_task_cred(struct task_cred* task_cred,
                               const struct task_struct* task) {
  if (!task_cred || !task) return -ENULLARG;
  const struct cred* real_cred;
  long ret = bpf_core_read(&real_cred, sizeof(real_cred), &task->real_cred);
  if (ret < 0) return -EBPF_PROBE_READ_KERNEL;
  ret = bpf_core_read(task_cred, sizeof(*task_cred), &real_cred->uid);
  if (ret < 0) return -EBPF_PROBE_READ_KERNEL;
  return 0;
}

/*
 * Fills task structure (tgid, pid, ppid, time_nsec, comm, loginuid, sessionid).
 */
FUNC_INLINE int fill_task(struct task* task) {
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
  ret |= bpf_core_read(&task->sessionid, sizeof(task->sessionid),
                       &current_task->sessionid);
  ret |= bpf_core_read(&task->loginuid, sizeof(task->loginuid),
                       &current_task->loginuid);
  ret |= fill_task_cred(&task->cred, current_task);
  long comm_ret = bpf_get_current_comm(&task->comm, TASK_COMM_LEN);
  if (ret < 0) return -EBPF_PROBE_READ_KERNEL;
  if (comm_ret < 0) return -EGETCURRENTCOMM;
  return 0;
}

/*
 * Gets file structure from file descriptor fd. Returns 0 on success, other on
 * errors.
 */
FUNC_INLINE int get_file_from_fd(int fd, const struct file** file) {
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
  ret = bpf_probe_read_kernel(file, sizeof(*file), &fds[fd]);
  if (ret < 0) return -EBPF_PROBE_READ_KERNEL;
  return 0;
}

/*
 * Gets path structure from file descriptor fd.
 * Returns 0 on success and negative on errors.
 */
FUNC_INLINE int get_path_from_fd(int fd, const struct path** path) {
  if (!path) return -ENULLARG;
  const struct file* file;
  int ret = get_file_from_fd(fd, &file);
  if (ret < 0) return ret;
  *path = &file->f_path;
  // ret = (int)bpf_core_read(path, sizeof(struct path), &file->f_path);
  // if (ret < 0) return -EBPF_PROBE_READ_KERNEL;
  return 0;
}

/*
 * Gets path structure pwd from current task. Returns 0 on success, other on
 * errors.
 */
FUNC_INLINE int get_task_pwd(const struct path** path) {
  if (!path) return -ENULLARG;
  const struct task_struct* task = (struct task_struct*)bpf_get_current_task();
  struct fs_struct* fs;
  long ret = bpf_core_read(&fs, sizeof(fs), &task->fs);
  if (ret < 0) return -EBPF_PROBE_READ_KERNEL;
  *path = &fs->pwd;
  // ret = bpf_core_read(path, sizeof(*path), &fs->pwd);
  // if (ret < 0) return -EBPF_PROBE_READ_KERNEL;
  return 0;
}

/*
 * Parses list of dentries from path. Writes from end to start
 * path_dentries->data. Returns offset of first byte or negative on errors.
 */
FUNC_INLINE int read_path_dentries(const struct path* path,
                                   struct path_dentries* path_dentries,
                                   int is_dir) {
  if (!path || !path_dentries) return -ENULLARG;
  const unsigned size = sizeof(path_dentries->data);
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
    if (ret < 0) {
      error = -EBPF_PROBE_READ_KERNEL;
      break;
    }
    if (dentry == dentry_parent) {
      if (mnt == mnt_parent) {
        error = 0;
        break;
      }
      ret = bpf_core_read(&dentry, sizeof(dentry), &mnt->mnt_mountpoint);
      ret |= bpf_core_read(&dentry_parent, sizeof(dentry_parent),
                           &dentry->d_parent);
      mnt = mnt_parent;
      ret |= bpf_core_read(&mnt_parent, sizeof(mnt_parent), &mnt->mnt_parent);
      if (ret < 0) {
        error = -EBPF_PROBE_READ_KERNEL;
        break;
      }
    }
    struct qstr d_name = BPF_CORE_READ(dentry, d_name);
    unsigned len = (d_name.len + 1) & (DENTRY_NAME_SIZE - 1);
    if (offset - len > size) {
      error = -ENAMETOOLONG;
      break;
    }
    ret = bpf_probe_read_kernel_str(&path_dentries->data[offset - len], len,
                                    (const char*)d_name.name);
    if (ret < 0) {
      error = -EBPF_PROBE_READ_KERNEL;
      break;
    }
    if (offset - 1 < size - 1) path_dentries->data[offset - 1] = '/';
    offset -= len;
    dentry = dentry_parent;
  }
  if (error) return error;
  if (offset < size) path_dentries->data[offset] = '\0';
  ++offset;
  path_dentries->offset = offset;
  return (int)offset;
}

FUNC_INLINE int read_path_dentries_fd(int fd,
                                      struct path_dentries* path_dentries,
                                      int is_dir) {
  path_dentries->offset = 0;
  const struct path* path;
  int ret = 0;
  if (fd == AT_FDCWD) {
    ret = get_task_pwd(&path);
    if (ret < 0) return ret;
  } else {
    ret = get_path_from_fd(fd, &path);
    if (ret < 0) return ret;
  }
  ret = read_path_dentries(path, path_dentries, is_dir);
  if (ret < 0) return ret;
  return 0;
}

FUNC_INLINE int read_cwd(struct path_dentries* path_dentries) {
  const struct path* path;
  int ret = get_task_pwd(&path);
  if (ret < 0) return ret;
  return read_path_dentries(path, path_dentries, 1);
}

#endif  // LOGGER_BPF_HELPERS_H_
