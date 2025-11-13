#include "logger/bpf/helpers.h"
#include "logger/bpf/file.h"

/*
 * Map for sharing data between
 * sys_enter_write and sys_exit_write,
 * sys_enter_read and sys_exit_read,
 * sys_enter_unlink and sys_exit_unlink,
 * sys_enter_unlinkat and sys_exit_unlinkat,
 * sys_enter_chmod and sys_exit_chmod,
 * sys_enter_fchmod and sys_exit_fchmod,
 * sys_enter_fchmodat and sys_exit_fchmodat,
 * sys_enter_fchmodat2 and sys_exit_fchmodat2
 * tracepoints.
 */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct sys_enter_file);
} sys_enter_file_array SEC(".maps");

/* Buffer for sending sys_write data to the userspace. */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries,
         NPROC * (sizeof(struct sys_write) + SYS_WRITE_BUFFER_SIZE));
} sys_write_rb SEC(".maps");

/* Buffer for sending sys_read data to the userspace. */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, NPROC * sizeof(struct sys_read));
} sys_read_rb SEC(".maps");

/* Buffer for sending sys_unlink data to the userspace. */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, NPROC * sizeof(struct sys_unlinkat));
} sys_unlink_rb SEC(".maps");

/* Buffer for sending sys_chmod data to the userspace. */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, NPROC * sizeof(struct sys_fchmodat));
} sys_chmod_rb SEC(".maps");

/* Buffer for sending sys_chown data to the userspace. */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, NPROC * sizeof(struct sys_fchownat));
} sys_chown_rb SEC(".maps");

/* Buffer for sending data to the userspace. */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, NPROC * sizeof(struct sys_renameat2));
} sys_rename_rb SEC(".maps");

/* For file.f_inode->i_mode. */
#define S_IFMT 00170000
/* Linux socket. */
#define S_IFSOCK 0140000
/* Symbolic link. */
#define S_IFLNK 0120000
/* Regular file. */
#define S_IFREG 0100000
/* Block device. */
#define S_IFBLK 0060000
/* Directory. */
#define S_IFDIR 0040000
/* Character device. */
#define S_IFCHR 0020000
/* Pipe. */
#define S_IFIFO 0010000
/* SUID. */
#define S_ISUID 0004000
/* GUID. */
#define S_ISGID 0002000
/* Sticky bit. */
#define S_ISVTX 0001000

/* Is symbolic link. */
#define S_ISLNK(m) (((m) & S_IFMT) == S_IFLNK)
/* Is regular file. */
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
/* Is directory. */
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
/* Is character device. */
#define S_ISCHR(m) (((m) & S_IFMT) == S_IFCHR)
/* Is block device. */
#define S_ISBLK(m) (((m) & S_IFMT) == S_IFBLK)
/* Is named pipe. */
#define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
/* Is socket. */
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)


/* Compares strings. Returns 0 if strings are equal. */
FUNC_INLINE int bpfstrcmp(const char* s1, const char* s2, unsigned size) {
  if (!s1 || !s2) return -256;
  for (unsigned i = 0; i < size && *s1 && (*s1 == *s2); ++s1, ++s2, ++i);
  char c1 = *s1, c2 = *s2;
  return (int)(c1 - c2);
}
/* Compares strings. Returns 0 if s1 contains s2. */
FUNC_INLINE int bpfstrcmp_contains(const char* s1, const char* s2,
                                    unsigned size) {
  if (!s1 || !s2) return -256;
  for (unsigned i = 0; i < size && *s1 && (*s1 == *s2); ++s1, ++s2, ++i);
  char c1 = *s1, c2 = *s2;
  if (!c2) return 0;
  return (int)(c1 - c2);
}

/*
 * Checks if path_dentries is the system file
 * that contains data about users and groups.
 */
FUNC_INLINE int is_file_with_buffer(const struct path_dentries* path_dentries) {
  if (!path_dentries) return -ENULLARG;
  unsigned offset = path_dentries->offset;
  if (offset >= sizeof(path_dentries->data)) return 0;
  unsigned size = sizeof(path_dentries->data) - offset;
  if (bpfstrcmp_contains(&path_dentries->data[offset], "/etc/", size) != 0) {
    return FILE_TYPE_OTHER;
  }
  offset += sizeof("/etc/") - 1;
  if (offset >= sizeof(path_dentries->data)) return 0;
  size = sizeof(path_dentries->data) - offset;
  if (bpfstrcmp(&path_dentries->data[offset], "passwd", size) == 0) {
    return FILE_TYPE_PASSWD;
  }
  if (bpfstrcmp(&path_dentries->data[offset], "group", size) == 0) {
    return FILE_TYPE_GROUP;
  }
  if (bpfstrcmp(&path_dentries->data[offset], "doas.conf", size) == 0) {
    return FILE_TYPE_DOAS;
  }
  if (bpfstrcmp(&path_dentries->data[offset], "sudoers", size) == 0) {
    return FILE_TYPE_SUDOERS;
  }
  if (bpfstrcmp_contains(&path_dentries->data[offset], "sudoers.d/", size) ==
      0) {
    return FILE_TYPE_SUDOERS_DIR;
  }
  return FILE_TYPE_OTHER;
}

const int array_index = 0;

/* From userspace. */
pid_t logger_pid;

#define is_logger_pid() ((pid_t)bpf_get_current_pid_tgid() == logger_pid)

FUNC_INLINE int on_sys_enter_write(int fd, const char* buffer, size_t count) {
  if (is_logger_pid()) return 0;
  struct sys_enter_file* enter =
      bpf_map_lookup_elem(&sys_enter_file_array, &array_index);
  if (!enter) return 1;
  enter->error = 0;
  enter->is_correct = 0;
  const struct file* file;
  if (get_file_from_fd(fd, &file)) return 1;
  umode_t i_mode = BPF_CORE_READ(file, f_inode, i_mode);
  if (!S_ISREG(i_mode)) return 0;
  if (read_path_dentries_fd(fd, &enter->path_dentries, 0) < 0)
    enter->error |= ERROR_READ_FD;
  enter->file_type = is_file_with_buffer(&enter->path_dentries);
  if (enter->file_type &&
      bpf_core_read_user_str(&enter->buffer,
                             (unsigned)count & (sizeof(enter->buffer) - 1),
                             buffer) < 0)
    enter->error |= ERROR_FILL_BUFFER;
  enter->fd = fd;
  enter->count = count;
  enter->f_pos = BPF_CORE_READ(file, f_pos);
  enter->f_flags = BPF_CORE_READ(file, f_flags);
  enter->f_mode = BPF_CORE_READ(file, f_mode);
  enter->is_correct = 1;
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint__syscalls__sys_enter_write(struct syscall_trace_enter* ctx) {
  return on_sys_enter_write((int)ctx->args[0], (const char*)ctx->args[1],
                            (size_t)ctx->args[2]);
}

#define copy_sys_enter_write(sys_write, enter)                         \
  sys_write->error = enter->error;                                     \
  sys_write->count = enter->count;                                     \
  sys_write->f_pos = enter->f_pos;                                     \
  sys_write->f_flags = enter->f_flags;                                 \
  sys_write->f_mode = enter->f_mode;                                   \
  sys_write->file_type = enter->file_type;                             \
  if (bpf_probe_read_kernel(&sys_write->file, sizeof(sys_write->file), \
                            &enter->path_dentries) < 0) {              \
    sys_write->error |= ERROR_COPY_ENTER;                              \
  }

FUNC_INLINE int on_sys_exit_write(int ret) {
  if (is_logger_pid()) return 0;
  struct sys_enter_file* enter =
      bpf_map_lookup_elem(&sys_enter_file_array, &array_index);
  if (!enter || !enter->is_correct) return 1;
  enter->is_correct = 0;
  unsigned buffer_size = 0;
  if (enter->file_type != FILE_TYPE_OTHER) {
    if (ret > 0) {
      buffer_size = (unsigned)(ret + 1) & (SYS_WRITE_BUFFER_SIZE - 1);
    } else {
      buffer_size = SYS_WRITE_BUFFER_SIZE;
    }
  }
  size_t reserved_size = sizeof(struct sys_write);
  if (buffer_size) reserved_size += SYS_WRITE_BUFFER_SIZE;
  struct sys_write* sys_write =
      bpf_ringbuf_reserve(&sys_write_rb, reserved_size, 0);
  if (!sys_write) return 1;
  copy_sys_enter_write(sys_write, enter);
  if (buffer_size && bpf_probe_read_kernel(&sys_write->buffer, buffer_size,
                                           &enter->buffer) < 0) {
    sys_write->error |= ERROR_COPY_BUFFER;
  }
  if (fill_task(&sys_write->task) < 0) sys_write->error |= ERROR_FILL_TASK;
  sys_write->ret = ret;
  bpf_ringbuf_submit(sys_write, 0);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int tracepoint__syscalls__sys_exit_write(struct syscall_trace_exit* ctx) {
  return on_sys_exit_write((int)ctx->ret);
}

FUNC_INLINE int on_sys_enter_read(int fd, size_t count) {
  if (is_logger_pid()) return 0;
  struct sys_enter_file* enter =
      bpf_map_lookup_elem(&sys_enter_file_array, &array_index);
  if (!enter) return 1;
  enter->error = 0;
  enter->is_correct = 0;
  const struct file* file;
  if (get_file_from_fd(fd, &file)) return 1;
  umode_t i_mode = BPF_CORE_READ(file, f_inode, i_mode);
  if (!S_ISREG(i_mode)) return 0;
  enter->fd = fd;
  enter->count = count;
  enter->f_pos = BPF_CORE_READ(file, f_pos);
  enter->f_flags = BPF_CORE_READ(file, f_flags);
  enter->f_mode = BPF_CORE_READ(file, f_mode);
  enter->is_correct = 1;
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint__syscalls__sys_enter_read(struct syscall_trace_enter* ctx) {
  return on_sys_enter_read((int)ctx->args[0], (size_t)ctx->args[2]);
}

FUNC_INLINE int on_sys_exit_read(int sys_ret) {
  if (is_logger_pid()) return 0;
  struct sys_enter_file* enter =
      bpf_map_lookup_elem(&sys_enter_file_array, &array_index);
  if (!enter || !enter->is_correct) return 1;
  enter->is_correct = 0;
  struct sys_read* sys_read =
      bpf_ringbuf_reserve(&sys_read_rb, sizeof(*sys_read), 0);
  if (!sys_read) return 1;
  sys_read->error = enter->error;
  sys_read->count = enter->count;
  sys_read->f_pos = enter->f_pos;
  sys_read->f_flags = enter->f_flags;
  sys_read->f_mode = enter->f_mode;
  if (read_path_dentries_fd(enter->fd, &sys_read->file, 0) < 0)
    sys_read->error |= ERROR_READ_FD;
  sys_read->ret = sys_ret;
  if (fill_task(&sys_read->task) < 0) sys_read->error |= ERROR_FILL_TASK;
  bpf_ringbuf_submit(sys_read, 0);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int tracepoint__syscalls__sys_exit_read(struct syscall_trace_exit* ctx) {
  return on_sys_exit_read((int)ctx->ret);
}

FUNC_INLINE int on_sys_enter_unlink(int dfd, const char* filename, int flags) {
  struct sys_enter_file* enter =
      bpf_map_lookup_elem(&sys_enter_file_array, &array_index);
  if (!enter) return 1;
  enter->error = 0;
  if (bpf_core_read_user_str(&enter->filename, sizeof(enter->filename),
                             filename) < 0)
    enter->error |= ERROR_FILENAME;
  enter->fd = dfd;
  enter->flags = flags;
  enter->is_correct = 1;
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int tracepoint__syscalls__sys_enter_unlink(struct syscall_trace_enter* ctx) {
  return on_sys_enter_unlink(AT_FDCWD, (const char*)ctx->args[0], 0);
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tracepoint__syscalls__sys_enter_unlinkat(struct syscall_trace_enter* ctx) {
  return on_sys_enter_unlink((int)ctx->args[0], (const char*)ctx->args[1],
                             (int)ctx->args[2]);
}

FUNC_INLINE int on_sys_exit_unlink(int ret, int event_type) {
  struct sys_enter_file* enter =
      bpf_map_lookup_elem(&sys_enter_file_array, &array_index);
  if (!enter || !enter->is_correct) return 1;
  enter->is_correct = 0;
  struct sys_unlink* sys_unlink;
  if (enter->filename[0] == '/') {
    sys_unlink = bpf_ringbuf_reserve(&sys_unlink_rb, sizeof(*sys_unlink), 0);
    if (!sys_unlink) return 1;
    sys_unlink->filename_type = PATH_ABSOLUTE;
  } else {
    struct sys_unlinkat* sys_unlinkat =
        bpf_ringbuf_reserve(&sys_unlink_rb, sizeof(*sys_unlinkat), 0);
    if (!sys_unlinkat) return 1;
    sys_unlink = &sys_unlinkat->sys_unlink;
    sys_unlink->filename_type = PATH_RELATIVE_FD;
    if (read_path_dentries_fd(enter->fd, &sys_unlinkat->dir, 1) < 0)
      enter->error |= ERROR_READ_FD;
  }
  sys_unlink->error = enter->error;
  if (bpf_probe_read_kernel_str(&sys_unlink->filename,
                                sizeof(sys_unlink->filename),
                                &enter->filename) < 0)
    sys_unlink->error |= ERROR_FILENAME;
  sys_unlink->flags = enter->flags;
  sys_unlink->event_type = event_type;
  sys_unlink->ret = ret;
  if (fill_task(&sys_unlink->task) < 0) sys_unlink->error |= ERROR_FILL_TASK;
  bpf_ringbuf_submit(sys_unlink, 0);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_unlink")
int tracepoint__syscalls__sys_exit_unlink(struct syscall_trace_exit* ctx) {
  return on_sys_exit_unlink((int)ctx->ret, SYS_UNLINK);
}

SEC("tracepoint/syscalls/sys_exit_unlinkat")
int tracepoint__syscalls__sys_exit_unlinkat(struct syscall_trace_exit* ctx) {
  return on_sys_exit_unlink((int)ctx->ret, SYS_UNLINKAT);
}

FUNC_INLINE int on_sys_enter_chmod(int fd, const char* filename, unsigned mode,
                                   int flags) {
  struct sys_enter_file* enter =
      bpf_map_lookup_elem(&sys_enter_file_array, &array_index);
  if (!enter) return 1;
  enter->error = 0;
  *enter->filename = 0;
  if (bpf_core_read_user_str(&enter->filename, sizeof(enter->filename),
                             filename) < 0) {
    enter->error |= ERROR_FILENAME;
  }
  enter->fd = fd;
  enter->flags = flags;
  enter->mode = mode;
  enter->is_correct = 1;
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_chmod")
int tracepoint__syscalls__sys_enter_chmod(struct syscall_trace_enter* ctx) {
  return on_sys_enter_chmod(AT_FDCWD, (const char*)ctx->args[0],
                            (unsigned)ctx->args[1], 0);
}

SEC("tracepoint/syscalls/sys_enter_fchmod")
int tracepoint__syscalls__sys_enter_fchmod(struct syscall_trace_enter* ctx) {
  return on_sys_enter_chmod((int)ctx->args[0], NULL, (unsigned)ctx->args[1], 0);
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int tracepoint__syscalls__sys_enter_fchmodat(struct syscall_trace_enter* ctx) {
  return on_sys_enter_chmod((int)ctx->args[0], (const char*)ctx->args[1],
                            (unsigned)ctx->args[2], 0);
}

SEC("tracepoint/syscalls/sys_enter_fchmodat2")
int tracepoint__syscalls__sys_enter_fchmodat2(struct syscall_trace_enter* ctx) {
  return on_sys_enter_chmod((int)ctx->args[0], (const char*)ctx->args[1],
                            (unsigned)ctx->args[2], (int)ctx->args[3]);
}

FUNC_INLINE int on_sys_exit_chmod(int ret, int event_type) {
  struct sys_enter_file* enter =
      bpf_map_lookup_elem(&sys_enter_file_array, &array_index);
  if (!enter || !enter->is_correct) return 1;
  enter->is_correct = 0;
  struct sys_chmod* sys_chmod = NULL;
  if (enter->filename[0] == '/') {
    /* Path is absoulute. */
    sys_chmod = bpf_ringbuf_reserve(&sys_chmod_rb, sizeof(*sys_chmod), 0);
    if (!sys_chmod) return 1;
    sys_chmod->filename_type = PATH_ABSOLUTE;
    if (bpf_probe_read_kernel_str(&sys_chmod->filename,
                                  sizeof(sys_chmod->filename),
                                  &enter->filename) < 0)
      enter->error |= ERROR_FILENAME;
  } else if (!(*enter->filename)) {
    /* Path is absoulute to the file descriptor. */
    struct sys_fchmod* sys_fchmod =
        bpf_ringbuf_reserve(&sys_chmod_rb, sizeof(*sys_fchmod), 0);
    if (!sys_fchmod) return 1;
    sys_chmod = (struct sys_chmod*)sys_fchmod;
    sys_chmod->filename_type = PATH_ABSOLUTE_FD;
    if (read_path_dentries_fd(enter->fd, &sys_fchmod->file, 0) < 0)
      enter->error |= ERROR_READ_FD;
  } else {
    /* Path is relative to file descriptor (can be AT_FDCWD). */
    struct sys_fchmodat* sys_fchmodat =
        bpf_ringbuf_reserve(&sys_chmod_rb, sizeof(*sys_fchmodat), 0);
    if (!sys_fchmodat) return 1;
    sys_chmod = &sys_fchmodat->sys_chmod;
    sys_chmod->filename_type = PATH_RELATIVE_FD;
    if (bpf_probe_read_kernel_str(&sys_chmod->filename,
                                  sizeof(sys_chmod->filename),
                                  &enter->filename) < 0)
      enter->error |= ERROR_FILENAME;
    if (read_path_dentries_fd(enter->fd, &sys_fchmodat->dir, 1) < 0)
      enter->error |= ERROR_READ_FD;
  }
  sys_chmod->error = enter->error;
  sys_chmod->mode = enter->mode;
  sys_chmod->flags = enter->flags;
  sys_chmod->event_type = event_type;
  sys_chmod->ret = ret;
  if (fill_task(&sys_chmod->task) < 0) sys_chmod->error |= ERROR_FILL_TASK;
  bpf_ringbuf_submit(sys_chmod, 0);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_chmod")
int tracepoint__syscalls__sys_exit_chmod(struct syscall_trace_exit* ctx) {
  return on_sys_exit_chmod((int)ctx->ret, SYS_CHMOD);
}

SEC("tracepoint/syscalls/sys_exit_fchmod")
int tracepoint__syscalls__sys_exit_fchmod(struct syscall_trace_exit* ctx) {
  return on_sys_exit_chmod((int)ctx->ret, SYS_FCHMOD);
}

SEC("tracepoint/syscalls/sys_exit_fchmodat")
int tracepoint__syscalls__sys_exit_fchmodat(struct syscall_trace_exit* ctx) {
  return on_sys_exit_chmod((int)ctx->ret, SYS_FCHMODAT);
}

SEC("tracepoint/syscalls/sys_exit_fchmodat2")
int tracepoint__syscalls__sys_exit_fchmodat2(struct syscall_trace_exit* ctx) {
  return on_sys_exit_chmod((int)ctx->ret, SYS_FCHMODAT2);
}

FUNC_INLINE int on_sys_enter_chown(int fd, const char* filename, uid_t uid,
                                   gid_t gid, int flags) {
  struct sys_enter_file* enter =
      bpf_map_lookup_elem(&sys_enter_file_array, &array_index);
  if (!enter) return 1;
  enter->error = 0;
  *enter->filename = 0;
  if (bpf_core_read_user_str(&enter->filename, sizeof(enter->filename),
                             filename) < 0)
    enter->error |= ERROR_FILENAME;
  enter->fd = fd;
  enter->flags = flags;
  enter->uid = uid;
  enter->gid = gid;
  enter->is_correct = 1;
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_chown")
int tracepoint__syscalls__sys_enter_chown(struct syscall_trace_enter* ctx) {
  return on_sys_enter_chown(AT_FDCWD, (const char*)ctx->args[0],
                            (uid_t)ctx->args[1], (gid_t)ctx->args[2], 0);
}

SEC("tracepoint/syscalls/sys_enter_fchown")
int tracepoint__syscalls__sys_enter_fchown(struct syscall_trace_enter* ctx) {
  return on_sys_enter_chown((int)ctx->args[0], NULL, (uid_t)ctx->args[1],
                            (gid_t)ctx->args[2], 0);
}

SEC("tracepoint/syscalls/sys_enter_fchownat")
int tracepoint__syscalls__sys_enter_fchownat(struct syscall_trace_enter* ctx) {
  return on_sys_enter_chown((int)ctx->args[0], (const char*)ctx->args[1],
                            (uid_t)ctx->args[2], (gid_t)ctx->args[3],
                            (int)ctx->args[4]);
}

FUNC_INLINE int on_sys_exit_chown(int ret, int event_type) {
  struct sys_enter_file* enter =
      bpf_map_lookup_elem(&sys_enter_file_array, &array_index);
  if (!enter || !enter->is_correct) return 1;
  enter->is_correct = 0;
  struct sys_chown* sys_chown = NULL;
  if (enter->filename[0] == '/') {
    /* Path is absoulute. */
    sys_chown = bpf_ringbuf_reserve(&sys_chown_rb, sizeof(*sys_chown), 0);
    if (!sys_chown) return 1;
    sys_chown->filename_type = PATH_ABSOLUTE;
    if (bpf_probe_read_kernel_str(&sys_chown->filename,
                                  sizeof(sys_chown->filename),
                                  &enter->filename) < 0)
      enter->error |= ERROR_FILENAME;
  } else if (!(*enter->filename)) {
    /* Path is absoulute to the file descriptor. */
    struct sys_fchown* sys_fchown =
        bpf_ringbuf_reserve(&sys_chown_rb, sizeof(*sys_fchown), 0);
    if (!sys_fchown) return 1;
    sys_chown = (struct sys_chown*)sys_fchown;
    sys_chown->filename_type = PATH_ABSOLUTE_FD;
    if (read_path_dentries_fd(enter->fd, &sys_fchown->file, 0) < 0)
      enter->error |= ERROR_READ_FD;
  } else {
    /* Path is relative to file descriptor (can be AT_FDCWD). */
    struct sys_fchownat* sys_fchownat =
        bpf_ringbuf_reserve(&sys_chown_rb, sizeof(*sys_fchownat), 0);
    if (!sys_fchownat) return 1;
    sys_chown = &sys_fchownat->sys_chown;
    sys_chown->filename_type = PATH_RELATIVE_FD;
    if (bpf_probe_read_kernel_str(&sys_chown->filename,
                                  sizeof(sys_chown->filename),
                                  &enter->filename) < 0)
      enter->error |= ERROR_FILENAME;
    if (read_path_dentries_fd(enter->fd, &sys_fchownat->dir, 1) < 0)
      enter->error |= ERROR_READ_FD;
  }
  sys_chown->uid = enter->uid;
  sys_chown->gid = enter->gid;
  sys_chown->error = enter->error;
  sys_chown->flags = enter->flags;
  sys_chown->event_type = event_type;
  sys_chown->ret = ret;
  if (fill_task(&sys_chown->task) < 0) sys_chown->error |= ERROR_FILL_TASK;
  bpf_ringbuf_submit(sys_chown, 0);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_chown")
int tracepoint__syscalls__sys_exit_chown(struct syscall_trace_exit* ctx) {
  return on_sys_exit_chown((int)ctx->ret, SYS_CHOWN);
}

SEC("tracepoint/syscalls/sys_exit_fchown")
int tracepoint__syscalls__sys_exit_fchown(struct syscall_trace_exit* ctx) {
  return on_sys_exit_chown((int)ctx->ret, SYS_FCHOWN);
}

SEC("tracepoint/syscalls/sys_exit_fchownat")
int tracepoint__syscalls__sys_exit_fchownat(struct syscall_trace_exit* ctx) {
  return on_sys_exit_chown((int)ctx->ret, SYS_FCHOWNAT);
}

FUNC_INLINE int on_sys_enter_rename(int oldfd, int newfd, const char* oldname,
                                    const char* newname, int flags) {
  struct sys_enter_file* enter =
      bpf_map_lookup_elem(&sys_enter_file_array, &array_index);
  if (!enter) return 1;
  enter->error = 0;
  if (bpf_core_read_user_str(&enter->filename, sizeof(enter->filename),
                             oldname) < 0)
    enter->error |= ERROR_FILENAME;
  if (bpf_core_read_user_str(&enter->newfilename, sizeof(enter->newfilename),
                             newname) < 0)
    enter->error |= ERROR_FILENAME;
  enter->fd = oldfd;
  enter->newfd = newfd;
  enter->flags = flags;
  enter->is_correct = 1;
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_rename")
int tracepoint__syscalls__sys_enter_rename(struct syscall_trace_enter* ctx) {
  return on_sys_enter_rename(AT_FDCWD, AT_FDCWD, (const char*)ctx->args[0],
                             (const char*)ctx->args[1], 0);
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int tracepoint__syscalls__sys_enter_renameat(struct syscall_trace_enter* ctx) {
  return on_sys_enter_rename((int)ctx->args[0], (int)ctx->args[2],
                             (const char*)ctx->args[1],
                             (const char*)ctx->args[3], 0);
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int tracepoint__syscalls__sys_enter_renameat2(struct syscall_trace_enter* ctx) {
  return on_sys_enter_rename((int)ctx->args[0], (int)ctx->args[2],
                             (const char*)ctx->args[1],
                             (const char*)ctx->args[3], (int)ctx->args[4]);
}

FUNC_INLINE int on_sys_exit_rename(int ret, int event_type) {
  struct sys_enter_file* enter =
      bpf_map_lookup_elem(&sys_enter_file_array, &array_index);
  if (!enter || !enter->is_correct) return 1;
  enter->is_correct = 0;
  struct sys_rename* sys_rename = NULL;
  if (enter->filename[0] == '/' && enter->newfilename[0] == '/') {
    /* Old and new paths are absoulute. */
    sys_rename = bpf_ringbuf_reserve(&sys_rename_rb, sizeof(*sys_rename), 0);
    if (!sys_rename) return 1;
    sys_rename->oldname_type = PATH_ABSOLUTE;
    sys_rename->newname_type = PATH_ABSOLUTE;
  } else if (enter->filename[0] != '/' && enter->newfilename[0] != '/') {
    /* New and old paths is relative to the file descriptors. */
    struct sys_renameat2* sys_renameat2 =
        bpf_ringbuf_reserve(&sys_rename_rb, sizeof(*sys_renameat2), 0);
    if (!sys_renameat2) return 1;
    sys_rename = &sys_renameat2->sys_rename;
    sys_rename->oldname_type = PATH_RELATIVE_FD;
    sys_rename->newname_type = PATH_RELATIVE_FD;
    if (read_path_dentries_fd(enter->fd, &sys_renameat2->olddir, 1) < 0)
      enter->error |= ERROR_READ_FD;
    if (read_path_dentries_fd(enter->newfd, &sys_renameat2->newdir, 1) < 0)
      enter->error |= ERROR_READ_FD;
  } else {
    /* Old or new path is relative to file descriptor and other is absolute. */
    struct sys_renameat* sys_renameat =
        bpf_ringbuf_reserve(&sys_rename_rb, sizeof(*sys_renameat), 0);
    if (!sys_renameat) return 1;
    sys_rename = &sys_renameat->sys_rename;
    int fd;
    if (enter->filename[0] == '/') {
      /* Old path is absoulute. New path is relative to the file descriptor. */
      sys_rename->oldname_type = PATH_ABSOLUTE;
      sys_rename->newname_type = PATH_RELATIVE_FD;
      fd = enter->newfd;
    } else {
      /* New path is absoulute. Old path is relative to the file descriptor. */
      sys_rename->oldname_type = PATH_RELATIVE_FD;
      sys_rename->newname_type = PATH_ABSOLUTE;
      fd = enter->fd;
    }
    if (read_path_dentries_fd(fd, &sys_renameat->dir, 1) < 0)
      enter->error |= ERROR_READ_FD;
  }
  if (bpf_probe_read_kernel_str(&sys_rename->oldname,
                                sizeof(sys_rename->oldname),
                                &enter->filename) < 0)
    enter->error |= ERROR_FILENAME;
  if (bpf_probe_read_kernel_str(&sys_rename->newname,
                                sizeof(sys_rename->newname),
                                &enter->newfilename) < 0)
    enter->error |= ERROR_FILENAME;
  sys_rename->error = enter->error;
  sys_rename->flags = enter->flags;
  sys_rename->event_type = event_type;
  sys_rename->ret = ret;
  if (fill_task(&sys_rename->task) < 0) sys_rename->error |= ERROR_FILL_TASK;
  bpf_ringbuf_submit(sys_rename, 0);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_rename")
int tracepoint__syscalls__sys_exit_rename(struct syscall_trace_exit* ctx) {
  return on_sys_exit_rename((int)ctx->ret, SYS_RENAME);
}

SEC("tracepoint/syscalls/sys_exit_renameat")
int tracepoint__syscalls__sys_exit_renameat(struct syscall_trace_exit* ctx) {
  return on_sys_exit_rename((int)ctx->ret, SYS_RENAMEAT);
}

SEC("tracepoint/syscalls/sys_exit_renameat2")
int tracepoint__syscalls__sys_exit_renameat2(struct syscall_trace_exit* ctx) {
  return on_sys_exit_rename((int)ctx->ret, SYS_RENAMEAT2);
}
