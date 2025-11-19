#include "logger/bpf/helpers.h"
#include "logger/bpf/file.h"

/* sys_enter_write tracepoint data. */
struct sys_enter_write {
#ifdef HAVE_RINGBUF_MAP_TYPE
  /* File name. */
  struct path_dentries file;
  /* The number of bytes to be written to the file. */
  size_t count;
  /* The position to write. */
  loff_t f_pos;
  /* File flags. file.f_flags. */
  unsigned f_flags;
  /* File mode. file.f_mode. */
  unsigned f_mode;
  int error;
  /*  Users and groups file type. */
  int file_type;
#else
  SYS_WRITE_HEADER;
#endif
  char buffer[SYS_WRITE_BUFFER_SIZE];
};

/* Temporary sys_enter_write data storage. */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct sys_enter_write);
} sys_enter_write_array SEC(".maps");

/*
 Map for sharing data between sys_enter_write and sys_exit_write tracepoints
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 128);
  __type(key, u64);
  __type(value, struct sys_enter_write);
} sys_enter_write_hash SEC(".maps");

/* Buffer for sending sys_write data to the userspace. */
struct {
#ifdef HAVE_RINGBUF_MAP_TYPE
  RINGBUF_BODY(NPROC * (sizeof(struct sys_write) + SYS_WRITE_BUFFER_SIZE));
#else
  PERF_EVENT_ARRAY_BODY;
#endif
} sys_write_buf SEC(".maps");

/* sys_enter_read tracepoint data. */
struct sys_enter_read {
  /* The number of bytes to be written to the file. */
  size_t count;
  /* The position to read. */
  loff_t f_pos;
  /* File flags. file.f_flags. */
  unsigned f_flags;
  /* File mode. file.f_mode. */
  unsigned f_mode;
  int error;
  /* File descriptor. */
  int fd;
};

/*
 Map for sharing data between sys_enter_read and sys_exit_read tracepoints
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 128);
  __type(key, u64);
  __type(value, struct sys_enter_read);
} sys_enter_read_hash SEC(".maps");

#ifndef HAVE_RINGBUF_MAP_TYPE
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct sys_read);
} sys_read_array SEC(".maps");
#endif

/* Buffer for sending sys_read data to the userspace. */
struct {
#ifdef HAVE_RINGBUF_MAP_TYPE
  RINGBUF_BODY(NPROC * sizeof(struct sys_read));
#else
  PERF_EVENT_ARRAY_BODY;
#endif
} sys_read_buf SEC(".maps");

#ifdef HAVE_RINGBUF_MAP_TYPE
struct sys_enter_unlink {
  /* File name. */
  char filename[PATH_SIZE];
  /* File descriptor for the sys_enter_unlinkat tracepoint. */
  int fd;
  /* AT_REMOVEDIR. */
  unsigned flags;
  int error;
};
#endif

/*
 * Map for sharing data between sys_enter_unlink and sys_exit_unlink,
 * sys_enter_unlinkat and sys_exit_unlinkat tracepoints.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 128);
  __type(key, u64);
#ifdef HAVE_RINGBUF_MAP_TYPE
  __type(value, struct sys_enter_unlink);
#else
  __type(value, struct sys_unlinkat);
#endif
} sys_enter_unlink_hash SEC(".maps");

/* Temporary data of sys_enter_unlink, sys_enter_unlinkat tracepoints. */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
#ifdef HAVE_RINGBUF_MAP_TYPE
  __type(value, struct sys_enter_unlink);
#else
  __type(value, struct sys_unlinkat);
#endif
} sys_enter_unlink_array SEC(".maps");

/* Buffer for sending sys_unlink data to the userspace. */
struct {
#ifdef HAVE_RINGBUF_MAP_TYPE
  RINGBUF_BODY(NPROC * sizeof(struct sys_unlinkat));
#else
  PERF_EVENT_ARRAY_BODY;
#endif
} sys_unlink_buf SEC(".maps");

struct sys_enter_chmod {
  /*
   * File descriptor for sys_enter_fchmod, sys_enter_fchmodat,
   * sys_enter_fchmodat2 tracepoints.
   */
  int fd;
  int error;
  /* AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW. */
  unsigned flags;
  unsigned mode;
  /* File name. */
  char filename[PATH_SIZE];
};

/*
 * Map for sharing data between
 * sys_enter_chmod and sys_exit_chmod,
 * sys_enter_fchmod and sys_exit_fchmod,
 * sys_enter_fchmodat and sys_exit_fchmodat,
 * sys_enter_fchmodat2 and sys_exit_fchmodat2
 * tracepoints.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 128);
  __type(key, u64);
  __type(value, struct sys_enter_chmod);
} sys_enter_chmod_hash SEC(".maps");

/*
 * Temporary data storage for sys_enter_chmod, sys_enter_fchmod,
 * sys_enter_fchmodat, sys_enter_fchmodat2 tracepoints.
 */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct sys_enter_chmod);
} sys_enter_chmod_array SEC(".maps");

#ifndef HAVE_RINGBUF_MAP_TYPE
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct sys_fchmod);
} sys_fchmod_array SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct sys_fchmodat);
} sys_fchmodat_array SEC(".maps");
#endif

/* Buffer for sending sys_chmod data to the userspace. */
struct {
#ifdef HAVE_RINGBUF_MAP_TYPE
  RINGBUF_BODY(NPROC * sizeof(struct sys_fchmodat));
#else
  PERF_EVENT_ARRAY_BODY;
#endif
} sys_chmod_buf SEC(".maps");

struct sys_enter_chown {
  /* File name. */
  char filename[PATH_SIZE];
  /* Target user ID. */
  uid_t uid;
  /* Target group ID. */
  gid_t gid;
  /* AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH. */
  unsigned flags;
  /* File descriptor. */
  int fd;
  int error;
};

/*
 * Map for sharing data between
 * sys_enter_chown and sys_exit_chown,
 * sys_enter_fchown and sys_exit_fchown,
 * sys_enter_lchown and sys_exit_lchown,
 * sys_enter_fchownat and sys_exit_fchownat
 * tracepoints.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 128);
  __type(key, u64);
  __type(value, struct sys_enter_chown);
} sys_enter_chown_hash SEC(".maps");

/*
 * Temporary data storage for sys_enter_chown, sys_enter_fchown,
 * sys_enter_lchown, sys_enter_fchownat  tracepoints.
 */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct sys_enter_chown);
} sys_enter_chown_array SEC(".maps");

#ifndef HAVE_RINGBUF_MAP_TYPE
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct sys_fchown);
} sys_fchown_array SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct sys_fchownat);
} sys_fchownat_array SEC(".maps");
#endif

/* Buffer for sending sys_chown data to the userspace. */
struct {
#ifdef HAVE_RINGBUF_MAP_TYPE
  RINGBUF_BODY(NPROC * sizeof(struct sys_fchownat));
#else
  PERF_EVENT_ARRAY_BODY;
#endif
} sys_chown_buf SEC(".maps");

#ifdef HAVE_RINGBUF_MAP_TYPE
struct sys_enter_rename {
  /* Old file name. */
  char oldname[PATH_SIZE];
  /* New file name. */
  char newname[PATH_SIZE];
  int error;
  /* RENAME_EXCHANGE, RENAME_NOREPLACE, RENAME_WHITEOUT. */
  unsigned flags;
  /* Old directory file descriptor. */
  int oldfd;
  /* New directory file descriptor. */
  int newfd;
};
#endif

/*
 * Map for sharing data between
 * sys_enter_rename and sys_exit_rename,
 * sys_enter_renameat and sys_exit_renameat,
 * sys_enter_renameat2 and sys_exit_renameat2
 * tracepoints.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 128);
  __type(key, u64);
#ifdef HAVE_RINGBUF_MAP_TYPE
  __type(value, struct sys_enter_rename);
#else
  __type(value, struct sys_renameat2);
#endif
} sys_enter_rename_hash SEC(".maps");

/*
 * Temporary data storage for sys_enter_rename, sys_enter_renameat,
 * sys_enter_renameat2 tracepoints.
 */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
#ifdef HAVE_RINGBUF_MAP_TYPE
  __type(value, struct sys_enter_rename);
#else
  __type(value, struct sys_renameat2);
#endif
} sys_enter_rename_array SEC(".maps");

/* Buffer for sending data to the userspace. */
struct {
#ifdef HAVE_RINGBUF_MAP_TYPE
  RINGBUF_BODY(NPROC * sizeof(struct sys_renameat2));
#else
  PERF_EVENT_ARRAY_BODY;
#endif
} sys_rename_buf SEC(".maps");

#define AT_EMPTY_PATH 0x1000

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

/* From userspace. */
pid_t logger_pid;

#define is_logger_pid() ((pid_t)bpf_get_current_pid_tgid() == logger_pid)

FUNC_INLINE int on_sys_enter_write(int fd, const char* buffer, size_t count) {
  const int array_index = 0;
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  if ((pid_t)hash_id == logger_pid) return 0;
  struct sys_enter_write* enter =
      bpf_map_lookup_elem(&sys_enter_write_array, &array_index);
  if (!enter) return 1;
  enter->error = 0;
  enter->count = count;
  const struct file* file;
  if (get_file_from_fd(fd, &file)) return 1;
  umode_t i_mode = BPF_CORE_READ(file, f_inode, i_mode);
  if (!S_ISREG(i_mode)) return 0;
  if (read_path_dentries_fd(fd, &enter->file, 0) < 0)
    enter->error |= ERROR_READ_FD;
  enter->file_type = is_file_with_buffer(&enter->file);
  if (enter->file_type &&
      bpf_probe_read_user_str(&enter->buffer,
                              (unsigned)count & (sizeof(enter->buffer) - 1),
                              buffer) < 0)
    enter->error |= ERROR_FILL_BUFFER;
  enter->f_pos = BPF_CORE_READ(file, f_pos);
  enter->f_flags = BPF_CORE_READ(file, f_flags);
  enter->f_mode = BPF_CORE_READ(file, f_mode);
#ifndef HAVE_RINGBUF_MAP_TYPE
  if (fill_task(&enter->task) < 0) enter->error |= ERROR_FILL_TASK;
#endif
  bpf_map_update_elem(&sys_enter_write_hash, &hash_id, enter, BPF_ANY);
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
                            &enter->file) < 0) {                       \
    sys_write->error |= ERROR_COPY_ENTER;                              \
  }

#ifdef HAVE_RINGBUF_MAP_TYPE
FUNC_INLINE int on_sys_exit_write(int ret, int event_type) {
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  if ((pid_t)hash_id == logger_pid) return 0;
  const struct sys_enter_write* enter =
      bpf_map_lookup_elem(&sys_enter_write_hash, &hash_id);
  if (!enter) return 1;
  unsigned buffer_size = 0;
  size_t reserved_size = sizeof(struct sys_write);
  if (enter->file_type != FILE_TYPE_OTHER) {
    reserved_size += SYS_WRITE_BUFFER_SIZE;
    if (ret > 0)
      buffer_size = (unsigned)(ret + 1) & (SYS_WRITE_BUFFER_SIZE - 1);
    else
      buffer_size = SYS_WRITE_BUFFER_SIZE;
  }
  struct sys_write* sys_write =
      bpf_ringbuf_reserve(&sys_write_buf, reserved_size, 0);
  if (!sys_write) goto clean;
  copy_sys_enter_write(sys_write, enter);
  if (buffer_size && bpf_probe_read_kernel(&sys_write->buffer, buffer_size,
                                           &enter->buffer) < 0) {
    sys_write->error |= ERROR_COPY_BUFFER;
  }
  if (fill_task(&sys_write->task) < 0) sys_write->error |= ERROR_FILL_TASK;
  sys_write->ret = ret;
  sys_write->event_type = event_type;
  bpf_ringbuf_submit(sys_write, 0);
clean:
  bpf_map_delete_elem(&sys_enter_write_hash, &hash_id);
  return 0;
}

#else
FUNC_INLINE int on_sys_exit_write(struct syscall_trace_exit* ctx,
                                  int event_type) {
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  if ((pid_t)hash_id == logger_pid) return 0;
  struct sys_enter_write* enter =
      bpf_map_lookup_elem(&sys_enter_write_hash, &hash_id);
  if (!enter) return 1;
  size_t reserved_size = sizeof(struct sys_write);
  int ret = (int)ctx->ret;
  if (enter->file_type != FILE_TYPE_OTHER) {
    if (ret > 0)
      reserved_size += (unsigned)(ret + 1) & (SYS_WRITE_BUFFER_SIZE - 1);
    else
      reserved_size += SYS_WRITE_BUFFER_SIZE;
  }
  enter->ret = ret;
  enter->event_type = event_type;
  bpf_perf_event_output(ctx, &sys_write_buf, BPF_F_CURRENT_CPU, enter,
                        reserved_size);
  bpf_map_delete_elem(&sys_enter_write_hash, &hash_id);
  return 0;
}
#endif

SEC("tracepoint/syscalls/sys_exit_write")
int tracepoint__syscalls__sys_exit_write(struct syscall_trace_exit* ctx) {
#ifdef HAVE_RINGBUF_MAP_TYPE
  return on_sys_exit_write((int)ctx->ret, SYS_WRITE);
#else
  return on_sys_exit_write(ctx, SYS_WRITE);
#endif
}

FUNC_INLINE int on_sys_enter_read(int fd, size_t count) {
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  if ((pid_t)hash_id == logger_pid) return 0;
  struct sys_enter_read enter;
  enter.error = 0;
  const struct file* file;
  if (get_file_from_fd(fd, &file)) return 1;
  umode_t i_mode = BPF_CORE_READ(file, f_inode, i_mode);
  if (!S_ISREG(i_mode)) return 0;
  enter.fd = fd;
  enter.count = count;
  enter.f_pos = BPF_CORE_READ(file, f_pos);
  enter.f_flags = BPF_CORE_READ(file, f_flags);
  enter.f_mode = BPF_CORE_READ(file, f_mode);
  bpf_map_update_elem(&sys_enter_read_hash, &hash_id, &enter, BPF_ANY);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint__syscalls__sys_enter_read(struct syscall_trace_enter* ctx) {
  return on_sys_enter_read((int)ctx->args[0], (size_t)ctx->args[2]);
}

#ifdef HAVE_RINGBUF_MAP_TYPE
FUNC_INLINE int on_sys_exit_read(int ret, int event_type) {
#else
FUNC_INLINE int on_sys_exit_read(struct syscall_trace_exit* ctx,
                                 int event_type) {
#endif
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  if ((pid_t)hash_id == logger_pid) return 0;
  struct sys_enter_read* enter =
      bpf_map_lookup_elem(&sys_enter_read_hash, &hash_id);
  if (!enter) return 1;
#ifdef HAVE_RINGBUF_MAP_TYPE
  struct sys_read* sys_read =
      bpf_ringbuf_reserve(&sys_read_buf, sizeof(*sys_read), 0);
#else
  const int array_index = 0;
  const int ret = (int)ctx->ret;
  struct sys_read* sys_read =
      bpf_map_lookup_elem(&sys_read_array, &array_index);
#endif
  if (!sys_read) goto clean;
  sys_read->error = enter->error;
  sys_read->count = enter->count;
  sys_read->f_pos = enter->f_pos;
  sys_read->f_flags = enter->f_flags;
  sys_read->f_mode = enter->f_mode;
  if (read_path_dentries_fd(enter->fd, &sys_read->file, 0) < 0)
    sys_read->error |= ERROR_READ_FD;
  sys_read->ret = ret;
  sys_read->event_type = event_type;
  if (fill_task(&sys_read->task) < 0) sys_read->error |= ERROR_FILL_TASK;
#ifdef HAVE_RINGBUF_MAP_TYPE
  bpf_ringbuf_submit(sys_read, 0);
#else
  bpf_perf_event_output(ctx, &sys_read_buf, BPF_F_CURRENT_CPU, sys_read,
                        sizeof(*sys_read));
#endif
clean:
  bpf_map_delete_elem(&sys_enter_read_hash, &hash_id);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int tracepoint__syscalls__sys_exit_read(struct syscall_trace_exit* ctx) {
#ifdef HAVE_RINGBUF_MAP_TYPE
  return on_sys_exit_read((int)ctx->ret, SYS_READ);
#else
  return on_sys_exit_read(ctx, SYS_READ);
#endif
}

#ifdef HAVE_RINGBUF_MAP_TYPE
FUNC_INLINE int on_sys_enter_unlink(int fd, const char* filename,
                                    unsigned flags) {
  const int array_index = 0;
  struct sys_enter_unlink* enter =
      bpf_map_lookup_elem(&sys_enter_unlink_array, &array_index);
  if (!enter) return 1;
  enter->error = 0;
  if (bpf_probe_read_user_str(&enter->filename, sizeof(enter->filename),
                              filename) < 0)
    enter->error |= ERROR_FILENAME;
  enter->fd = fd;
  enter->flags = flags;
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&sys_enter_unlink_hash, &hash_id, enter, BPF_ANY);
  return 0;
}

FUNC_INLINE int on_sys_exit_unlink(int ret, int event_type) {
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  struct sys_enter_unlink* enter =
      bpf_map_lookup_elem(&sys_enter_unlink_hash, &hash_id);
  if (!enter) return 1;
  struct sys_unlink* sys_unlink;
  if (enter->filename[0] == '/') {
    sys_unlink = bpf_ringbuf_reserve(&sys_unlink_buf, sizeof(*sys_unlink), 0);
    if (!sys_unlink) goto clean;
    sys_unlink->filename_type = PATH_ABSOLUTE;
  } else {
    struct sys_unlinkat* sys_unlinkat =
        bpf_ringbuf_reserve(&sys_unlink_buf, sizeof(*sys_unlinkat), 0);
    if (!sys_unlinkat) goto clean;
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
clean:
  bpf_map_delete_elem(&sys_enter_unlink_hash, &hash_id);
  return 0;
}

#else
FUNC_INLINE int on_sys_enter_unlink(int fd, const char* filename,
                                    unsigned flags) {
  const int array_index = 0;
  struct sys_unlinkat* sys_unlinkat =
      bpf_map_lookup_elem(&sys_enter_unlink_array, &array_index);
  if (!sys_unlinkat) return 1;
  struct sys_unlink* sys_unlink = &sys_unlinkat->sys_unlink;
  sys_unlink->error = 0;
  if (bpf_probe_read_user_str(&sys_unlink->filename,
                              sizeof(sys_unlink->filename), filename) < 0)
    sys_unlink->error |= ERROR_FILENAME;
  sys_unlink->flags = flags;
  if (sys_unlink->filename[0] == '/') {
    sys_unlink->filename_type = PATH_ABSOLUTE;
  } else {
    sys_unlink->filename_type = PATH_RELATIVE_FD;
    if (read_path_dentries_fd(fd, &sys_unlinkat->dir, 1) < 0)
      sys_unlink->error |= ERROR_READ_FD;
  }
  if (fill_task(&sys_unlink->task) < 0) sys_unlink->error |= ERROR_FILL_TASK;
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&sys_enter_unlink_hash, &hash_id, sys_unlinkat, BPF_ANY);
  return 0;
}

FUNC_INLINE int on_sys_exit_unlink(struct syscall_trace_exit* ctx,
                                   int event_type) {
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  struct sys_unlinkat* sys_unlinkat =
      bpf_map_lookup_elem(&sys_enter_unlink_hash, &hash_id);
  if (!sys_unlinkat) return 1;
  struct sys_unlink* sys_unlink = &sys_unlinkat->sys_unlink;
  sys_unlink->event_type = event_type;
  sys_unlink->ret = (int)ctx->ret;
  size_t data_size = sizeof(*sys_unlink);
  if (sys_unlink->filename_type == PATH_RELATIVE_FD)
    data_size = sizeof(*sys_unlinkat);
  bpf_perf_event_output(ctx, &sys_unlink_buf, BPF_F_CURRENT_CPU, sys_unlinkat,
                        data_size);
  bpf_map_delete_elem(&sys_enter_unlink_hash, &hash_id);
  return 0;
}
#endif

SEC("tracepoint/syscalls/sys_enter_unlink")
int tracepoint__syscalls__sys_enter_unlink(struct syscall_trace_enter* ctx) {
  return on_sys_enter_unlink(AT_FDCWD, (const char*)ctx->args[0], 0);
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tracepoint__syscalls__sys_enter_unlinkat(struct syscall_trace_enter* ctx) {
  return on_sys_enter_unlink((int)ctx->args[0], (const char*)ctx->args[1],
                             (unsigned)ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_exit_unlink")
int tracepoint__syscalls__sys_exit_unlink(struct syscall_trace_exit* ctx) {
#ifdef HAVE_RINGBUF_MAP_TYPE
  return on_sys_exit_unlink((int)ctx->ret, SYS_UNLINK);
#else
  return on_sys_exit_unlink(ctx, SYS_UNLINK);
#endif
}

SEC("tracepoint/syscalls/sys_exit_unlinkat")
int tracepoint__syscalls__sys_exit_unlinkat(struct syscall_trace_exit* ctx) {
#ifdef HAVE_RINGBUF_MAP_TYPE
  return on_sys_exit_unlink((int)ctx->ret, SYS_UNLINKAT);
#else
  return on_sys_exit_unlink(ctx, SYS_UNLINKAT);
#endif
}

/*
 * Returns 1 if fd is the directory. */
FUNC_INLINE int is_dir_fd(int fd) {
  const struct file* file;
  if (get_file_from_fd(fd, &file)) return 1;
  umode_t i_mode = BPF_CORE_READ(file, f_inode, i_mode);
  if (S_ISDIR(i_mode)) return 1;
  // if (S_ISREG(i_mode)) return 0;
  else
    return 0;
}

FUNC_INLINE int on_sys_enter_chmod(int fd, const char* filename, unsigned mode,
                                   unsigned flags) {
  const int array_index = 0;
  struct sys_enter_chmod* enter =
      bpf_map_lookup_elem(&sys_enter_chmod_array, &array_index);
  if (!enter) return 1;
  enter->error = 0;
  *enter->filename = 0;
  if (!(flags & AT_EMPTY_PATH) &&
      bpf_probe_read_user_str(&enter->filename, sizeof(enter->filename),
                              filename) < 0) {
    enter->error |= ERROR_FILENAME;
  }
  enter->fd = fd;
  enter->flags = flags;
  enter->mode = mode;
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&sys_enter_chmod_hash, &hash_id, enter, BPF_ANY);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_chmod")
int tracepoint__syscalls__sys_enter_chmod(struct syscall_trace_enter* ctx) {
  return on_sys_enter_chmod(AT_FDCWD, (const char*)ctx->args[0],
                            (unsigned)ctx->args[1], 0);
}

SEC("tracepoint/syscalls/sys_enter_fchmod")
int tracepoint__syscalls__sys_enter_fchmod(struct syscall_trace_enter* ctx) {
  return on_sys_enter_chmod((int)ctx->args[0], NULL, (unsigned)ctx->args[1],
                            AT_EMPTY_PATH);
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int tracepoint__syscalls__sys_enter_fchmodat(struct syscall_trace_enter* ctx) {
  return on_sys_enter_chmod((int)ctx->args[0], (const char*)ctx->args[1],
                            (unsigned)ctx->args[2], 0);
}

SEC("tracepoint/syscalls/sys_enter_fchmodat2")
int tracepoint__syscalls__sys_enter_fchmodat2(struct syscall_trace_enter* ctx) {
  return on_sys_enter_chmod((int)ctx->args[0], (const char*)ctx->args[1],
                            (unsigned)ctx->args[2], (unsigned)ctx->args[3]);
}

#ifdef HAVE_RINGBUF_MAP_TYPE
FUNC_INLINE int on_sys_exit_chmod(int ret, int event_type) {
#else
FUNC_INLINE int on_sys_exit_chmod(struct syscall_trace_exit* ctx,
                                  int event_type) {
  const int array_index = 0;
  int ret = (int)ctx->ret;
  size_t data_size;
#endif
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  struct sys_enter_chmod* enter =
      bpf_map_lookup_elem(&sys_enter_chmod_hash, &hash_id);
  if (!enter) return 1;
  struct sys_chmod* sys_chmod = NULL;
  if (enter->filename[0] == '/') {
    /* Path is absoulute. */
#ifdef HAVE_RINGBUF_MAP_TYPE
    sys_chmod = bpf_ringbuf_reserve(&sys_chmod_buf, sizeof(*sys_chmod), 0);
#else
    sys_chmod = (struct sys_chmod*)bpf_map_lookup_elem(&sys_fchmodat_array,
                                                       &array_index);
    data_size = sizeof(*sys_chmod);
#endif
    if (!sys_chmod) goto clean;
    sys_chmod->filename_type = PATH_ABSOLUTE;
    if (bpf_probe_read_kernel_str(&sys_chmod->filename,
                                  sizeof(sys_chmod->filename),
                                  &enter->filename) < 0)
      enter->error |= ERROR_FILENAME;
  } else if (!(*enter->filename)) {
    /* Path is absoulute to the file descriptor. */
#ifdef HAVE_RINGBUF_MAP_TYPE
    struct sys_fchmod* sys_fchmod =
        bpf_ringbuf_reserve(&sys_chmod_buf, sizeof(*sys_fchmod), 0);
#else
    struct sys_fchmod* sys_fchmod =
        bpf_map_lookup_elem(&sys_fchmod_array, &array_index);
    data_size = sizeof(*sys_fchmod);
#endif
    if (!sys_fchmod) goto clean;
    sys_chmod = (struct sys_chmod*)sys_fchmod;
    sys_chmod->filename_type = PATH_ABSOLUTE_FD;
    if (read_path_dentries_fd(enter->fd, &sys_fchmod->file,
                              is_dir_fd(enter->fd)) < 0)
      enter->error |= ERROR_READ_FD;
  } else {
    /* Path is relative to file descriptor (can be AT_FDCWD). */
#ifdef HAVE_RINGBUF_MAP_TYPE
    struct sys_fchmodat* sys_fchmodat =
        bpf_ringbuf_reserve(&sys_chmod_buf, sizeof(*sys_fchmodat), 0);
#else
    struct sys_fchmodat* sys_fchmodat =
        bpf_map_lookup_elem(&sys_fchmodat_array, &array_index);
    data_size = sizeof(*sys_fchmodat);
#endif
    if (!sys_fchmodat) goto clean;
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
#ifdef HAVE_RINGBUF_MAP_TYPE
  bpf_ringbuf_submit(sys_chmod, 0);
#else
  bpf_perf_event_output(ctx, &sys_chmod_buf, BPF_F_CURRENT_CPU, sys_chmod,
                        data_size);
#endif
clean:
  bpf_map_delete_elem(&sys_enter_chmod_hash, &hash_id);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_chmod")
int tracepoint__syscalls__sys_exit_chmod(struct syscall_trace_exit* ctx) {
#ifdef HAVE_RINGBUF_MAP_TYPE
  return on_sys_exit_chmod((int)ctx->ret, SYS_CHMOD);
#else
  return on_sys_exit_chmod(ctx, SYS_CHMOD);
#endif
}

SEC("tracepoint/syscalls/sys_exit_fchmod")
int tracepoint__syscalls__sys_exit_fchmod(struct syscall_trace_exit* ctx) {
#ifdef HAVE_RINGBUF_MAP_TYPE
  return on_sys_exit_chmod((int)ctx->ret, SYS_FCHMOD);
#else
  return on_sys_exit_chmod(ctx, SYS_FCHMOD);
#endif
}

SEC("tracepoint/syscalls/sys_exit_fchmodat")
int tracepoint__syscalls__sys_exit_fchmodat(struct syscall_trace_exit* ctx) {
#ifdef HAVE_RINGBUF_MAP_TYPE
  return on_sys_exit_chmod((int)ctx->ret, SYS_FCHMODAT);
#else
  return on_sys_exit_chmod(ctx, SYS_FCHMODAT);
#endif
}

SEC("tracepoint/syscalls/sys_exit_fchmodat2")
int tracepoint__syscalls__sys_exit_fchmodat2(struct syscall_trace_exit* ctx) {
#ifdef HAVE_RINGBUF_MAP_TYPE
  return on_sys_exit_chmod((int)ctx->ret, SYS_FCHMODAT2);
#else
  return on_sys_exit_chmod(ctx, SYS_FCHMODAT2);
#endif
}

FUNC_INLINE int on_sys_enter_chown(int fd, const char* filename, uid_t uid,
                                   gid_t gid, unsigned flags) {
  const int array_index = 0;
  struct sys_enter_chown* enter =
      bpf_map_lookup_elem(&sys_enter_chown_array, &array_index);
  if (!enter) return 1;
  enter->error = 0;
  *enter->filename = 0;
  if (!(flags & AT_EMPTY_PATH) &&
      bpf_probe_read_user_str(&enter->filename, sizeof(enter->filename),
                              filename) < 0)
    enter->error |= ERROR_FILENAME;
  enter->fd = fd;
  enter->flags = flags;
  enter->uid = uid;
  enter->gid = gid;
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&sys_enter_chown_hash, &hash_id, enter, BPF_ANY);
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
                            (unsigned)ctx->args[4]);
}

#ifdef HAVE_RINGBUF_MAP_TYPE
FUNC_INLINE int on_sys_exit_chown(int ret, int event_type) {
#else
FUNC_INLINE int on_sys_exit_chown(struct syscall_trace_exit* ctx,
                                  int event_type) {
  const int array_index = 0;
  size_t data_size;
  const int ret = (int)ctx->ret;
#endif
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  struct sys_enter_chown* enter =
      bpf_map_lookup_elem(&sys_enter_chown_hash, &hash_id);
  if (!enter) return 1;
  struct sys_chown* sys_chown = NULL;
  if (enter->filename[0] == '/') {
    /* Path is absoulute. */
#ifdef HAVE_RINGBUF_MAP_TYPE
    sys_chown = bpf_ringbuf_reserve(&sys_chown_buf, sizeof(*sys_chown), 0);
#else
    sys_chown = (struct sys_chown*)bpf_map_lookup_elem(&sys_fchownat_array,
                                                       &array_index);
    data_size = sizeof(*sys_chown);
#endif
    if (!sys_chown) goto clean;
    sys_chown->filename_type = PATH_ABSOLUTE;
    if (bpf_probe_read_kernel_str(&sys_chown->filename,
                                  sizeof(sys_chown->filename),
                                  &enter->filename) < 0)
      enter->error |= ERROR_FILENAME;
  } else if (!(*enter->filename)) {
    /* Path is absoulute to the file descriptor. */
    struct sys_fchown* sys_fchown =
#ifdef HAVE_RINGBUF_MAP_TYPE
        bpf_ringbuf_reserve(&sys_chown_buf, sizeof(*sys_fchown), 0);
#else
        bpf_map_lookup_elem(&sys_fchown_array, &array_index);
    data_size = sizeof(*sys_fchown);
#endif
    if (!sys_fchown) goto clean;
    sys_chown = (struct sys_chown*)sys_fchown;
    sys_chown->filename_type = PATH_ABSOLUTE_FD;
    if (read_path_dentries_fd(enter->fd, &sys_fchown->file,
                              is_dir_fd(enter->fd)) < 0)
      enter->error |= ERROR_READ_FD;
  } else {
    /* Path is relative to file descriptor (can be AT_FDCWD). */
    struct sys_fchownat* sys_fchownat =
#ifdef HAVE_RINGBUF_MAP_TYPE
        bpf_ringbuf_reserve(&sys_chown_buf, sizeof(*sys_fchownat), 0);
#else
        bpf_map_lookup_elem(&sys_fchownat_array, &array_index);
    data_size = sizeof(*sys_fchownat);
#endif
    if (!sys_fchownat) goto clean;
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
#ifdef HAVE_RINGBUF_MAP_TYPE
  bpf_ringbuf_submit(sys_chown, 0);
#else
  bpf_perf_event_output(ctx, &sys_chown_buf, BPF_F_CURRENT_CPU, sys_chown,
                        data_size);
#endif
clean:
  bpf_map_delete_elem(&sys_enter_chown_hash, &hash_id);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_chown")
int tracepoint__syscalls__sys_exit_chown(struct syscall_trace_exit* ctx) {
#ifdef HAVE_RINGBUF_MAP_TYPE
  return on_sys_exit_chown((int)ctx->ret, SYS_CHOWN);
#else
  return on_sys_exit_chown(ctx, SYS_CHOWN);
#endif
}

SEC("tracepoint/syscalls/sys_exit_fchown")
int tracepoint__syscalls__sys_exit_fchown(struct syscall_trace_exit* ctx) {
#ifdef HAVE_RINGBUF_MAP_TYPE
  return on_sys_exit_chown((int)ctx->ret, SYS_FCHOWN);
#else
  return on_sys_exit_chown(ctx, SYS_FCHOWN);
#endif
}

SEC("tracepoint/syscalls/sys_exit_fchownat")
int tracepoint__syscalls__sys_exit_fchownat(struct syscall_trace_exit* ctx) {
#ifdef HAVE_RINGBUF_MAP_TYPE
  return on_sys_exit_chown((int)ctx->ret, SYS_FCHOWNAT);
#else
  return on_sys_exit_chown(ctx, SYS_FCHOWNAT);
#endif
}

#define IS_SYS_RENAME(oldname, newname) \
  ((oldname)[0] == '/' && (newname)[0] == '/')
#define IS_SYS_RENAMEAT2(oldname, newname, oldfd, newfd) \
  ((oldname)[0] != '/' && (newname)[0] != '/' && (oldfd) != (newfd))

FUNC_INLINE int fill_sys_rename(struct sys_rename* sys_rename) {
  sys_rename->oldname_type = PATH_ABSOLUTE;
  sys_rename->newname_type = PATH_ABSOLUTE;
  return 0;
}

FUNC_INLINE int fill_sys_renameat2(struct sys_renameat2* sys_renameat2,
                                   int oldfd, int newfd) {
  struct sys_rename* sys_rename = &sys_renameat2->sys_rename;
  sys_rename->oldname_type = PATH_RELATIVE_FD;
  sys_rename->newname_type = PATH_RELATIVE_FD;
  if (read_path_dentries_fd(oldfd, &sys_renameat2->olddir, 1) < 0)
    sys_rename->error |= ERROR_READ_FD;
  if (read_path_dentries_fd(newfd, &sys_renameat2->newdir, 1) < 0)
    sys_rename->error |= ERROR_READ_FD;
  return 0;
};

FUNC_INLINE int fill_sys_renameat(struct sys_renameat* sys_renameat, int oldfd,
                                  int newfd) {
  int fd = oldfd;
  struct sys_rename* sys_rename = &sys_renameat->sys_rename;
  if (oldfd == newfd) {
    sys_rename->oldname_type = PATH_RELATIVE_FD;
    sys_rename->newname_type = PATH_RELATIVE_FD;
  } else if (sys_rename->oldname[0] == '/') {
    /* Old path is absoulute. New path is relative to the file descriptor. */
    sys_rename->oldname_type = PATH_ABSOLUTE;
    sys_rename->newname_type = PATH_RELATIVE_FD;
    fd = newfd;
  } else {
    /* New path is absoulute. Old path is relative to the file descriptor. */
    sys_rename->oldname_type = PATH_RELATIVE_FD;
    sys_rename->newname_type = PATH_ABSOLUTE;
  }
  if (read_path_dentries_fd(fd, &sys_renameat->dir, 1) < 0)
    sys_rename->error |= ERROR_READ_FD;
  return 0;
}

#ifdef HAVE_RINGBUF_MAP_TYPE
FUNC_INLINE int on_sys_enter_rename(int oldfd, int newfd, const char* oldname,
                                    const char* newname, unsigned flags) {
  const int array_index = 0;
  struct sys_enter_rename* enter =
      bpf_map_lookup_elem(&sys_enter_rename_array, &array_index);
  if (!enter) return 1;
  enter->error = 0;
  if (bpf_probe_read_user_str(&enter->oldname, sizeof(enter->oldname),
                              oldname) < 0)
    enter->error |= ERROR_FILENAME;
  if (bpf_probe_read_user_str(&enter->newname, sizeof(enter->newname),
                              newname) < 0)
    enter->error |= ERROR_FILENAME;
  enter->oldfd = oldfd;
  enter->newfd = newfd;
  enter->flags = flags;
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&sys_enter_rename_hash, &hash_id, enter, BPF_ANY);
  return 0;
}

FUNC_INLINE int on_sys_exit_rename(int ret, int event_type) {
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  struct sys_enter_rename* enter =
      bpf_map_lookup_elem(&sys_enter_rename_hash, &hash_id);
  if (!enter) return 1;
  struct sys_rename* sys_rename = NULL;
  if (IS_SYS_RENAME(enter->oldname, enter->newname)) {
    /* Old and new paths are absoulute. */
    sys_rename = bpf_ringbuf_reserve(&sys_rename_buf, sizeof(*sys_rename), 0);
    if (!sys_rename) goto clean;
    fill_sys_rename(sys_rename);
  } else if (IS_SYS_RENAMEAT2(enter->oldname, enter->newname, enter->oldfd,
                              enter->newfd)) {
    /* New and old paths is relative to the file descriptors. */
    struct sys_renameat2* sys_renameat2 =
        bpf_ringbuf_reserve(&sys_rename_buf, sizeof(*sys_renameat2), 0);
    if (!sys_renameat2) goto clean;
    sys_rename = &sys_renameat2->sys_rename;
    fill_sys_renameat2(sys_renameat2, enter->oldfd, enter->newfd);
  } else {
    /* Old or new path is relative to file descriptor and other is absolute. */
    struct sys_renameat* sys_renameat =
        bpf_ringbuf_reserve(&sys_rename_buf, sizeof(*sys_renameat), 0);
    if (!sys_renameat) goto clean;
    sys_rename = &sys_renameat->sys_rename;
    fill_sys_renameat(sys_renameat, enter->oldfd, enter->newfd);
  }
  if (bpf_probe_read_kernel_str(&sys_rename->oldname,
                                sizeof(sys_rename->oldname),
                                &enter->oldname) < 0)
    enter->error |= ERROR_FILENAME;
  if (bpf_probe_read_kernel_str(&sys_rename->newname,
                                sizeof(sys_rename->newname),
                                &enter->newname) < 0)
    enter->error |= ERROR_FILENAME;
  sys_rename->samedir = enter->oldfd == enter->newfd;
  sys_rename->error = enter->error;
  sys_rename->flags = enter->flags;
  sys_rename->event_type = event_type;
  sys_rename->ret = ret;
  if (fill_task(&sys_rename->task) < 0) sys_rename->error |= ERROR_FILL_TASK;
  bpf_ringbuf_submit(sys_rename, 0);
clean:
  bpf_map_delete_elem(&sys_enter_rename_hash, &hash_id);
  return 0;
}

#else
FUNC_INLINE int on_sys_enter_rename(int oldfd, int newfd, const char* oldname,
                                    const char* newname, unsigned flags) {
  const int array_index = 0;
  struct sys_renameat2* sys_renameat2 =
      bpf_map_lookup_elem(&sys_enter_rename_array, &array_index);
  if (!sys_renameat2) return 1;
  struct sys_rename* sys_rename = &sys_renameat2->sys_rename;
  sys_rename->error = 0;
  if (bpf_probe_read_user_str(&sys_rename->oldname, sizeof(sys_rename->oldname),
                              oldname) < 0)
    sys_rename->error |= ERROR_FILENAME;
  if (bpf_probe_read_user_str(&sys_rename->newname, sizeof(sys_rename->newname),
                              newname) < 0)
    sys_rename->error |= ERROR_FILENAME;
  sys_rename->flags = flags;

  if (IS_SYS_RENAME(sys_rename->oldname, sys_rename->newname)) {
    /* Old and new paths are absoulute. */
    fill_sys_rename(sys_rename);
  } else if (IS_SYS_RENAMEAT2(sys_rename->oldname, sys_rename->newname, oldfd,
                              newfd)) {
    fill_sys_renameat2(sys_renameat2, oldfd, newfd);
    /* New and old paths is relative to the file descriptors. */
  } else {
    /* Old or new path is relative to file descriptor and other is absolute. */
    fill_sys_renameat((struct sys_renameat*)sys_renameat2, oldfd, newfd);
  }
  sys_rename->samedir = oldfd == newfd;
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&sys_enter_rename_hash, &hash_id, sys_renameat2, BPF_ANY);
  return 0;
}

FUNC_INLINE int on_sys_exit_rename(struct syscall_trace_exit* ctx,
                                   int event_type) {
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  struct sys_renameat2* sys_renameat2 =
      bpf_map_lookup_elem(&sys_enter_rename_hash, &hash_id);
  if (!sys_renameat2) return 1;
  struct sys_rename* sys_rename = &sys_renameat2->sys_rename;
  sys_rename->ret = (int)ctx->ret;
  sys_rename->event_type = event_type;
  size_t data_size;
  if (IS_SYS_RENAME(sys_rename->oldname, sys_rename->newname)) {
    data_size = sizeof(struct sys_rename);
  } else if (sys_rename->oldname[0] != '/' && sys_rename->newname[0] != '/' &&
             !sys_rename->samedir) {
    data_size = sizeof(struct sys_renameat2);
  } else {
    data_size = sizeof(struct sys_renameat);
  }
  bpf_perf_event_output(ctx, &sys_rename_buf, BPF_F_CURRENT_CPU, sys_renameat2,
                        data_size);
  bpf_map_delete_elem(&sys_enter_rename_hash, &hash_id);
  return 0;
}
#endif

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
                             (const char*)ctx->args[3], (unsigned)ctx->args[4]);
}

SEC("tracepoint/syscalls/sys_exit_rename")
int tracepoint__syscalls__sys_exit_rename(struct syscall_trace_exit* ctx) {
#ifdef HAVE_RINGBUF_MAP_TYPE
  return on_sys_exit_rename((int)ctx->ret, SYS_RENAME);
#else
  return on_sys_exit_rename(ctx, SYS_RENAME);
#endif
}

SEC("tracepoint/syscalls/sys_exit_renameat")
int tracepoint__syscalls__sys_exit_renameat(struct syscall_trace_exit* ctx) {
#ifdef HAVE_RINGBUF_MAP_TYPE
  return on_sys_exit_rename((int)ctx->ret, SYS_RENAMEAT);
#else
  return on_sys_exit_rename(ctx, SYS_RENAMEAT);
#endif
}

SEC("tracepoint/syscalls/sys_exit_renameat2")
int tracepoint__syscalls__sys_exit_renameat2(struct syscall_trace_exit* ctx) {
#ifdef HAVE_RINGBUF_MAP_TYPE
  return on_sys_exit_rename((int)ctx->ret, SYS_RENAMEAT2);
#else
  return on_sys_exit_rename(ctx, SYS_RENAMEAT2);
#endif
}
