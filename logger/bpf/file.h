#ifndef LOGGER_BPF_FILE_H_
#define LOGGER_BPF_FILE_H_

#include "logger/bpf/task.h"

#define SYS_WRITE_BUFFER_SIZE 8192

/*
 * System files that contains info about users and groups.
 * For these files buffer must be set.
 */
enum file_type {
  FILE_TYPE_OTHER = 0,
  FILE_TYPE_PASSWD,
  FILE_TYPE_GROUP,
  FILE_TYPE_DOAS,
  FILE_TYPE_SUDOERS,
  FILE_TYPE_SUDOERS_DIR,
};

#define SYS_WRITE_HEADER                               \
  struct task task;                                    \
  /* The number of bytes to be written to the file. */ \
  size_t count;                                        \
  /* The position to write. */                         \
  loff_t f_pos;                                        \
  /* File flags. file.f_flags. */                      \
  unsigned f_flags;                                    \
  /* File mode. file.f_mode. */                        \
  unsigned f_mode;                                     \
  int file_type;                                       \
  /* File name. */                                     \
  struct path_dentries file;                           \
  /* The number of bytes written. */                   \
  int ret;                                             \
  int error;                                           \
  int event_type

/* Struct for the write syscall. */
struct sys_write {
  SYS_WRITE_HEADER;
  /* The written buffer. */
  char buffer[];
};

/* Struct for the read syscall. */
struct sys_read {
  struct task task;
  int error;
  /* The number of bytes to be readen from the file. */
  size_t count;
  /* The position to read. */
  loff_t f_pos;
  /* File flags. file.f_flags. */
  unsigned f_flags;
  /* File mode. file.f_mode. */
  unsigned f_mode;
  /* File name. */
  struct path_dentries file;
  /* The number of readen bytes. */
  int event_type;
  int ret;
};

/* Struct for the unlink syscall. */
struct sys_unlink {
  struct task task;
  enum path_type filename_type;
  int event_type;
  /* On success, zero is returned. */
  int ret;
  int error;
  unsigned flags;
  /* File name. */
  char filename[PATH_SIZE];
};

/* Struct for the unlinkat syscall. */
struct sys_unlinkat {
  struct sys_unlink sys_unlink;
  struct path_dentries dir;
};

#define SYS_CHMOD_HEADER        \
  struct task task;             \
  enum path_type filename_type; \
  unsigned mode;                \
  int event_type;               \
  unsigned flags;               \
  int error;                    \
  int ret

/* Struct for the chmod syscall. */
struct sys_chmod {
  SYS_CHMOD_HEADER;
  char filename[PATH_SIZE];
};

/* Struct for the fchmod syscall. */
struct sys_fchmod {
  SYS_CHMOD_HEADER;
  struct path_dentries file;
};

/* Struct for the fchmodat syscall. */
struct sys_fchmodat {
  struct sys_chmod sys_chmod;
  struct path_dentries dir;
};

#define SYS_CHOWN_HEADER        \
  struct task task;             \
  enum path_type filename_type; \
  uid_t uid;                    \
  gid_t gid;                    \
  int event_type;               \
  unsigned flags;               \
  int error;                    \
  int ret

/* Struct for the chown syscall. */
struct sys_chown {
  SYS_CHOWN_HEADER;
  char filename[PATH_SIZE];
};

/* Struct for the fchown syscall. */
struct sys_fchown {
  SYS_CHOWN_HEADER;
  struct path_dentries file;
};

/* Struct for the fchownat syscall. */
struct sys_fchownat {
  struct sys_chown sys_chown;
  struct path_dentries dir;
};

/* Struct for the rename syscall. */
struct sys_rename {
  char oldname[PATH_SIZE];
  char newname[PATH_SIZE];
  int error;
  struct task task;
  enum path_type newname_type;
  enum path_type oldname_type;
  int event_type;
  unsigned flags;
  /* If oldfd == newfd. */
  int samedir;
  int ret;
};

/*
 * Struct for the renameat, renameat2 syscall if one of names is relative or
 * both names are relative and newdirfd == olddirfd.
 */
struct sys_renameat {
  struct sys_rename sys_rename;
  struct path_dentries dir;
};

/* Struct for the renameat, renameat2 syscall. */
struct sys_renameat2 {
  struct sys_rename sys_rename;
  struct path_dentries newdir;
  struct path_dentries olddir;
};

#endif  // LOGGER_BPF_FILE_H_
