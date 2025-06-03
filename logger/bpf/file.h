#ifndef LOGGER_BPF_FILE_H_
#define LOGGER_BPF_FILE_H_

#include "logger/bpf/task.h"

#define DEFINE_STRUCT(name)   \
  struct name {               \
    enum path_type path_type; \
    struct task task;         \
    struct name##_args args;  \
    int ret;                  \
  }

#define DEFINE_STRUCT_FD(name)  \
  struct name {                 \
    enum path_type path_type;   \
    struct task task;           \
    struct name##_args args;    \
    struct path_name path_name; \
    int ret;                    \
  }

#define DEFINE_STRUCT_AT(name) \
  struct name##at {            \
    struct name name;          \
    struct path_name dir;      \
  }

#define DEFINE_STRUCT2(name) \
  DEFINE_STRUCT(name);       \
  DEFINE_STRUCT_AT(name)

enum event_type {
  EXECVE,
  PROCESS_EXIT,
  WRITE,
  READ,
  RMDIR,
  UNLINK,
  MKDIR,
  RENAME,
};

struct write_args {
  int fd;
  char buffer[8192];
  size_t count;
  loff_t pos;
  unsigned flags;
  unsigned mode;
};


struct write {
  enum path_type path_type;
  struct task task;
  struct write_args args;
  int ret;
  struct path_name path_name;
};

struct unlink_args {
  int dfd;
  int flags;
  char filename[PATH_SIZE];
};

DEFINE_STRUCT2(unlink);

/*
struct unlink {
  enum path_type path_type;
  struct task task;
  struct unlink_args args;
};

struct unlinkat {
  struct unlink unlink;
  struct path_name dir;
};
*/

struct rmdir_args {
  char filename[PATH_SIZE];
};

DEFINE_STRUCT2(rmdir);

/*
struct rmdir {
  enum path_type path_type;
  struct task task;
  struct rmdir_args args;
};

struct rmdirat {
  struct rmdir rmdir;
  struct path_name dir;
};
*/

struct rename_args {
  int olddfd;
  int newdfd;
  char oldfilename[PATH_SIZE];
  char newfilename[PATH_SIZE];
};

struct rename {
  enum path_type old_path_type;
  enum path_type new_path_type;
  struct task task;
  struct rename_args args;
};

DEFINE_STRUCT_AT(rename);

/*
struct renameat {
  struct rename rename;
  struct path_name dir;
};
*/

struct renameat2 {
  struct rename rename;
  struct path_name olddir;
  struct path_name newdir;
};

struct chmod_args {
  char filename[PATH_SIZE];
};

DEFINE_STRUCT2(chmod);

/*
struct chmod {
  enum path_type path_type;
  struct task task;
  struct chmod_args args;
};

struct chmodat {
  struct chmod chmod;
  struct path_name dir;
};
*/

struct fchmod_args {
  int fd;
};

DEFINE_STRUCT_FD(fchmod);

/*
struct fchmod {
  enum path_type path_type;
  struct task task;
  struct fchmod_args args;
  struct path_name path_name;
};
*/

struct chown_args {
  uid_t uid;
  gid_t gid;
  int dfd;
  char filename[PATH_SIZE];
};

DEFINE_STRUCT2(chown);

/*
struct chown {
  enum path_type path_type;
  struct task task;
  struct chown_args args;
};

struct chownat {
  struct chown chown;
  struct path_name dir;
};
*/

struct fchown_args {
  uid_t uid;
  gid_t gid;
  int fd;
};

DEFINE_STRUCT_FD(fchown);

/*
struct fchown {
  enum path_type path_type;
  struct task task;
  struct fchown_args args;
  struct path_name path_name;
};
*/

struct mkdir_args {
  int fd;
  mode_t mode;
  char filename[PATH_SIZE];
};

DEFINE_STRUCT2(mkdir);

#endif  // LOGGER_BPF_FILE_H_
