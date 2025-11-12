#ifndef LOGGER_BPF_TASK_H_
#define LOGGER_BPF_TASK_H_

#include "logger/bpf/feature_probe.h"

#define TASK_COMM_LEN 16
#define PATH_SIZE 4096
#define DENTRY_NAME_SIZE 256
#define MAX_DENTRIES 128

/* Syscalls. */
#define SYS_READ 0
#define SYS_WRITE 1
// #define SYS_OPEN 2
// #define SYS_CLOSE 3
// #define SYS_PREAD64 17
// #define SYS_PWRITE64 18
// #define SYS_READV 19
// #define SYS_WRITEV 20
// #define SYS_DUP 32
// #define SYS_DUP3 33
// #define SYS_SENDFILE 40
#define SYS_CONNECT 42
#define SYS_ACCEPT 43
// #define SYS_BIND 49
// #define SYS_SOCKETPAIR 53
#define SYS_CLONE 56
// #define SYS_FORK 57
// #define SYS_VFORK 58
#define SYS_EXECVE 59
#define SYS_RENAME 82
// #define SYS_MKDIR 83
// #define SYS_RMDIR 84
// #define SYS_CREAT 85
// #define SYS_LINK 86
#define SYS_UNLINK 87
// #define SYS_SYMLINK 88
#define SYS_CHMOD 90
#define SYS_FCHMOD 91
#define SYS_CHOWN 92
#define SYS_FCHOWN 93
// #define SYS_LCHOWN 94
#define SYS_SETUID 105
#define SYS_SETGID 106
// #define SYS_SETPGID 109
// #define SYS_SETSID 112
#define SYS_SETREUID 113
#define SYS_SETREGID 114
#define SYS_SETRESUID 117
#define SYS_SETRESGID 119
#define SYS_SETFSUID 122
#define SYS_SETFSGID 123
// #define SYS_CAPSET 126
// #define SYS_PIVOT_ROOT 155
// #define SYS_PRCTL 157
// #define SYS_MOUNT 165
// #define SYS_UMOUNT2 166
// #define SYS_SETHOSTNAME 170
// #define SYS_SETDOMAINNAME 171
// #define SYS_INIT_MODULE 175
// #define SYS_DELETE_MODULE 176
// #define SYS_QUOTACTL 179
// #define SYS_SETXATTR 188
// #define SYS_LSETXATTR 189
// #define SYS_FSETXATTR 190
// #define SYS_REMOVEXATTR 197
// #define SYS_LREMOVEXATTR 198
// #define SYS_FREMOVEXATTR 199
// #define SYS_OPENAT 257
// #define SYS_MKDIRAT 258
#define SYS_FCHOWNAT 260
#define SYS_UNLINKAT 263
#define SYS_RENAMEAT 264
// #define SYS_LINKAT 265
// #define SYS_SYMLINKAT 266
#define SYS_FCHMODAT 268
#define SYS_ACCEPT4 288
// #define SYS_DUP3 292
// #define SYS_PREADV 295
// #define SYS_PWRITEV 296
#define SYS_RENAMEAT2 316
#define SYS_EXECVEAT 322
// #define SYS_PREADV2 327
// #define SYS_PWRITEV2 328
// #define SYS_MOVE_MOUNT 429 /* Since 5.2. */
// #define SYS_FSMOUNT 432 /* Since 5.2. */
#if LINUX_KERNEL_VERSION >= GET_LINUX_KERNEL_VERSION(5, 3)
#define SYS_CLONE3 435 /* Since 5.3. */
#endif
// #define SYS_OPENAT2 437 /* Since 5.6. */
#define SYS_FCHMODAT2 452
// #define SYS_SETXATTRAT 463

/* Perf event. */
#define SCHED_PROCESS_EXIT 1000

/*Kernel functions. */
// #define KERNEL_TCP_CONNECT 2000
// #define KERNEL_UDP_CONNECT 2001
// #define KERNEL_UDPV6_CONNECT 2002
// #define KERNEL_IP4_DATAGRAM_CONNECT 2003
// #define KERNEL_IP6_DATAGRAM_CONNECT 2004

#define ERROR_FILENAME 0x1
#define ERROR_ARGV 0x2
#define ERROR_READ_FD  0x4
#define ERROR_READ_CWD 0x8
#define ERROR_FILL_TASK  0x10
#define ERROR_FILL_TASK_CAPS 0x20
#define ERROR_FILL_BUFFER  0x40
#define ERROR_COPY_ENTER 0x80
#define ERROR_COPY_BUFFER  0x100
#define ERROR_EXIT_CODE  0x200
#define ERROR_READ_DADDR 0x400
#define ERROR_READ_SADDR 0x800
#define ERROR_READ_DPORT 0x1000
#define ERROR_READ_SPORT 0x1000
#define ERROR_READ_PROTOCOL 0x4000
#define ERROR_READ_TYPE 0x8000
#define ERROR_READ_STATE 0x10000

enum path_type {
  PATH_ABSOLUTE,
  PATH_ABSOLUTE_FD,
  /* Path is relative to the current working directory. */
  PATH_RELATIVE_CWD,
  /* Path is relative to the file descriptor. */
  PATH_RELATIVE_FD
};

/* Stores data from struct cred. */
struct task_cred {
  /* Real UID of the task. */
  uid_t uid;
  /* Real GID of the task. */
  gid_t gid;
  /* Saved UID of the task. */
  uid_t suid;
  /* Saved GID of the task. */
  gid_t sgid; 
  /* Effective UID of the task. */
  uid_t euid;
  /* Effective GID of the task. */
  gid_t egid;
  /* UID for VFS ops. */
  uid_t fsuid;
  /* GID for VFS ops. */
  gid_t fsgid;
};

/* Stores data from struct task_struct. */
struct task {
  /* Time in nanoseconds from 01.01.1970. */
  uint64_t time_nsec;
  /* Process ID. */
  pid_t pid;
  /* Parent process ID. */
  pid_t ppid;
  /* Thread group ID. */
  pid_t tgid;
  /* Login UID. */
  uid_t loginuid;
  /* Session ID. */
  unsigned sessionid;
  /* Real task cred. */
  struct task_cred cred;
  /* Short task command. */
  char comm[TASK_COMM_LEN];
};

/* Struct stores dentry.d_name entries. */
struct path_dentries {
  char data[PATH_SIZE];
  /* For BPF verifier. */
  char reserve[DENTRY_NAME_SIZE];
  unsigned offset;
};

#endif  // LOGGER_BPF_TASK_H_
