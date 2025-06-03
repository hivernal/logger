#ifndef LOGGER_BPF_TASK_H_
#define LOGGER_BPF_TASK_H_

#define TASK_COMM_LEN 16
#define PATH_SIZE 4096
#define DENTRY_NAME_SIZE 256
#define MAX_DENTRIES 128

enum path_type {
  PATH_ABSOLUTE,
  // PATH_ABSOLUTE_FD,
  PATH_RELATIVE_CWD,
  PATH_RELATIVE_FD
};

struct task {
  uint64_t time_nsec;
  uid_t uid;
  gid_t gid;
  pid_t pid;
  pid_t ppid;
  pid_t tgid;
  unsigned sessionid;
  char comm[TASK_COMM_LEN];
};

struct path_name {
  char data[PATH_SIZE];
  char reserve[DENTRY_NAME_SIZE]; /* For BPF verifier. */
  unsigned offset;
};

#endif  // LOGGER_BPF_TASK_H_
