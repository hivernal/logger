#ifndef LOGGER_task_H_
#define LOGGER_task_H_

#define TASK_COMM_LEN 16

struct task {
  char comm[TASK_COMM_LEN];
  uint64_t time_nsec;
  uid_t uid;
  gid_t gid;
  pid_t pid;
  pid_t ppid;
  uint32_t tgid;
};

int fill_task(struct task* task);

#endif  // LOGGER_task_H_
