#ifndef LOGGER_BPF_SETID_H_
#define LOGGER_BPF_SETID_H_

#include "logger/bpf/task.h"

#define SYS_SETID_HEADER \
  struct task task;      \
  int error;             \
  int event_type;        \
  int ret

/*
 * Struct for setuid, setreuid, setresuid, setgid, setregid, setresgid,
 * setfsuid, setfsgid.
 */
struct sys_setid {
  SYS_SETID_HEADER;
  uint32_t ids[];
};

#endif  // LOGGER_BPF_SETID_H_
