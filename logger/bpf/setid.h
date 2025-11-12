#ifndef LOGGER_BPF_SETID_H_
#define LOGGER_BPF_SETID_H_

#include "logger/bpf/task.h"

/*
 * Struct contains sys_enter_setuid, sys_enter_setreuid, sys_enter_setresuid,
 * sys_enter_setgid, sys_enter_setregid, sys_enter_setresgid,
 * sys_enter_setfsuid, sys_enter_setfsgid, data.
 */
struct sys_enter_setid {
  uint32_t ids[3];
  /* Flag for checking errors. */
  int is_correct;
};

/*
 * Struct for setuid, setreuid, setresuid, setgid, setregid, setresgid,
 * setfsuid, setfsgid.
 */
struct sys_setid {
  struct task task;
  int error;
  int event_type;
  int ret;
  uint32_t ids[];
};

#endif  // LOGGER_BPF_SETID_H_
