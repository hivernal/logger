#ifndef LOGGER_BPF_SOCK_H_
#define LOGGER_BPF_SOCK_H_

#include "logger/bpf/task.h"

/*
 * Struct for sharing data between sys_enter_connect and sys_exit_connect,
 * sys_enter_accept and sys_exit_accept tracepoints.
 */
struct sys_enter_sock {
  /* Socket file descriptor. */
  int fd;
  /* Flag for checking errors. */
  int is_correct;
};

/* Struct for the connect, accept syscalls. */
struct sys_sock {
  struct task task;
  int event_type;
  int error;
  /* IP family. AF_INET, AF_INET6. */
  sa_family_t family;
  int type;
  /* Protocol type. TCP, UDP, ICMP... see /etc/protocols. */
  int protocol;
  /* Connection state. */
  unsigned char state;
  int ret;
};

/* Struct for the AF_INET6 connect, accept syscalls. */
struct sys_sock6 {
  struct sys_sock sock;
  /* Destination ipv6 address. */
  uint8_t daddr[16];
  /* Source ipv6 address. */
  uint8_t saddr[16];
  /* Destination port. */
  uint16_t dport;
  /* Source port. */
  uint16_t sport;
};

/* Struct for the AF_INET4 connect, accept syscalls. */
struct sys_sock4 {
  struct sys_sock sock;
  /* Destination ipv4 address. */
  uint32_t daddr;
  /* Source ipv4 address. */
  uint32_t saddr;
  /* Destination port. */
  uint16_t dport;
  /* Source port. */
  uint16_t sport;
};

#endif  // LOGGER_BPF_SOCK_H_
