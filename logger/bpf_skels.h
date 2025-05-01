#ifndef LOGGER_BPF_SKELLS_H_
#define LOGGER_BPF_SKELLS_H_

#include "execve.skel.h"

struct bpf_skels {
  struct execve_bpf *execve;
};

int open_bpf_skels(struct bpf_skels* bpf_skels);
int load_bpf_skels(struct bpf_skels* bpf_skels);
int attach_bpf_skels(struct bpf_skels* bpf_skels);
void destroy_bpf_skels(struct bpf_skels* bpf_skels);

#endif
