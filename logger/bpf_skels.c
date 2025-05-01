#include "bpf_skels.h"

int open_bpf_skels(struct bpf_skels* bpf_skels) {
  bpf_skels->execve = execve_bpf__open();
  if (!bpf_skels->execve) {
    return 1;
  }
  return 0;
}

#define DEFINE_BPF_SKEL_HELPER(name)                  \
  int name##_bpf_skels(struct bpf_skels* bpf_skels) { \
    if (execve_bpf__##name(bpf_skels->execve)) {      \
      return 1;                                       \
    }                                                 \
    return 0;                                         \
  }

DEFINE_BPF_SKEL_HELPER(load);
DEFINE_BPF_SKEL_HELPER(attach);

void destroy_bpf_skels(struct bpf_skels* bpf_skels) {
  execve_bpf__destroy(bpf_skels->execve);
}
