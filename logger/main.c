#include "bpf.h"

int main(int argc, char** argv) {
  struct bpf* bpf = bpf_create();
  if (!bpf) return 1;

  for (;;) {
    /* trigger our BPF program */
    if (poll_ring_buffers(bpf)) break;
  }

  bpf_destroy(bpf);
  return 0;
}
