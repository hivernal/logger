/* Interface for manipulating BPF applicaton. */

#ifndef LOGGER_BPF_H_
#define LOGGER_BPF_H_

struct bpf;

struct bpf* bpf_create();
void bpf_destroy(struct bpf* bpf);
int poll_ring_buffers(struct bpf* bpf);

#endif  // LOGGER_BPF_H_
