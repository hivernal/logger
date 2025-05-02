#include "logger.skel.h"
#include "process.h"

struct bpf {
  struct logger_bpf* skel;
  struct ring_buffer* sys_execve_rb;
  int is_run;
  int poll_time_ms;
};

struct bpf* bpf_create();
void bpf_destroy(struct bpf* bpf);
int poll_ring_buffers(struct bpf* bpf);
