#include "bpf.h"
#include <bpf/libbpf.h>
#include <stdlib.h>

#define BPF_OPEN_ERROR_MSG "Failed to open BPF skeleton\n"
#define BPF_LOAD_ERROR_MSG "Failed to load BPF skeleton\n"
#define BPF_ATTACH_ERROR_MSG "Failed to attach BPF skeleton\n"

static int libbpf_print_fn(enum libbpf_print_level level, const char* format,
                           va_list args) {
  return vfprintf(stderr, format, args);
}

/* Callback function for sys_execve_rb ring buffer. */
int sys_execve_callback(void* ctx, void* data, size_t data_sz) {
  const struct sys_execve* sys_execve = (struct sys_execve*)data;
  printf("Execve: %d %d %d %d %s\n", sys_execve->task.uid, sys_execve->task.gid,
         sys_execve->task.pid, sys_execve->task.ppid, sys_execve->task.comm);
  return 0;
}

/* Open BPF application. */
int bpf_open(struct bpf* bpf) {
  bpf->skel = logger_bpf__open();
  if (!bpf->skel) {
    fprintf(stderr, BPF_OPEN_ERROR_MSG);
    return 1;
  }
  return 0;
}

/* Load & verify BPF programs. */
int bpf_load(struct bpf* bpf) {
  if (logger_bpf__load(bpf->skel)) {
    fprintf(stderr, BPF_LOAD_ERROR_MSG);
    return 1;
  }
  return 0;
}

/* Attach tracepoint handler. */
int bpf_attach(struct bpf* bpf) {
  if (logger_bpf__attach(bpf->skel)) {
    fprintf(stderr, BPF_ATTACH_ERROR_MSG);
    return 1;
  }
  return 0;
}

/* Create ring buffers. */
int create_ring_buffers(struct bpf* bpf) {
  bpf->sys_execve_rb =
      ring_buffer__new(bpf_map__fd(bpf->skel->maps.sys_execve_rb),
                       sys_execve_callback, NULL, NULL);
  if (!bpf->sys_execve_rb) {
    fprintf(stderr, "Error to create ring_buffer\n");
    return 1;
  }
  return 0;
}

/* Poll data from ring buffers. */
int poll_ring_buffers(struct bpf* bpf) {
  if (ring_buffer__poll(bpf->sys_execve_rb, 100) < 0) {
    return 1;
  }
  return 0;
}

/* Open, load, verify BPF application, attach tracepoint handler and create ring
 * buffers. */
struct bpf* bpf_create() {
  struct bpf* bpf = malloc(sizeof(struct bpf));
  if (!bpf) return NULL;
  if (bpf_open(bpf) || bpf_load(bpf) || bpf_attach(bpf) ||
      create_ring_buffers(bpf)) {
    bpf_destroy(bpf);
    return NULL;
  }
  libbpf_set_print(libbpf_print_fn);
  return bpf;
}

/* Destroy BPF application. */
void bpf_destroy(struct bpf* bpf) {
  if (bpf->skel) logger_bpf__destroy(bpf->skel);
  if (bpf) free(bpf);
}
