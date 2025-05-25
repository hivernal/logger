#include "logger/bpf.h"
#include <bpf/libbpf.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include "logger/process.skel.h"
#include "logger/file.skel.h"
#pragma GCC diagnostic pop

#include "logger/process.h"

#define BPF_OPEN_ERROR_MSG "Failed to open BPF skeleton\n"
#define BPF_LOAD_ERROR_MSG "Failed to load BPF skeleton\n"
#define BPF_ATTACH_ERROR_MSG "Failed to attach BPF skeleton\n"
#define BPF_CREATE_RB_ERROR_MSG "Failed to create BPF ringbuffer\n"

static int libbpf_print_fn(enum libbpf_print_level level
                           __attribute__((unused)),
                           const char* format, va_list args) {
  return vfprintf(stderr, format, args);
}

struct bpf {
  /* Skeletons. */
  struct process_skel* process_skel; /* Process skeleton object. */
  struct file_skel* file_skel;       /* File skeleton object. */

  /* Ring buffers. */
  struct ring_buffer* sys_execve_rb;

  /*
  int is_run;
  int poll_time_ms;
  */
};

/* Open BPF application. */
int bpf_open(struct bpf* bpf) {
  bpf->process_skel = process_skel__open();
  bpf->file_skel = file_skel__open();
  if (!bpf->process_skel || !bpf->file_skel) {
    fprintf(stderr, BPF_OPEN_ERROR_MSG);
    return 1;
  }
  return 0;
}

/* Load & verify BPF programs. */
int bpf_load(struct bpf* bpf) {
  if (process_skel__load(bpf->process_skel) ||
      file_skel__load(bpf->file_skel)) {
    fprintf(stderr, BPF_LOAD_ERROR_MSG);
    return 1;
  }
  return 0;
}

/* Attach tracepoint handler. */
int bpf_attach(struct bpf* bpf) {
  if (process_skel__attach(bpf->process_skel) ||
      file_skel__attach(bpf->file_skel)) {
    fprintf(stderr, BPF_ATTACH_ERROR_MSG);
    return 1;
  }
  return 0;
}

/* Create ring buffers. */
int create_ring_buffers(struct bpf* bpf) {
  bpf->sys_execve_rb =
      ring_buffer__new(bpf_map__fd(bpf->process_skel->maps.sys_execve_rb),
                       sys_execve_callback, NULL, NULL);
  if (!bpf->sys_execve_rb) {
    fprintf(stderr, BPF_CREATE_RB_ERROR_MSG);
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
  if (bpf->process_skel) process_skel__destroy(bpf->process_skel);
  if (bpf->file_skel) file_skel__destroy(bpf->file_skel);
  if (bpf) free(bpf);
}
