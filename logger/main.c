#include <bpf/libbpf.h>
#include <stdio.h>
#include <sys/resource.h>
#include <unistd.h>

#include "bpf_skels.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char* format,
                           va_list args) {
  return vfprintf(stderr, format, args);
}

int main(int argc, char** argv) {
  int err = 0;
  struct bpf_skels bpf_skels;

  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  /* Open BPF application */
  err = open_bpf_skels(&bpf_skels);
  if (err) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
  }

  /* Load & verify BPF programs */
  err = load_bpf_skels(&bpf_skels);
  if (err) {
    fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    goto cleanup;
  }

  /* Attach tracepoint handler */
  err = attach_bpf_skels(&bpf_skels);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

  printf(
      "Successfully started! Please run `sudo cat "
      "/sys/kernel/debug/tracing/trace_pipe` "
      "to see output of the BPF programs.\n");

  for (;;) {
    /* trigger our BPF program */
    fprintf(stderr, ".");
    sleep(1);
  }

cleanup:
  destroy_bpf_skels(&bpf_skels);
  return -err;
}
