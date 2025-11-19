#include "logger/bpf/helpers.h"
#include "logger/bpf/setid.h"

/*
 * Struct contains sys_enter_setuid, sys_enter_setreuid, sys_enter_setresuid,
 * sys_enter_setgid, sys_enter_setregid, sys_enter_setresgid,
 * sys_enter_setfsuid, sys_enter_setfsgid, data.
 */
struct sys_enter_setid {
  uint32_t ids[3];
};

/*
 * Map for sharing data between enter and exit setuid, setgid, setreuid,
 * setregid, setid, setresgid, setfsuid, setfsgid tracepoints.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 128);
  __type(key, u64);
  __type(value, struct sys_enter_setid);
} sys_enter_setid_hash SEC(".maps");

/* Buffer for sending sys_setid data to the userspace. */
struct {
#ifdef HAVE_RINGBUF_MAP_TYPE
  RINGBUF_BODY(NPROC *
               (sizeof(struct sys_setid) + sizeof(struct sys_enter_setid)));
#else
  PERF_EVENT_ARRAY_BODY;
#endif
} sys_setid_buf SEC(".maps");

#ifndef HAVE_RINGBUF_MAP_TYPE
struct sys_setid3 {
  SYS_SETID_HEADER;
  uint32_t ids[3];
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct sys_setid3);
} sys_setid_array SEC(".maps");
#endif

FUNC_INLINE int on_sys_enter_setid1(uint32_t id) {
  uint64_t hash_id = bpf_get_current_pid_tgid();
  struct sys_enter_setid sys_setid = {.ids[0] = id};
  return (int)bpf_map_update_elem(&sys_enter_setid_hash, &hash_id, &sys_setid,
                                  BPF_ANY);
};

FUNC_INLINE int on_sys_enter_setid2(uint32_t id1, uint32_t id2) {
  uint64_t hash_id = bpf_get_current_pid_tgid();
  struct sys_enter_setid sys_setid = {.ids[0] = id1, .ids[1] = id2};
  return (int)bpf_map_update_elem(&sys_enter_setid_hash, &hash_id, &sys_setid,
                                  BPF_ANY);
};

FUNC_INLINE int on_sys_enter_setid3(uint32_t id1, uint32_t id2, uint32_t id3) {
  uint64_t hash_id = bpf_get_current_pid_tgid();
  struct sys_enter_setid sys_setid = {.ids = {id1, id2, id3}};
  return (int)bpf_map_update_elem(&sys_enter_setid_hash, &hash_id, &sys_setid,
                                  BPF_ANY);
};

SEC("tracepoint/syscalls/sys_enter_setuid")
int tracepoint__syscalls__sys_enter_setuid(struct syscall_trace_enter* ctx) {
  return on_sys_enter_setid1((uint32_t)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_setgid")
int tracepoint__syscalls__sys_enter_setgid(struct syscall_trace_enter* ctx) {
  return on_sys_enter_setid1((uint32_t)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_setreuid")
int tracepoint__syscalls__sys_enter_setreuid(struct syscall_trace_enter* ctx) {
  return on_sys_enter_setid2((uint32_t)ctx->args[0], (uint32_t)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_setregid")
int tracepoint__syscalls__sys_enter_setregid(struct syscall_trace_enter* ctx) {
  return on_sys_enter_setid2((uint32_t)ctx->args[0], (uint32_t)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_setresuid")
int tracepoint__syscalls__sys_enter_setresuid(struct syscall_trace_enter* ctx) {
  return on_sys_enter_setid3((uint32_t)ctx->args[0], (uint32_t)ctx->args[1],
                             (uint32_t)ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_setresgid")
int tracepoint__syscalls__sys_enter_setresgid(struct syscall_trace_enter* ctx) {
  return on_sys_enter_setid3((uint32_t)ctx->args[0], (uint32_t)ctx->args[1],
                             (uint32_t)ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_setfsuid")
int tracepoint__syscalls__sys_enter_setfsuid(struct syscall_trace_enter* ctx) {
  return on_sys_enter_setid1((uint32_t)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_setfsgid")
int tracepoint__syscalls__sys_enter_setfsgid(struct syscall_trace_enter* ctx) {
  return on_sys_enter_setid1((uint32_t)ctx->args[0]);
}

#define IS_SETID1(type)                                                      \
  ((type) == SYS_SETUID || (type) == SYS_SETGID || (type) == SYS_SETFSUID || \
   (type) == SYS_SETFSGID)

#define IS_SETID2(type) ((type) == SYS_SETREUID || (type) == SYS_SETREGID)

#define IS_SETID3(type) ((type) == SYS_SETRESUID || (type) == SYS_SETRESGID)

#ifdef HAVE_RINGBUF_MAP_TYPE
FUNC_INLINE int on_sys_exit_setid(int ret, int type) {
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  struct sys_enter_setid* enter =
      bpf_map_lookup_elem(&sys_enter_setid_hash, &hash_id);
  if (!enter) return 1;
  struct sys_setid* sys_setid = NULL;
  if (IS_SETID1(type)) {
    sys_setid = bpf_ringbuf_reserve(
        &sys_setid_buf, sizeof(*sys_setid) + sizeof(enter->ids[0]), 0);
    if (!sys_setid) goto clean;
    sys_setid->ids[0] = enter->ids[0];
  } else if (IS_SETID2(type)) {
    sys_setid = bpf_ringbuf_reserve(
        &sys_setid_buf, sizeof(*sys_setid) + 2 * sizeof(enter->ids[0]), 0);
    if (!sys_setid) goto clean;
    sys_setid->ids[0] = enter->ids[0];
    sys_setid->ids[1] = enter->ids[1];
  } else if (IS_SETID3(type)) {
    sys_setid = bpf_ringbuf_reserve(
        &sys_setid_buf, sizeof(*sys_setid) + 3 * sizeof(enter->ids[0]), 0);
    if (!sys_setid) goto clean;
    sys_setid->ids[0] = enter->ids[0];
    sys_setid->ids[1] = enter->ids[1];
    sys_setid->ids[2] = enter->ids[2];
  } else {
    goto clean;
  }
  sys_setid->ret = ret;
  sys_setid->event_type = type;
  sys_setid->error = 0;
  if (fill_task(&sys_setid->task) < 0) sys_setid->error |= ERROR_FILL_TASK;
  bpf_ringbuf_submit(sys_setid, 0);
clean:
  bpf_map_delete_elem(&sys_enter_setid_hash, &hash_id);
  return 0;
}

#else
FUNC_INLINE int on_sys_exit_setid(struct syscall_trace_exit* ctx, int type) {
  const int array_index = 0;
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  struct sys_enter_setid* enter =
      bpf_map_lookup_elem(&sys_enter_setid_hash, &hash_id);
  if (!enter) return 1;
  struct sys_setid3* sys_setid =
      bpf_map_lookup_elem(&sys_setid_array, &array_index);
  if (!sys_setid) goto clean;
  sys_setid->ret = (int)ctx->ret;
  sys_setid->event_type = type;
  sys_setid->error = 0;
  if (fill_task(&sys_setid->task) < 0) sys_setid->error |= ERROR_FILL_TASK;
  if (IS_SETID1(type)) {
    sys_setid->ids[0] = enter->ids[0];
  } else if (IS_SETID2(type)) {
    sys_setid->ids[0] = enter->ids[0];
    sys_setid->ids[1] = enter->ids[1];
  } else if (IS_SETID3(type)) {
    sys_setid->ids[0] = enter->ids[0];
    sys_setid->ids[1] = enter->ids[1];
    sys_setid->ids[2] = enter->ids[2];
  } else {
    goto clean;
  }
  bpf_perf_event_output(ctx, &sys_setid_buf, BPF_F_CURRENT_CPU, sys_setid,
                        sizeof(*sys_setid));
clean:
  bpf_map_delete_elem(&sys_enter_setid_hash, &hash_id);
  return 0;
}
#endif

SEC("tracepoint/syscalls/sys_exit_setuid")
int tracepoint__syscalls__sys_exit_setuid(struct syscall_trace_exit* ctx) {
#ifdef HAVE_RINGBUF_MAP_TYPE
  return on_sys_exit_setid((int)ctx->ret, SYS_SETUID);
#else
  return on_sys_exit_setid(ctx, SYS_SETUID);
#endif
}

SEC("tracepoint/syscalls/sys_exit_setgid")
int tracepoint__syscalls__sys_exit_setgid(struct syscall_trace_exit* ctx) {
#ifdef HAVE_RINGBUF_MAP_TYPE
  return on_sys_exit_setid((int)ctx->ret, SYS_SETGID);
#else
  return on_sys_exit_setid(ctx, SYS_SETGID);
#endif
}

SEC("tracepoint/syscalls/sys_exit_setreuid")
int tracepoint__syscalls__sys_exit_setreuid(struct syscall_trace_exit* ctx) {
#ifdef HAVE_RINGBUF_MAP_TYPE
  return on_sys_exit_setid((int)ctx->ret, SYS_SETREUID);
#else
  return on_sys_exit_setid(ctx, SYS_SETREUID);
#endif
}

SEC("tracepoint/syscalls/sys_exit_setregid")
int tracepoint__syscalls__sys_exit_setregid(struct syscall_trace_exit* ctx) {
#ifdef HAVE_RINGBUF_MAP_TYPE
  return on_sys_exit_setid((int)ctx->ret, SYS_SETREGID);
#else
  return on_sys_exit_setid(ctx, SYS_SETREGID);
#endif
}

SEC("tracepoint/syscalls/sys_exit_setresuid")
int tracepoint__syscalls__sys_exit_setresuid(struct syscall_trace_exit* ctx) {
#ifdef HAVE_RINGBUF_MAP_TYPE
  return on_sys_exit_setid((int)ctx->ret, SYS_SETRESUID);
#else
  return on_sys_exit_setid(ctx, SYS_SETRESUID);
#endif
}

SEC("tracepoint/syscalls/sys_exit_setresgid")
int tracepoint__syscalls__sys_exit_setresgid(struct syscall_trace_exit* ctx) {
#ifdef HAVE_RINGBUF_MAP_TYPE
  return on_sys_exit_setid((int)ctx->ret, SYS_SETRESGID);
#else
  return on_sys_exit_setid(ctx, SYS_SETRESGID);
#endif
}

SEC("tracepoint/syscalls/sys_exit_setfsuid")
int tracepoint__syscalls__sys_exit_setfsuid(struct syscall_trace_exit* ctx) {
#ifdef HAVE_RINGBUF_MAP_TYPE
  return on_sys_exit_setid((int)ctx->ret, SYS_SETFSUID);
#else
  return on_sys_exit_setid(ctx, SYS_SETFSUID);
#endif
}

SEC("tracepoint/syscalls/sys_exit_setfsgid")
int tracepoint__syscalls__sys_exit_setfsgid(struct syscall_trace_exit* ctx) {
#ifdef HAVE_RINGBUF_MAP_TYPE
  return on_sys_exit_setid((int)ctx->ret, SYS_SETFSGID);
#else
  return on_sys_exit_setid(ctx, SYS_SETFSGID);
#endif
}
