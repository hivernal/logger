#include "logger/bpf/helpers.h"
#include "logger/bpf/setid.h"

/* Buffer for sending sys_setid data to the userspace. */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries,
         NPROC * (sizeof(struct sys_setid) + sizeof(struct sys_enter_setid)));
} sys_setid_rb SEC(".maps");

/*
 * Map for sharing data between enter and exit setuid, setgid, setreuid,
 * setregid, setid, setresgid, setfsuid, setfsgid tracepoints.
 */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct sys_enter_setid);
} sys_enter_setid_array SEC(".maps");

const int array_index = 0;

FUNC_INLINE int on_sys_enter_setid1(uint32_t id) {
  struct sys_enter_setid* enter =
      bpf_map_lookup_elem(&sys_enter_setid_array, &array_index);
  if (!enter) return 1;
  enter->ids[0] = id;
  enter->is_correct = 1;
  return 0;
};

FUNC_INLINE int on_sys_enter_setid2(uint32_t id1, uint32_t id2) {
  struct sys_enter_setid* enter =
      bpf_map_lookup_elem(&sys_enter_setid_array, &array_index);
  if (!enter) return 1;
  enter->ids[0] = id1;
  enter->ids[1] = id2;
  enter->is_correct = 1;
  return 0;
};

FUNC_INLINE int on_sys_enter_setid3(uint32_t id1, uint32_t id2, uint32_t id3) {
  struct sys_enter_setid* enter =
      bpf_map_lookup_elem(&sys_enter_setid_array, &array_index);
  if (!enter) return 1;
  enter->ids[0] = id1;
  enter->ids[1] = id2;
  enter->ids[2] = id3;
  enter->is_correct = 1;
  return 0;
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

FUNC_INLINE int on_sys_exit_setid(int ret, int type) {
  struct sys_enter_setid* enter =
      bpf_map_lookup_elem(&sys_enter_setid_array, &array_index);
  if (!enter || !enter->is_correct) return 1;
  enter->is_correct = 0;
  struct sys_setid* sys_setid = NULL;
  if (type == SYS_SETUID || type == SYS_SETGID || type == SYS_SETFSUID ||
      type == SYS_SETFSGID) {
    sys_setid = bpf_ringbuf_reserve(
        &sys_setid_rb, sizeof(*sys_setid) + sizeof(enter->ids[0]), 0);
    if (!sys_setid) return 1;
    sys_setid->ids[0] = enter->ids[0];
  } else if (type == SYS_SETREUID || type == SYS_SETREGID) {
    sys_setid = bpf_ringbuf_reserve(
        &sys_setid_rb, sizeof(*sys_setid) + 2 * sizeof(enter->ids[0]), 0);
    if (!sys_setid) return 1;
    sys_setid->ids[0] = enter->ids[0];
    sys_setid->ids[1] = enter->ids[1];
  } else if (type == SYS_SETRESUID || type == SYS_SETRESGID) {
    sys_setid = bpf_ringbuf_reserve(
        &sys_setid_rb, sizeof(*sys_setid) + 3 * sizeof(enter->ids[0]), 0);
    if (!sys_setid) return 1;
    sys_setid->ids[0] = enter->ids[0];
    sys_setid->ids[1] = enter->ids[1];
    sys_setid->ids[2] = enter->ids[2];
  } else {
    return 0;
  }
  sys_setid->ret = ret;
  sys_setid->event_type = type;
  sys_setid->error = 0;
  if (fill_task(&sys_setid->task) < 0) sys_setid->error |= ERROR_FILL_TASK;
  bpf_ringbuf_submit(sys_setid, 0);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_setuid")
int tracepoint__syscalls__sys_exit_setuid(struct syscall_trace_exit* ctx) {
  return on_sys_exit_setid((int)ctx->ret, SYS_SETUID);
}

SEC("tracepoint/syscalls/sys_exit_setgid")
int tracepoint__syscalls__sys_exit_setgid(struct syscall_trace_exit* ctx) {
  return on_sys_exit_setid((int)ctx->ret, SYS_SETGID);
}

SEC("tracepoint/syscalls/sys_exit_setreuid")
int tracepoint__syscalls__sys_exit_setreuid(struct syscall_trace_exit* ctx) {
  return on_sys_exit_setid((int)ctx->ret, SYS_SETREUID);
}

SEC("tracepoint/syscalls/sys_exit_setregid")
int tracepoint__syscalls__sys_exit_setregid(struct syscall_trace_exit* ctx) {
  return on_sys_exit_setid((int)ctx->ret, SYS_SETREGID);
}

SEC("tracepoint/syscalls/sys_exit_setresuid")
int tracepoint__syscalls__sys_exit_setresuid(struct syscall_trace_exit* ctx) {
  return on_sys_exit_setid((int)ctx->ret, SYS_SETRESUID);
}

SEC("tracepoint/syscalls/sys_exit_setresgid")
int tracepoint__syscalls__sys_exit_setresgid(struct syscall_trace_exit* ctx) {
  return on_sys_exit_setid((int)ctx->ret, SYS_SETRESGID);
}

SEC("tracepoint/syscalls/sys_exit_setfsuid")
int tracepoint__syscalls__sys_exit_setfsuid(struct syscall_trace_exit* ctx) {
  return on_sys_exit_setid((int)ctx->ret, SYS_SETFSUID);
}

SEC("tracepoint/syscalls/sys_exit_setfsgid")
int tracepoint__syscalls__sys_exit_setfsgid(struct syscall_trace_exit* ctx) {
  return on_sys_exit_setid((int)ctx->ret, SYS_SETFSGID);
}
