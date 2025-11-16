#include "logger/bpf/helpers.h"
#include "logger/bpf/sock.h"

/* IPV4. */
#define AF_INET 2
/* IPV6. */
#define AF_INET6 10

#ifdef HAVE_RINGBUF_MAP_TYPE

/* Buffer for sending sys_sock6 and sys_sock4 data to the userspace. */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, NPROC * sizeof(struct sys_sock6));
} sys_sock_buf SEC(".maps");

#else

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct sys_sock4);
} sys_sock4_array SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct sys_sock6);
} sys_sock6_array SEC(".maps");

/* Buffer for sending sys_sock6 and sys_sock4 data to the userspace. */
struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} sys_sock_buf SEC(".maps");

#endif

/*
 * Map for sharing data between enter and exit sockets syscalls
 * tracepoints.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 128);
  __type(key, u64);
  __type(value, int);
} sys_enter_sock_hash SEC(".maps");

FUNC_INLINE int get_sock_from_fd(int fd, const struct sock** sock) {
  if (!sock) return 1;
  const struct file* file;
  const struct socket* socket;
  if (get_file_from_fd(fd, &file) < 0) return 1;
  if (bpf_core_read(&socket, sizeof(socket), &file->private_data) < 0) return 1;
  if (bpf_core_read(sock, sizeof(*sock), &socket->sk) < 0) return 1;
  return 0;
}

/* Fills the sys_enter_sock_hash map. */
FUNC_INLINE int on_sys_enter_sock(int fd) {
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  return (int)bpf_map_update_elem(&sys_enter_sock_hash, &hash_id, &fd, BPF_ANY);
}

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint__syscalls__sys_enter_connect(struct syscall_trace_enter* ctx) {
  return on_sys_enter_sock((int)ctx->args[0]);
}

/* Reads the destination and source addresses and ports of the sock. */
FUNC_INLINE int fill_sys_sock4(struct sys_sock4* sys_sock4,
                               const struct sock* sock) {
  int error = 0;
  if (bpf_core_read(&sys_sock4->daddr, sizeof(sys_sock4->daddr),
                    &sock->__sk_common.skc_daddr) < 0)
    error |= ERROR_READ_DADDR;
  if (bpf_core_read(&sys_sock4->saddr, sizeof(sys_sock4->saddr),
                    &sock->__sk_common.skc_rcv_saddr) < 0)
    error |= ERROR_READ_SADDR;
  if (bpf_core_read(&sys_sock4->dport, sizeof(sock->__sk_common.skc_portpair),
                    &sock->__sk_common.skc_portpair) < 0)
    error |= ERROR_READ_DPORT;
  return error;
}

FUNC_INLINE int fill_sys_sock6(struct sys_sock6* sys_sock6,
                               const struct sock* sock) {
  int error = 0;
  if (bpf_core_read(&sys_sock6->daddr, sizeof(sys_sock6->daddr),
                    &sock->__sk_common.skc_v6_daddr.in6_u) < 0)
    error |= ERROR_READ_DADDR;
  if (bpf_core_read(&sys_sock6->saddr,
                    sizeof(sock->__sk_common.skc_v6_rcv_saddr),
                    &sock->__sk_common.skc_v6_rcv_saddr.in6_u) < 0)
    error |= ERROR_READ_SADDR;
  if (bpf_core_read(&sys_sock6->dport, sizeof(sock->__sk_common.skc_portpair),
                    &sock->__sk_common.skc_portpair) < 0)
    error |= ERROR_READ_DPORT;
  return error;
}

#ifdef HAVE_RINGBUF_MAP_TYPE
FUNC_INLINE int fill_and_send_sock(const struct sock* sock, int ret,
                                   int event_type) {
#else
FUNC_INLINE int fill_and_send_sock(const struct sock* sock,
                                   struct syscall_trace_exit* ret,
                                   int event_type) {
  const int array_index = 0;
  size_t sys_sock_size = 0;
#endif
  sa_family_t family;
  if (bpf_core_read(&family, sizeof(family), &sock->__sk_common.skc_family) < 0)
    return 1;
  struct sys_sock* sys_sock = NULL;
  int error = 0;
  unsigned char state;
  if (bpf_core_read(&state, sizeof(state), &sock->__sk_common.skc_state) < 0)
    error |= ERROR_READ_STATE;
  if ((event_type == SYS_CONNECT && state == TCP_CLOSE)) return 0;
  if (family == AF_INET) {
#ifdef HAVE_RINGBUF_MAP_TYPE
    struct sys_sock4* sys_sock4 =
        bpf_ringbuf_reserve(&sys_sock_buf, sizeof(*sys_sock4), 0);
#else
    struct sys_sock4* sys_sock4 =
        bpf_map_lookup_elem(&sys_sock4_array, &array_index);
    sys_sock_size = sizeof(*sys_sock4);
#endif
    if (!sys_sock4) return 1;
    sys_sock = (struct sys_sock*)sys_sock4;
    error = fill_sys_sock4(sys_sock4, sock);
  } else if (family == AF_INET6) {
#ifdef HAVE_RINGBUF_MAP_TYPE
    struct sys_sock6* sys_sock6 =
        bpf_ringbuf_reserve(&sys_sock_buf, sizeof(*sys_sock6), 0);
#else
    struct sys_sock6* sys_sock6 =
        bpf_map_lookup_elem(&sys_sock6_array, &array_index);
    sys_sock_size = sizeof(*sys_sock6);
#endif
    if (!sys_sock6) return 1;
    sys_sock = (struct sys_sock*)sys_sock6;
    error = fill_sys_sock6(sys_sock6, sock);
  } else {
    return 0;
  }
  sys_sock->error = error;
  if (bpf_core_read(&sys_sock->protocol, sizeof(sock->sk_protocol),
                    &sock->sk_protocol) < 0)
    sys_sock->error |= ERROR_READ_PROTOCOL;
  if (bpf_core_read(&sys_sock->type, sizeof(sock->sk_type), &sock->sk_type) < 0)
    sys_sock->error |= ERROR_READ_TYPE;
  if (fill_task(&sys_sock->task) < 0) sys_sock->error |= ERROR_FILL_TASK;
#ifdef HAVE_RINGBUF_MAP_TYPE
  sys_sock->ret = ret;
#else
  sys_sock->ret = (int)ret->ret;
#endif
  sys_sock->family = family;
  sys_sock->event_type = event_type;
  sys_sock->state = state;
#ifdef HAVE_RINGBUF_MAP_TYPE
  bpf_ringbuf_submit(sys_sock, 0);
#else
  bpf_perf_event_output(ret, &sys_sock_buf, BPF_F_CURRENT_CPU, sys_sock,
                        sys_sock_size);
#endif
  return 0;
}

#ifdef HAVE_RINGBUF_MAP_TYPE
FUNC_INLINE int on_sys_exit_sock(int ret, int event_type) {
#else
FUNC_INLINE int on_sys_exit_sock(struct syscall_trace_exit* ret,
                                 int event_type) {
#endif
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  const int* fd = bpf_map_lookup_elem(&sys_enter_sock_hash, &hash_id);
  if (!fd) return 1;
  const struct sock* sock;
  if (get_sock_from_fd(*fd, &sock)) {
    bpf_map_delete_elem(&sys_enter_sock_hash, &hash_id);
    return 1;
  }
  bpf_map_delete_elem(&sys_enter_sock_hash, &hash_id);
  return fill_and_send_sock(sock, ret, event_type);
}

SEC("tracepoint/syscalls/sys_exit_connect")
int tracepoint__syscalls__sys_exit_connect(struct syscall_trace_exit* ctx) {
#ifdef HAVE_RINGBUF_MAP_TYPE
  return on_sys_exit_sock((int)ctx->ret, SYS_CONNECT);
#else
  return on_sys_exit_sock(ctx, SYS_CONNECT);
#endif
}

SEC("tracepoint/syscalls/sys_exit_accept")
int tracepoint__syscalls__sys_exit_accept(struct syscall_trace_exit* ctx) {
  int fd = (int)ctx->ret;
  const struct sock* sock;
  if (get_sock_from_fd(fd, &sock)) return 1;
#ifdef HAVE_RINGBUF_MAP_TYPE
  return fill_and_send_sock(sock, fd, SYS_ACCEPT);
#else
  return fill_and_send_sock(sock, ctx, SYS_ACCEPT);
#endif
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int tracepoint__syscalls__sys_exit_accept4(struct syscall_trace_exit* ctx) {
  int fd = (int)ctx->ret;
  const struct sock* sock;
  if (get_sock_from_fd(fd, &sock)) return 1;
#ifdef HAVE_RINGBUF_MAP_TYPE
  return fill_and_send_sock(sock, fd, SYS_ACCEPT4);
#else
  return fill_and_send_sock(sock, ctx, SYS_ACCEPT4);
#endif
}
