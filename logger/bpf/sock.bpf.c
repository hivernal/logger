#include "logger/bpf/helpers.h"
#include "logger/bpf/sock.h"

/* IPV4. */
#define AF_INET 2
/* IPV6. */
#define AF_INET6 10

/* Buffer for sending sys_sock6 and sys_sock4 data to the userspace. */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, NPROC * sizeof(struct sys_sock6));
} sys_sock_rb SEC(".maps");

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

FUNC_INLINE int fill_and_send_sock(const struct sock* sock, int sys_ret,
                                   int event_type) {
  sa_family_t family;
  if (bpf_core_read(&family, sizeof(family), &sock->__sk_common.skc_family) < 0)
    return 1;
  struct sys_sock* sys_sock = NULL;
  int error = 0;
  unsigned char state;
  if (bpf_core_read(&state, sizeof(state), &sock->__sk_common.skc_state) < 0)
    error |= ERROR_READ_STATE;
  if ((event_type == SYS_CONNECT && state == TCP_CLOSE))
    return 0;
  if (family == AF_INET) {
    struct sys_sock4* sys_sock4 =
        bpf_ringbuf_reserve(&sys_sock_rb, sizeof(*sys_sock4), 0);
    if (!sys_sock4) return 1;
    sys_sock = (struct sys_sock*)sys_sock4;
    error = fill_sys_sock4(sys_sock4, sock);
  } else if (family == AF_INET6) {
    struct sys_sock6* sys_sock6 =
        bpf_ringbuf_reserve(&sys_sock_rb, sizeof(*sys_sock6), 0);
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
  sys_sock->ret = sys_ret;
  sys_sock->family = family;
  sys_sock->event_type = event_type;
  sys_sock->state = state;
  bpf_ringbuf_submit(sys_sock, 0);
  return 0;
}

FUNC_INLINE int on_sys_exit_sock(int sys_ret, int event_type) {
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  const int *fd =
      bpf_map_lookup_elem(&sys_enter_sock_hash, &hash_id);
  if (!fd) return 1;
  const struct sock* sock;
  if (get_sock_from_fd(*fd, &sock)) return 1;
  bpf_map_delete_elem(&sys_enter_sock_hash, &hash_id);
  return fill_and_send_sock(sock, sys_ret, event_type);
}

SEC("tracepoint/syscalls/sys_exit_connect")
int tracepoint__syscalls__sys_exit_connect(struct syscall_trace_exit* ctx) {
  return on_sys_exit_sock((int)ctx->ret, SYS_CONNECT);
}

SEC("tracepoint/syscalls/sys_exit_accept")
int tracepoint__syscalls__sys_exit_accept(struct syscall_trace_exit* ctx) {
  int fd = (int)ctx->ret;
  const struct sock* sock;
  if (get_sock_from_fd(fd, &sock)) return 1;
  return fill_and_send_sock(sock, fd, SYS_ACCEPT);
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int tracepoint__syscalls__sys_exit_accept4(struct syscall_trace_exit* ctx) {
  int fd = (int)ctx->ret;
  const struct sock* sock;
  if (get_sock_from_fd(fd, &sock)) return 1;
  return fill_and_send_sock(sock, fd, SYS_ACCEPT);
}
