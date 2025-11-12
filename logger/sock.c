#include "logger/sock.h"
#include "logger/helpers.h"

#include <arpa/inet.h>
#include <netdb.h>

#include "logger/bpf/sock.h"

void fprint_ip4(FILE* file, uint32_t addr, uint16_t port) {
  const uint8_t* data = (uint8_t*)&addr;
  fprintf(file, "%u.%u.%u.%u:%u", data[0], data[1], data[2], data[3], port);
}

void fprint_ip6(FILE* file, const uint8_t* addr, uint16_t port) {
  char buffer[36];
  if (!inet_ntop(AF_INET6, addr, buffer, sizeof(buffer))) return;
  fprintf(file, "%s:%u", buffer, port);
}

void fprint_sys_sock(FILE* file, const struct sys_sock* sys_sock) {
  if (sys_sock->event_type == SYS_CONNECT) {
    fprintf(file, "event: sys_connect\nsaddr: ");
  } else if (sys_sock->event_type == SYS_ACCEPT) {
    fprintf(file, "event: sys_accept\nsaddr: ");
  } else if (sys_sock->event_type == SYS_ACCEPT4) {
    fprintf(file, "event: sys_accept4\nsaddr: ");
  } else {
    return;
  }
  if (sys_sock->family == AF_INET) {
    struct sys_sock4* sys_sock4 = (struct sys_sock4*)sys_sock;
    fprint_ip4(file, sys_sock4->saddr, sys_sock4->sport);
    fprintf(file, "\ndaddr: ");
    fprint_ip4(file, sys_sock4->daddr, ntohs(sys_sock4->dport));
  } else if (sys_sock->family == AF_INET6) {
    struct sys_sock6* sys_sock6 = (struct sys_sock6*)sys_sock;
    fprint_ip6(file, sys_sock6->saddr, sys_sock6->sport);
    fprintf(file, "\ndaddr: ");
    fprint_ip6(file, sys_sock6->daddr, ntohs(sys_sock6->dport));
  } else {
    return;
  }
  fprintf(file, "\nerror: 0x%x\nret: %d\nstate: %u\n", sys_sock->error,
          sys_sock->ret, sys_sock->state);
  const struct protoent* protocol = getprotobynumber(sys_sock->protocol);
  if (protocol) fprintf(file, "protocol: %s\n", protocol->p_name);
  else fprintf(file, "protocol: %d\n", sys_sock->protocol);
  fprint_task(file, &sys_sock->task);
  fputc('\n', file);
}

int sys_sock_cb(void* ctx UNUSED, void* data, size_t data_sz UNUSED) {
  FILE* file = fopen(*(const char**)ctx, "a");
  if (file) {
    fprint_sys_sock(file, data);
    fclose(file);
  } else {
    fprint_sys_sock(stdout, data);
  }
  return 0;
}
