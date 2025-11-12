#include "logger/setid.h"
#include "logger/helpers.h"
#include "logger/bpf/setid.h"

void fprint_sys_setid(FILE* file, const struct sys_setid* sys_setid) {
  if (sys_setid->event_type == SYS_SETUID) {
    fprintf(file, "event: sys_setuid\nuid: %u\n", sys_setid->ids[0]);
  } else if (sys_setid->event_type == SYS_SETGID) {
    fprintf(file, "event: sys_setgid\ngid: %u\n", sys_setid->ids[0]);
  } else if (sys_setid->event_type == SYS_SETREUID) {
    fprintf(file, "event: sys_setreuid\nuid: %u\neuid: %u\n",
            sys_setid->ids[0], sys_setid->ids[1]);
  } else if (sys_setid->event_type == SYS_SETREGID) {
    fprintf(file, "event: sys_setregid\ngid: %u\negid: %u\n",
            sys_setid->ids[0], sys_setid->ids[1]);
  } else if (sys_setid->event_type == SYS_SETRESUID) {
    fprintf(file, "event: sys_setresuid\nuid: %u\neuid: %u\nsuid: %u\n",
            sys_setid->ids[0], sys_setid->ids[1], sys_setid->ids[2]);
  } else if (sys_setid->event_type == SYS_SETRESGID) {
    fprintf(file, "event: sys_setresgid\ngid: %u\negid: %u\nsgid: %u\n",
            sys_setid->ids[0], sys_setid->ids[1], sys_setid->ids[2]);
  } else if (sys_setid->event_type == SYS_SETFSUID) {
    fprintf(file, "event: sys_setfsuid\nfsuid: %u\n", sys_setid->ids[0]);
  } else if (sys_setid->event_type == SYS_SETFSGID) {
    fprintf(file, "event: sys_setfsgid\nfsgid: %u\n", sys_setid->ids[0]);
  }
  fprintf(file, "error: 0x%x\nret: %d\n", sys_setid->error,
          sys_setid->ret);
  fprint_task(file, &sys_setid->task);
  fputc('\n', file);
}

int sys_setid_cb(void* ctx, void* data, size_t data_sz UNUSED) {
  FILE* file = fopen(*(const char**)ctx, "a");
  if (file) {
    fprint_sys_setid(file, data);
    fclose(file);
  } else {
    fprint_sys_setid(stdout, data);
  }
  return 0;
}
