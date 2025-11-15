#include "logger/setid.h"
#include "logger/helpers.h"
#include "logger/bpf/setid.h"

void fprint_sys_setid(FILE* file, const struct sys_setid* sys_setid) {
  if (sys_setid->event_type == SYS_SETUID) {
    fprintf(file, "event: sys_setuid\ntarget_uid: %u\n", sys_setid->ids[0]);
  } else if (sys_setid->event_type == SYS_SETGID) {
    fprintf(file, "event: sys_setgid\ntarget_gid: %u\n", sys_setid->ids[0]);
  } else if (sys_setid->event_type == SYS_SETREUID) {
    fprintf(file, "event: sys_setreuid\ntarget_uid: %u\ntarget_euid: %u\n",
            sys_setid->ids[0], sys_setid->ids[1]);
  } else if (sys_setid->event_type == SYS_SETREGID) {
    fprintf(file, "event: sys_setregid\ntarget_gid: %u\ntarget_egid: %u\n",
            sys_setid->ids[0], sys_setid->ids[1]);
  } else if (sys_setid->event_type == SYS_SETRESUID) {
    fprintf(file,
            "event: sys_setresuid\ntarget_uid: %u\netarget_uid: "
            "%u\ntarget_suid: %u\n",
            sys_setid->ids[0], sys_setid->ids[1], sys_setid->ids[2]);
  } else if (sys_setid->event_type == SYS_SETRESGID) {
    fprintf(file,
            "event: sys_setresgid\ntarget_gid: %u\ntarget_egid: "
            "%u\ntarget_sgid: %u\n",
            sys_setid->ids[0], sys_setid->ids[1], sys_setid->ids[2]);
  } else if (sys_setid->event_type == SYS_SETFSUID) {
    fprintf(file, "event: sys_setfsuid\ntarget_fsuid: %u\n", sys_setid->ids[0]);
  } else if (sys_setid->event_type == SYS_SETFSGID) {
    fprintf(file, "event: sys_setfsgid\ntarget_fsgid: %u\n", sys_setid->ids[0]);
  }
  fprintf(file, "error: 0x%x\nret: %d\n", sys_setid->error, sys_setid->ret);
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
