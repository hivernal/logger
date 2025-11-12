/* Interface for manipulating BPF applicaton. */

#ifndef LOGGER_BPF_H_
#define LOGGER_BPF_H_

struct bpf;

struct bpf_opts {
  const char* log_dir;

  const char* sys_execve_log;
  int sys_execve_enable;
  int sys_execveat_enable;
  const char* hash_alg;

  const char* sys_write_log;
  int sys_write_enable;
  int sys_pwrite64_enable;
  int sys_writev_enable;
  int sys_pwritev_enable;
  int sys_pwritev2_enable;

  const char* sys_read_log;
  int sys_read_enable;
  int sys_pread64_enable;
  int sys_readv_enable;
  int sys_preadv_enable;
  int sys_preadv2_enable;

  const char* sys_unlink_log;
  int sys_unlink_enable;
  int sys_unlinkat_enable;

  const char* sys_chmod_log;
  int sys_chmod_enable;
  int sys_fchmod_enable;
  int sys_fchmodat_enable;
  int sys_fchmodat2_enable;

  const char* sys_chown_log;
  int sys_chown_enable;
  int sys_fchown_enable;
  int sys_lchown_enable;
  int sys_fchownat_enable;

  const char* sys_rename_log;
  int sys_rename_enable;
  int sys_renameat_enable;
  int sys_renameat2_enable;

  const char* sys_sock_log;
  int sys_connect_enable;
  int sys_accept_enable;
  int sys_accept4_enable;

  const char* sys_setid_log;
  int sys_setuid_enable;
  int sys_setgid_enable;
  int sys_setreuid_enable;
  int sys_setregid_enable;
  int sys_setresuid_enable;
  int sys_setresgid_enable;
  int sys_setfsuid_enable;
  int sys_setfsgid_enable;

  const char* sys_clone_log;
  int sys_clone_enable;
  int sys_clone3_enable;

  const char* sched_process_exit_log;
  int sched_process_exit_enable;
};

struct bpf* bpf_init(struct bpf_opts* opts);
void bpf_delete(struct bpf* bpf);
int bpf_poll_map_buffers(struct bpf* bpf, int time_ms);

#endif  // LOGGER_BPF_H_
