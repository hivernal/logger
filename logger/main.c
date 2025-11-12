#include "bpf.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>

#define HELP                                                                   \
  "Usage: system_logger [OPTION]...\n"                                         \
  "--hash_alg=ALG\t\t\tSets the hash algorithm for sys_execve and\n"           \
  "\t\t\t\tsys_execve_events. 0 - hash is disabled.\n"                         \
  "--EVENT_enable=INT\t\tEnables or disables  EVENT logging. 0 - logging is\n" \
  "\t\t\t\tdisabled, > 0 - logging is enabled. Default all events are\n"       \
  "\t\t\t\tenabled.\n"                                                         \
  "--sys_read_log=FILE\t\tSets the log file for the sys_read, sys_pread64,\n"  \
  "\t\t\t\tsys_readv, sys_preadv, sys_preadv2 events.\n"                       \
  "--sys_write_log=FILE\t\tSets the log file for the sys_write,\n"             \
  "\t\t\t\tsys_pwrite64, sys_writev, sys_pwritev, sys_pwritev2 events.\n"      \
  "--sys_unlink_log=FILE\t\tSets the log file for the sys_unlink,\n"           \
  "\t\t\t\tsys_unlinkat events.\n"                                             \
  "--sys_chmod_log=FILE\t\tSets the log file for the sys_chmod, sys_fchmod,\n" \
  "\t\t\t\tsys_fchmodat, sys_fchmodat2 events.\n"                              \
  "--sys_chown_log=FILE\t\tSets the log file for the sys_chown, sys_fchown,\n" \
  "\t\t\t\tsys_lchown, sys_fchownat events.\n"                                 \
  "--sys_rename_log=FILE\t\tSets the log file for the sys_rename,\n"           \
  "\t\t\t\tsys_renameat, sys_renameat2 events.\n"                              \
  "--sys_sock_log=FILE\t\tSets the log file for the sys_connect, sys_accept\n" \
  "\t\t\t\tsys_accept4 events.\n"                                              \
  "--sys_setid_log=FILE\t\tSets the log file for the sys_setuid,sys_setgid,\n" \
  "\t\t\t\tsys_setreuid, sys_setregid, sys_setresuid, sys_setresgid,\n"        \
  "\t\t\t\tsys_setfsuid, sys_setfsgid events.\n"                               \
  "--sys_execve_log=FILE\t\tSets the log file for the sys_execve,\n"           \
  "\t\t\t\tsys_execveat events.\n"                                             \
  "--sys_clone_log=FILE\t\tSets the log file for the sys_clone, sys_clone3\n"  \
  "\t\t\t\tevents.\n"                                                          \
  "--sched_process_exit_log=FILE\tSets the log file for the\n"                 \
  "\t\t\t\tsched_process_exit events.\n"                                       \
  "EVENT:\n"                                                                   \
  "sys_read, sys_pread64, sys_readv, sys_preadv, sys_preadv2.\n"               \
  "sys_write, sys_pwrite64, sys_writev, sys_pwritev, sys_pwritev2.\n"          \
  "sys_unlink, sys_unlinkat.\n"                                                \
  "sys_chmod, sys_fchmod, sys_fchmodat, sys_fchmodat2.\n"                      \
  "sys_chown, sys_fchown, sys_lchown, sys_fchownat.\n"                         \
  "sys_rename, sys_renameat, sys_renameat2.\n"                                 \
  "sys_connect, sys_accept, sys_accept4.\n"                                    \
  "sys_setuid, sys_setgid, sys_setreuid.\n"                                    \
  "sys_setregid, sys_setresuid, sys_setresgid, sys_setfsuid, sys_setfsgid.\n"  \
  "sys_execve, sys_execveat.\n"                                                \
  "sys_clone, sys_clone3.\n"                                                   \
  "sched_process_exit.\n"                                                      \
  "EXAMPLE:\n"                                                                 \
  "system_logger "                                                             \
  "--sched_process_exit_log=/var/log/system_logger/sched_process_exit.log "    \
  "--hash=sha512 --sys_clone_enable=0\n"

#define HASH_ALG "SHA256"
#define LOG_DIR "/var/log/system_logger/"
#define SYS_EXECVE_LOG "/var/log/system_logger/sys_execve.log"
#define SYS_CLONE_LOG "/var/log/system_logger/sys_clone.log"
#define SCHED_PROCESS_EXIT_LOG "/var/log/system_logger/sched_process_exit.log"
#define SYS_WRITE_LOG "/var/log/system_logger/sys_write.log"
#define SYS_READ_LOG "/var/log/system_logger/sys_read.log"
#define SYS_UNLINK_LOG "/var/log/system_logger/sys_unlink.log"
#define SYS_CHMOD_LOG "/var/log/system_logger/sys_chmod.log"
#define SYS_CHOWN_LOG "/var/log/system_logger/sys_chown.log"
#define SYS_RENAME_LOG "/var/log/system_logger/sys_rename.log"
#define SYS_SETID_LOG "/var/log/system_logger/sys_setid.log"
#define SYS_SOCK_LOG "/var/log/system_logger/sys_sock.log"

/* For capturing signals. */
volatile sig_atomic_t bpf_is_run = 1;

void signal_callback(int sig __attribute__((unused))) { bpf_is_run = 0; }

#define DEFAULT_BPF_OPTS(name)                                              \
  struct bpf_opts name = {.log_dir = LOG_DIR,                               \
                          .sys_read_log = SYS_READ_LOG,                     \
                          .sys_read_enable = 1,                             \
                          .sys_pread64_enable = 1,                          \
                          .sys_readv_enable = 1,                            \
                          .sys_preadv_enable = 1,                           \
                          .sys_preadv2_enable = 1,                          \
                          .sys_write_log = SYS_WRITE_LOG,                   \
                          .sys_write_enable = 1,                            \
                          .sys_pwrite64_enable = 1,                         \
                          .sys_writev_enable = 1,                           \
                          .sys_pwritev_enable = 1,                          \
                          .sys_pwritev2_enable = 1,                         \
                          .sys_unlink_log = SYS_UNLINK_LOG,                 \
                          .sys_unlink_enable = 1,                           \
                          .sys_unlinkat_enable = 1,                         \
                          .sys_chmod_log = SYS_CHMOD_LOG,                   \
                          .sys_chmod_enable = 1,                            \
                          .sys_fchmod_enable = 1,                           \
                          .sys_fchmodat_enable = 1,                         \
                          .sys_fchmodat2_enable = 1,                        \
                          .sys_chown_log = SYS_CHOWN_LOG,                   \
                          .sys_chown_enable = 1,                            \
                          .sys_fchown_enable = 1,                           \
                          .sys_lchown_enable = 1,                           \
                          .sys_fchownat_enable = 1,                         \
                          .sys_rename_log = SYS_RENAME_LOG,                 \
                          .sys_rename_enable = 1,                           \
                          .sys_renameat_enable = 1,                         \
                          .sys_renameat2_enable = 1,                        \
                          .sys_sock_log = SYS_SOCK_LOG,                     \
                          .sys_connect_enable = 1,                          \
                          .sys_accept_enable = 1,                           \
                          .sys_accept4_enable = 1,                          \
                          .sys_setid_log = SYS_SETID_LOG,                   \
                          .sys_setuid_enable = 1,                           \
                          .sys_setgid_enable = 1,                           \
                          .sys_setreuid_enable = 1,                         \
                          .sys_setregid_enable = 1,                         \
                          .sys_setresuid_enable = 1,                        \
                          .sys_setresgid_enable = 1,                        \
                          .sys_setfsuid_enable = 1,                         \
                          .sys_setfsgid_enable = 1,                         \
                          .sys_execve_log = SYS_EXECVE_LOG,                 \
                          .sys_execve_enable = 1,                           \
                          .sys_execveat_enable = 1,                         \
                          .hash_alg = HASH_ALG,                             \
                          .sys_clone_log = SYS_CLONE_LOG,                   \
                          .sys_clone_enable = 1,                            \
                          .sys_clone3_enable = 1,                           \
                          .sched_process_exit_log = SCHED_PROCESS_EXIT_LOG, \
                          .sched_process_exit_enable = 1}

enum {
  help_val = 1,
  sys_read_log_val,
  sys_read_enable_val,
  sys_pread64_enable_val,
  sys_readv_enable_val,
  sys_preadv_enable_val,
  sys_preadv2_enable_val,

  sys_write_log_val,
  sys_write_enable_val,
  sys_pwrite64_enable_val,
  sys_writev_enable_val,
  sys_pwritev_enable_val,
  sys_pwritev2_enable_val,

  sys_unlink_log_val,
  sys_unlink_enable_val,
  sys_unlinkat_enable_val,

  sys_chmod_log_val,
  sys_chmod_enable_val,
  sys_fchmod_enable_val,
  sys_fchmodat_enable_val,
  sys_fchmodat2_enable_val,

  sys_chown_log_val,
  sys_chown_enable_val,
  sys_fchown_enable_val,
  sys_lchown_enable_val,
  sys_fchownat_enable_val,

  sys_rename_log_val,
  sys_rename_enable_val,
  sys_renameat_enable_val,
  sys_renameat2_enable_val,

  sys_sock_log_val,
  sys_connect_enable_val,
  sys_accept_enable_val,
  sys_accept4_enable_val,

  sys_setid_log_val,
  sys_setuid_enable_val,
  sys_setgid_enable_val,
  sys_setreuid_enable_val,
  sys_setregid_enable_val,
  sys_setresuid_enable_val,
  sys_setresgid_enable_val,
  sys_setfsuid_enable_val,
  sys_setfsgid_enable_val,

  sys_execve_log_val,
  sys_execve_enable_val,
  sys_execveat_enable_val,
  hash_alg_val,

  sys_clone_log_val,
  sys_clone_enable_val,
  sys_clone3_enable_val,

  sched_process_exit_log_val,
  sched_process_exit_enable_val,
};

#define LONGOPT(optname) \
  {.name = "" #optname, .has_arg = 1, .val = optname##_val, .flag = NULL}

static const struct option longopts[] = {
    {.name = "help", .has_arg = 0, .val = help_val, .flag = NULL},
    LONGOPT(sys_read_log),
    LONGOPT(sys_read_enable),
    LONGOPT(sys_pread64_enable),
    LONGOPT(sys_readv_enable),
    LONGOPT(sys_preadv_enable),
    LONGOPT(sys_preadv2_enable),

    LONGOPT(sys_write_log),
    LONGOPT(sys_write_enable),
    LONGOPT(sys_pwrite64_enable),
    LONGOPT(sys_writev_enable),
    LONGOPT(sys_pwritev_enable),
    LONGOPT(sys_pwritev2_enable),

    LONGOPT(sys_unlink_log),
    LONGOPT(sys_unlink_enable),
    LONGOPT(sys_unlinkat_enable),

    LONGOPT(sys_chmod_log),
    LONGOPT(sys_chmod_enable),
    LONGOPT(sys_fchmod_enable),
    LONGOPT(sys_fchmodat_enable),
    LONGOPT(sys_fchmodat2_enable),

    LONGOPT(sys_chown_log),
    LONGOPT(sys_chown_enable),
    LONGOPT(sys_fchown_enable),
    LONGOPT(sys_lchown_enable),
    LONGOPT(sys_fchownat_enable),

    LONGOPT(sys_rename_log),
    LONGOPT(sys_rename_enable),
    LONGOPT(sys_renameat_enable),
    LONGOPT(sys_renameat2_enable),

    LONGOPT(sys_sock_log),
    LONGOPT(sys_connect_enable),
    LONGOPT(sys_accept_enable),
    LONGOPT(sys_accept4_enable),

    LONGOPT(sys_setid_log),
    LONGOPT(sys_setuid_enable),
    LONGOPT(sys_setgid_enable),
    LONGOPT(sys_setreuid_enable),
    LONGOPT(sys_setregid_enable),
    LONGOPT(sys_setresuid_enable),
    LONGOPT(sys_setresgid_enable),
    LONGOPT(sys_setfsuid_enable),
    LONGOPT(sys_setfsgid_enable),

    LONGOPT(sys_execve_log),
    LONGOPT(sys_execve_enable),
    LONGOPT(sys_execveat_enable),
    LONGOPT(hash_alg),

    LONGOPT(sys_clone_log),
    LONGOPT(sys_clone_enable),
    LONGOPT(sys_clone3_enable),

    LONGOPT(sched_process_exit_log),
    LONGOPT(sched_process_exit_enable)};

#define IF_LOG(type, name, opts) \
  if (type == name##_val) opts.name = optarg

#define ELSE_IF_LOG(type, name, opts) else IF_LOG(type, name, opts)

#define IF_ENABLE(type, name, opts) \
  if (type == name##_val) opts.name = atoi(optarg)

#define ELSE_IF_ENABLE(type, name, opts) else IF_ENABLE(type, name, opts)

int main(int argc, char* argv[]) {
  signal(SIGTERM, signal_callback);
  signal(SIGINT, signal_callback);
  DEFAULT_BPF_OPTS(bpf_opts);

  for (int type = 0;
       (type = getopt_long_only(argc, argv, "", longopts, NULL)) > 0;) {
    if (type == help_val || type == '?') {
      printf(HELP);
      return 0;
    }
    ELSE_IF_LOG(type, sys_read_log, bpf_opts);
    ELSE_IF_LOG(type, sys_write_log, bpf_opts);
    ELSE_IF_LOG(type, sys_unlink_log, bpf_opts);
    ELSE_IF_LOG(type, sys_chmod_log, bpf_opts);
    ELSE_IF_LOG(type, sys_chown_log, bpf_opts);
    ELSE_IF_LOG(type, sys_rename_log, bpf_opts);
    ELSE_IF_LOG(type, sys_sock_log, bpf_opts);
    ELSE_IF_LOG(type, sys_setid_log, bpf_opts);
    ELSE_IF_LOG(type, sys_execve_log, bpf_opts);
    ELSE_IF_LOG(type, sys_clone_log, bpf_opts);
    ELSE_IF_LOG(type, sched_process_exit_log, bpf_opts);
    ELSE_IF_ENABLE(type, sys_read_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_pread64_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_readv_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_preadv_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_preadv2_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_write_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_pwrite64_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_writev_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_pwritev_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_pwritev2_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_unlink_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_unlinkat_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_chmod_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_fchmod_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_fchmodat_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_fchmodat2_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_chown_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_lchown_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_fchown_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_fchownat_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_rename_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_renameat_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_renameat2_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_connect_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_accept_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_accept4_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_setuid_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_setgid_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_setreuid_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_setregid_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_setresuid_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_setresgid_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_setfsuid_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_setfsgid_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_execve_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_execveat_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_clone_enable, bpf_opts);
    ELSE_IF_ENABLE(type, sys_clone3_enable, bpf_opts);
    else if (type == hash_alg_val) bpf_opts.hash_alg = optarg;
    ELSE_IF_ENABLE(type, sched_process_exit_enable, bpf_opts);
  }

  struct bpf* bpf = bpf_init(&bpf_opts);
  if (!bpf) return 1;

  while (bpf_is_run) {
    if (bpf_poll_map_buffers(bpf, 100)) break;
  }

  bpf_delete(bpf);
  return 0;
}
