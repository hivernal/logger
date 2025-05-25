#ifndef LOGGER_BPF_HELPERS_H_
#define LOGGER_BPF_HELPERS_H_

#define FUNC_INLINE static __always_inline
#define AT_FDCWD -100

enum error {
  ENULLARG = 1,
  EATFDCWD,
  EBPF_PROBE_READ_KERNEL,
  EBPF_PROBE_READ_USER,
  ENAMETOOLONG,
  EDENTRIESTOOMUCH,
  ETASKEMPTY,
  EGETCURRENTCOMM,
};

/* Fills task structure (uid, gid, tgid, pid, ppid, time_nsec, comm). */
int fill_task(struct task* task);

/* Gets path structure from file descriptor fd. Returns i_mode of parent
 * structure file on success, other on errors. */
int get_path_from_fd(int fd, struct path* path);

/* Gets file structure from file descriptor fd. Returns 0 on success, other on
 * errors. */
int get_file_from_fd(int fd, struct file** file);

/* Gets path structure pwd from current task. Returns 0 on success, other on
 * errors. */
int get_task_pwd(struct path* path);

/* Parses list of dentries from path. Writes from end to start path_name->data.
 * Returns offset of first byte or negative on errors. */
int read_path_name(const struct path* path, struct path_name* path_name,
                   int is_dir);

int read_path_name_fd(int fd, struct path_name* path_name, int is_dir);

int read_cwd(struct path_name* path_name);

#endif  // LOGGER_BPF_HELPERS_H_
