#ifndef LOGGER_BPF_HELPERS_H_
#define LOGGER_BPF_HELPERS_H_

#define AT_FDCWD -100

/* Fills task structure (uid, gid, tgid, pid, ppid, time_nsec, comm). */
int fill_task(struct task* task);

/* Gets path structure from file descriptor fd. Returns i_mode of parent
 * structure file on success, other on errors. */
int get_path_from_fd(int fd, struct path* path);

/* Gets file structure from file descriptor fd. Returns 0 on success, other on
 * errors. */
int get_file_from_fd(int fd, struct file** file);

/* Parses list of dentries from path. Writes from end to start path_name->data.
 * Returns offset of first byte or negative on errors. */
int read_path_name(const struct path* path, struct path_name* path_name,
                   int is_dir);

#endif  // LOGGER_BPF_HELPERS_H_
