#include "logger/file.h"

#include <stdio.h>

#include "logger/helpers.h"
#include "logger/bpf/file.h"
#include "logger/diff.h"
#include "logger/text.h"
#include "logger/bpf.h"

/* File flags. file.f_flags. */
#define O_ACCMODE 00000003
/* File read-only. */
#define O_RDONLY 00000000
/* File write-only. */
#define O_WRONLY 00000001
/* File read and write. */
#define O_RDWR 00000002
/* If file doesn't exist, creates it as regular file when opened. */
#define O_CREAT 00000100
/* Ensures that open call will create the file. */
#define O_EXCL 00000200
/*
 * If file refers to a terminal device it will not become the
 * process's controlling terminal even if the process does not have one.
 */
#define O_NOCTTY 00000400
/*
 * If the file already exists and is a regular file and the access mode allows
 * writing (i.e., is O_RDWR or O_WRONLY) it will be truncated to length 0. If
 * the file is a FIFO or terminal device file, the O_TRUNC flag is ignored.
 * Otherwise, the effect of O_TRUNC is unspecified.
 */
#define O_TRUNC 00001000
/* The file is opened in append mode. */
#define O_APPEND 00002000
/*
 * When possible, the file is opened in nonblocking mode.  Neither the open()
 * nor  any  subse‐ quent  I/O  operations  on  the  file  descriptor  which is
 * returned will cause the calling process to wait.
 */
#define O_NONBLOCK 00004000
/*
 * Write operations on the file will complete according to the requirements
 * of synchronized I/O data integrity completion.
 */
#define O_DSYNC 00010000
/*
 * The Linux header file <asm/fcntl.h> doesn't define O_ASYNC; the (BSD-derived)
 * FASYNC synonym  is defined instead.
 * Enables signal-driven I/O: generates a signal (SIGIO by default, but this can
 * be changed  via fcntl(2)) when  input or output becomes possible on the
 * file.
 */
#define FASYNC 00020000
/* For minimizing cache effects of the I/O to and from the file. */
#define O_DIRECT 00040000
/*
 * Allow files whose sizes cannot be represented in an off_t (but can be
 * represented  in an  off64_t) to be opened.
 */
#define O_LARGEFILE 00100000
/* If path is not a directory, causes the open to fail. */
#define O_DIRECTORY 00200000
/*
 * If the trailing component (i.e., basename) of path is a symbolic link, then
 * the open fails, with  the  error ELOOP.
 */
#define O_NOFOLLOW 00400000
/* Do not update the file last access time. */
#define O_NOATIME 01000000
/*
 * Enable the close-on-exec flag for the file descriptor. Specifying this
 * flag permits  a program to avoid additional fcntl(2) F_SETFD operations to
 * set the FD_CLOEXEC flag.
 */
#define O_CLOEXEC 02000000
#define __O_TMPFILE 020000000
/* An unnamed temporary regular file. */
#define O_TMPFILE (__O_TMPFILE | O_DIRECTORY)

void check_f_flags(unsigned f_flag, FILE* file) {
#define CHECK_F_FLAG(value) \
  if ((f_flag & (value)) == (value)) fprintf(file, ", %s (0x%x)", #value, value)

  CHECK_F_FLAG(O_ACCMODE);
  /*
  CHECK_F_FLAG(O_RDONLY);
  CHECK_F_FLAG(O_WRONLY);
  CHECK_F_FLAG(O_RDWR);
  */
  if (f_flag & O_RDWR)
    fprintf(file, ", O_RDWR (0x%x)", O_RDWR);
  else if (f_flag & O_WRONLY)
    fprintf(file, ", O_WRONLY (0x%x)", O_WRONLY);
  else
    fprintf(file, ", O_RDONLY (0x%x)", O_RDONLY);

  CHECK_F_FLAG(O_CREAT);
  CHECK_F_FLAG(O_EXCL);
  CHECK_F_FLAG(O_NOCTTY);
  CHECK_F_FLAG(O_TRUNC);
  CHECK_F_FLAG(O_APPEND);
  CHECK_F_FLAG(O_NONBLOCK);
  CHECK_F_FLAG(O_DSYNC);
  CHECK_F_FLAG(FASYNC);
  CHECK_F_FLAG(O_DIRECT);
  CHECK_F_FLAG(O_LARGEFILE);
  CHECK_F_FLAG(O_DIRECTORY);
  CHECK_F_FLAG(O_NOFOLLOW);
  CHECK_F_FLAG(O_NOATIME);
  CHECK_F_FLAG(O_CLOEXEC);
  CHECK_F_FLAG(O_TMPFILE);

#undef CHECK_F_FLAG
}

/*
 * Flags in file.f_mode. Note that FMODE_READ and FMODE_WRITE must correspond
 * to O_WRONLY and O_RDWR via the strange trick in do_dentry_open().
 */

/* File is open for reading. */
#define FMODE_READ (1 << 0)
/* File is open for writing. */
#define FMODE_WRITE (1 << 1)
/* File is seekable. */
#define FMODE_LSEEK (1 << 2)
/* File can be accessed using pread. */
#define FMODE_PREAD (1 << 3)
/* File can be accessed using pwrite. */
#define FMODE_PWRITE (1 << 4)
/* File is open for execution with sys_execve / sys_uselib. */
#define FMODE_EXEC (1 << 5)
/* File writes are restricted (block device specific). */
#define FMODE_WRITE_RESTRICTED (1 << 6)
/* File supports atomic writes. */
#define FMODE_CAN_ATOMIC_WRITE (1 << 7)
/* 32bit hashes as llseek() offset (for directories). */
#define FMODE_32BITHASH (1 << 9)
/* 64bit hashes as llseek() offset (for directories). */
#define FMODE_64BITHASH (1 << 10)
/*
 * Don't update ctime and mtime. Currently a special hack for the XFS
 * open_by_handle ioctl.
 */
#define FMODE_NOCMTIME (1 << 11)
/* Expect random access pattern. */
#define FMODE_RANDOM (1 << 12)
/* Support IOCB_HAS_METADATA. */
#define FMODE_HAS_METADATA (1 << 13)
/* File is opened with O_PATH; almost nothing can be done with it */
#define FMODE_PATH (1 << 14)
/* File needs atomic accesses to f_pos. */
#define FMODE_ATOMIC_POS (1 << 15)
/* Write access to underlying fs. */
#define FMODE_WRITER (1 << 16)
/* Has read method(s). */
#define FMODE_CAN_READ (1 << 17)
/* Has write method(s). */
#define FMODE_CAN_WRITE (1 << 18)
#define FMODE_OPENED (1 << 19)
#define FMODE_CREATED (1 << 20)
/* File is stream-like. */
#define FMODE_STREAM (1 << 21)
/* File supports DIRECT IO. */
#define FMODE_CAN_ODIRECT (1 << 22)
#define FMODE_NOREUSE (1 << 23)
/* File is embedded in backing_file object. */
#define FMODE_BACKING (1 << 24)
/*
 * Together with FMODE_NONOTIFY_PERM defines which fsnotify events shouldn't be
 * generated.
 */
#define FMODE_NONOTIFY (1 << 25)
/*
 * Together with FMODE_NONOTIFY defines which fsnotify events shouldn't be
 * generated
 */
#define FMODE_NONOTIFY_PERM (1 << 26)
/* File is capable of returning -EAGAIN if I/O will block. */
#define FMODE_NOWAIT (1 << 27)
/* File represents mount that needs unmounting */
#define FMODE_NEED_UNMOUNT (1 << 28)
/* File does not contribute to nr_files count */
#define FMODE_NOACCOUNT (1 << 29)

void check_f_mode(unsigned f_mode, FILE* file) {
#define CHECK_F_MODE(value) \
  if (f_mode & (value)) fprintf(file, ", %s (0x%x)", #value, value);

  CHECK_F_MODE(FMODE_READ);
  CHECK_F_MODE(FMODE_WRITE);
  CHECK_F_MODE(FMODE_LSEEK);
  CHECK_F_MODE(FMODE_PREAD);
  CHECK_F_MODE(FMODE_PWRITE);
  CHECK_F_MODE(FMODE_EXEC);
  CHECK_F_MODE(FMODE_WRITE_RESTRICTED);
  CHECK_F_MODE(FMODE_CAN_ATOMIC_WRITE);
  CHECK_F_MODE(FMODE_32BITHASH);
  CHECK_F_MODE(FMODE_64BITHASH);
  CHECK_F_MODE(FMODE_NOCMTIME);
  CHECK_F_MODE(FMODE_RANDOM);
  CHECK_F_MODE(FMODE_HAS_METADATA);
  CHECK_F_MODE(FMODE_PATH);
  CHECK_F_MODE(FMODE_ATOMIC_POS);
  CHECK_F_MODE(FMODE_WRITER);
  CHECK_F_MODE(FMODE_CAN_READ);
  CHECK_F_MODE(FMODE_CAN_WRITE);
  CHECK_F_MODE(FMODE_OPENED);
  CHECK_F_MODE(FMODE_CREATED);
  CHECK_F_MODE(FMODE_STREAM);
  CHECK_F_MODE(FMODE_CAN_ODIRECT);
  CHECK_F_MODE(FMODE_NOREUSE);
  CHECK_F_MODE(FMODE_BACKING);
  CHECK_F_MODE(FMODE_NONOTIFY);
  CHECK_F_MODE(FMODE_NONOTIFY_PERM);
  CHECK_F_MODE(FMODE_NOWAIT);
  CHECK_F_MODE(FMODE_NEED_UNMOUNT);
  CHECK_F_MODE(FMODE_NOACCOUNT);

#undef CHECK_F_MODE
}

int diff_cmp(const void* a, int i, const void* b, int j) {
  const char* const* strs1 = a;
  const char* const* strs2 = b;
  const char* str1 = strs1[i];
  const char* str2 = strs2[j];
  for (; *str1 && (*str1 != '\n') && (*str1 == *str2); ++str1, ++str2);
  return (int)(*str1 - *str2);
}

void diff_add(const void* a, int i, void* data) {
  FILE* file = data;
  if (!file) file = stdout;
  const char* const* strs = a;
  const char* str = strs[i];
  fprintf(file, "+ ");
  while (*str && (*str != '\n')) {
    fputc(*str, file);
    ++str;
  }
  fputc('\n', file);
}

void diff_del(const void* a, int i, void* data UNUSED) {
  FILE* file = data;
  if (!file) file = stdout;
  const char* const* strs = a;
  const char* str = strs[i];
  fprintf(file, "- ");
  while (*str && (*str != '\n')) {
    fputc(*str, file);
    ++str;
  }
  fputc('\n', file);
}

static const struct diff_callbacks diff_callbacks UNUSED = {
    .cmp = diff_cmp, .add = diff_add, .del = diff_del};

void fprint_diff_files(FILE* file, struct users_groups* users_groups,
                       struct text* text, int file_type) {
  if (!text) return;
  fprintf(file, "diff:\n");
  struct text** text_old_ptr;
  pthread_mutex_t* mutex;
  if (file_type == FILE_TYPE_GROUP) {
    text_old_ptr = &users_groups->group.text;
    mutex = &users_groups->group.mutex;
  } else if (file_type == FILE_TYPE_PASSWD) {
    text_old_ptr = &users_groups->passwd.text;
    mutex = &users_groups->passwd.mutex;
  } else if (file_type == FILE_TYPE_SUDOERS) {
    text_old_ptr = &users_groups->sudoers.text;
    mutex = &users_groups->sudoers.mutex;
  } else if (file_type == FILE_TYPE_DOAS) {
    text_old_ptr = &users_groups->doas.text;
    mutex = &users_groups->doas.mutex;
  } else {
    return;
  }
  struct text* text_old = *text_old_ptr;
  pthread_mutex_lock(mutex);
  diff(text_old->lines, (int)text_old->lines_size, text->lines,
       (int)text->lines_size, &diff_callbacks, file);
  text_delete(text_old);
  pthread_mutex_unlock(mutex);
  *text_old_ptr = text;
}

void fprint_sys_write(FILE* file, const struct sys_write* sys_write,
                      struct sys_write_rename_cb_data* data) {
  fprintf(file,
          "event: sys_write\npath: %s\ncount: %lu\nret: %d\nf_pos: "
          "%ld\nerror: 0x%x\nf_flags: 0x%x",
          sys_write->file.data + sys_write->file.offset, sys_write->count,
          sys_write->ret, sys_write->f_pos, sys_write->error,
          sys_write->f_flags);
  // check_f_flags(sys_write->f_flags, file);
  fprintf(file, "\nf_mode: 0x%x", sys_write->f_mode);
  // check_f_mode(sys_write->f_mode, file);
  fputc('\n', file);
  if (sys_write->file_type != FILE_TYPE_OTHER) {
    struct text* text =
        text_buffer_init(sys_write->buffer, (size_t)sys_write->ret);
    fprint_diff_files(file, data->users_groups, text, sys_write->file_type);
  }
  fprint_task(file, &sys_write->task);
  fputc('\n', file);
}

int sys_write_cb(void* ctx, void* data, size_t data_sz UNUSED) {
  FILE* file = fopen(((struct sys_write_rename_cb_data*)ctx)->filename, "a");
  if (file) {
    fprint_sys_write(file, data, ctx);
    fclose(file);
  } else {
    fprint_sys_write(stdout, data, ctx);
  }
  return 0;
}

void fprint_sys_read(FILE* file, const struct sys_read* sys_read) {
  fprintf(file,
          "event: sys_read\npath: %s\ncount: %lu\nret: %d\nf_pos: "
          "%ld\nerror: 0x%x\nf_flags: 0x%x",
          sys_read->file.data + sys_read->file.offset, sys_read->count,
          sys_read->ret, sys_read->f_pos, sys_read->error, sys_read->f_flags);
  // check_f_flags(sys_read->f_flags, file);
  fprintf(file, "\nf_mode: 0x%x", sys_read->f_mode);
  // check_f_mode(sys_read->f_mode, file);
  fputc('\n', file);
  fprint_task(file, &sys_read->task);
  fputc('\n', file);
}

int sys_read_cb(void* ctx UNUSED, void* data, size_t data_sz UNUSED) {
  FILE* file = fopen(*(const char**)ctx, "a");
  if (file) {
    fprint_sys_read(file, data);
    fclose(file);
  } else {
    fprint_sys_read(stdout, data);
  }
  return 0;
}

void fprint_sys_unlink(FILE* file, const struct sys_unlink* sys_unlink) {
  if (sys_unlink->event_type == SYS_UNLINK) {
    fprintf(file, "event: sys_unlink\npath: ");
  } else if (sys_unlink->event_type == SYS_UNLINKAT) {
    fprintf(file, "event: sys_unlinkat\npath: ");
  } else {
    return;
  }
  if (sys_unlink->filename_type == PATH_ABSOLUTE) {
    fprintf(file, "%s", sys_unlink->filename);
  } else {
    const struct sys_unlinkat* sys_unlinkat = (struct sys_unlinkat*)sys_unlink;
    fprint_relative_filename(file, sys_unlink->filename, &sys_unlinkat->dir);
  }
  fprintf(file, "\nret: %d\nflags: %d\nerror: 0x%x\n", sys_unlink->ret,
          sys_unlink->flags, sys_unlink->error);
  fprint_task(file, &sys_unlink->task);
  fputc('\n', file);
}

int sys_unlink_cb(void* ctx UNUSED, void* data, size_t data_sz UNUSED) {
  FILE* file = fopen(*(const char**)ctx, "a");
  if (file) {
    fprint_sys_unlink(file, data);
    fclose(file);
  } else {
    fprint_sys_unlink(stdout, data);
  }
  return 0;
}

void fprint_sys_chmod(FILE* file, const struct sys_chmod* sys_chmod) {
  if (sys_chmod->event_type == SYS_CHMOD) {
    fprintf(file, "event: sys_chmod\npath: ");
  } else if (sys_chmod->event_type == SYS_FCHMOD) {
    fprintf(file, "event: sys_fchmod\npath: ");
  } else if (sys_chmod->event_type == SYS_FCHMODAT) {
    fprintf(file, "event: sys_fchmodat\npath: ");
  } else if (sys_chmod->event_type == SYS_FCHMODAT2) {
    fprintf(file, "event: sys_fchmodat2\npath: ");
  } else {
    return;
  }
  if (sys_chmod->filename_type == PATH_ABSOLUTE) {
    fprintf(file, "%s", sys_chmod->filename);
  } else if (sys_chmod->filename_type == PATH_ABSOLUTE_FD) {
    const struct sys_fchmod* sys_fchmod = (struct sys_fchmod*)sys_chmod;
    fprintf(file, "%s", sys_fchmod->file.data + sys_fchmod->file.offset);
  } else {
    const struct sys_fchmodat* sys_fchmodat = (struct sys_fchmodat*)sys_chmod;
    fprint_relative_filename(file, sys_chmod->filename, &sys_fchmodat->dir);
  }
  fprintf(file, "\nret: %d\nflags: %d\nmode: %.4o\nerror: 0x%x\n",
          sys_chmod->ret, sys_chmod->flags, sys_chmod->mode, sys_chmod->error);
  fprint_task(file, &sys_chmod->task);
  fputc('\n', file);
}

int sys_chmod_cb(void* ctx UNUSED, void* data, size_t data_sz UNUSED) {
  FILE* file = fopen(*(const char**)ctx, "a");
  if (file) {
    fprint_sys_chmod(file, data);
    fclose(file);
  } else {
    fprint_sys_chmod(stdout, data);
  }
  return 0;
}

void fprint_sys_chown(FILE* file, const struct sys_chown* sys_chown) {
  if (sys_chown->event_type == SYS_CHOWN) {
    fprintf(file, "event: sys_chown\npath: ");
  } else if (sys_chown->event_type == SYS_FCHOWN) {
    fprintf(file, "event: sys_fchown\npath: ");
  } else if (sys_chown->event_type == SYS_FCHOWNAT) {
    fprintf(file, "event: sys_fchownat\npath: ");
  } else {
    return;
  }
  if (sys_chown->filename_type == PATH_ABSOLUTE) {
    fprintf(file, "%s", sys_chown->filename);
  } else if (sys_chown->filename_type == PATH_ABSOLUTE_FD) {
    const struct sys_fchown* sys_fchown = (struct sys_fchown*)sys_chown;
    fprintf(file, "%s", sys_fchown->file.data + sys_fchown->file.offset);
  } else {
    const struct sys_fchownat* sys_fchownat = (struct sys_fchownat*)sys_chown;
    fprint_relative_filename(file, sys_chown->filename, &sys_fchownat->dir);
  }
  fprintf(file,
          "\nret: %d\nflags: %d\ntarget_uid: %u\ntarget_gid: %u\nerror: 0x%x\n",
          sys_chown->ret, sys_chown->flags, sys_chown->uid, sys_chown->gid,
          sys_chown->error);
  fprint_task(file, &sys_chown->task);
  fputc('\n', file);
}

int sys_chown_cb(void* ctx UNUSED, void* data, size_t data_sz UNUSED) {
  FILE* file = fopen(*(const char**)ctx, "a");
  if (file) {
    fprint_sys_chown(file, data);
    fclose(file);
  } else {
    fprint_sys_chown(stdout, data);
  }
  return 0;
}

int strcmp(const char* s1, const char* s2) {
  // if (!s1 || !s2) return -256;
  for (; *s1 && (*s1 == *s2); ++s1, ++s2);
  char c1 = *s1, c2 = *s2;
  return (int)(c1 - c2);
}

/* Compares strings. Returns 0 if s1 contains s2. */
int strcmp_contains(const char* s1, const char* s2) {
  // if (!s1 || !s2) return -256;
  for (; *s1 && (*s1 == *s2); ++s1, ++s2);
  char c1 = *s1, c2 = *s2;
  if (!c2) return 0;
  return (int)(c1 - c2);
}

struct dentry_range* strcmp_dentry_ranges(const struct list_head* list,
                                          const char* s) {
  struct dentry_range* c;
  list_for_each_entry(c, list, node) {
    const char *ptr = c->start, *end = c->end;
    for (; (ptr <= end) && (*ptr == *s); ++ptr, ++s);
    if (!(*s)) return c;
    if (ptr <= end) return NULL;
  }
  return NULL;
}

int get_file_type(const char* filename, size_t size) {
  size_t offset = sizeof("/etc/") - 1;
  if (offset >= size) return FILE_TYPE_OTHER;
  if (strcmp_contains(filename, "/etc/") != 0) return FILE_TYPE_OTHER;
  // size -= offset;
  if (strcmp(&filename[offset], "passwd") == 0) return FILE_TYPE_PASSWD;
  if (strcmp(&filename[offset], "group") == 0) return FILE_TYPE_GROUP;
  if (strcmp(&filename[offset], "doas.conf") == 0) return FILE_TYPE_DOAS;
  if (strcmp(&filename[offset], "sudoers") == 0) return FILE_TYPE_SUDOERS;
  if (strcmp_contains(&filename[offset], "sudoers.d/") == 0)
    return FILE_TYPE_SUDOERS_DIR;
  return FILE_TYPE_OTHER;
}

int get_dentry_ranges_file_type(const struct list_head* list) {
  if (strcmp_dentry_ranges(list, "/etc/passwd")) return FILE_TYPE_PASSWD;
  if (strcmp_dentry_ranges(list, "/etc/group")) return FILE_TYPE_GROUP;
  if (strcmp_dentry_ranges(list, "/etc/doas.conf")) return FILE_TYPE_DOAS;
  if (strcmp_dentry_ranges(list, "/etc/sudoers")) return FILE_TYPE_SUDOERS;
  if (strcmp_dentry_ranges(list, "/etc/sudoers.d/"))
    return FILE_TYPE_SUDOERS_DIR;
  return FILE_TYPE_OTHER;
}

int fprint_sys_renameat(FILE* file, const struct sys_renameat* sys_renameat,
                        const char** newdir) {
  const struct sys_rename* sys_rename = &sys_renameat->sys_rename;
  if (sys_rename->oldname_type == PATH_ABSOLUTE) {
    fprintf(file, "%s\nnewpath: ", sys_rename->oldname);
    struct list_head list = LIST_HEAD_INIT(list);
    int newfile_type = FILE_TYPE_OTHER;
    if (!dentry_ranges_init(&list, sys_rename->newname, &sys_renameat->dir)) {
      newfile_type = get_dentry_ranges_file_type(&list);
      fprint_dentry_ranges(file, &list);
      *newdir = sys_renameat->dir.data + sys_renameat->dir.offset;
    }
    dentry_ranges_delete(&list);
    return newfile_type;
  }
  fprint_relative_filename(file, sys_rename->oldname, &sys_renameat->dir);
  fprintf(file, "\nnewpath: %s", sys_rename->newname);
  return get_file_type(sys_rename->newname, sizeof(sys_rename->newname));
}

int fprint_sys_renameat2(FILE* file, const struct sys_renameat2* sys_renameat2,
                         const char** newdir) {
  const struct sys_rename* sys_rename = &sys_renameat2->sys_rename;
  fprint_relative_filename(file, sys_rename->oldname, &sys_renameat2->olddir);
  fprintf(file, "\nnewpath: ");
  struct list_head list = LIST_HEAD_INIT(list);
  int newfile_type = FILE_TYPE_OTHER;
  if (!dentry_ranges_init(&list, sys_rename->newname, &sys_renameat2->newdir)) {
    newfile_type = get_dentry_ranges_file_type(&list);
    fprint_dentry_ranges(file, &list);
    *newdir = sys_renameat2->newdir.data + sys_renameat2->newdir.offset;
  }
  dentry_ranges_delete(&list);
  return newfile_type;
}

void fprint_sys_rename(FILE* file, const struct sys_rename* sys_rename,
                       struct sys_write_rename_cb_data* data) {
  if (sys_rename->event_type == SYS_RENAME) {
    fprintf(file, "event: sys_rename\noldpath: ");
  } else if (sys_rename->event_type == SYS_RENAMEAT) {
    fprintf(file, "event: sys_renameat\noldpath: ");
  } else if (sys_rename->event_type == SYS_RENAMEAT2) {
    fprintf(file, "event: sys_renameat2\noldpath: ");
  } else {
    return;
  }
  int file_type = FILE_TYPE_OTHER;
  const char* newdir = NULL;
  if (sys_rename->oldname_type == PATH_ABSOLUTE &&
      sys_rename->newname_type == PATH_ABSOLUTE) {
    fprintf(file, "%s\nnewpath: %s", sys_rename->oldname, sys_rename->newname);
    file_type = get_file_type(sys_rename->newname, sizeof(sys_rename->newname));
  } else if (sys_rename->oldname_type == PATH_RELATIVE_FD &&
             sys_rename->newname_type == PATH_RELATIVE_FD) {
    file_type =
        fprint_sys_renameat2(file, (struct sys_renameat2*)sys_rename, &newdir);
  } else {
    file_type =
        fprint_sys_renameat(file, (struct sys_renameat*)sys_rename, &newdir);
  }
  fprintf(file, "\nfile_type: %d\nret: %d\nflags: %d\nerror: 0x%x\n", file_type,
          sys_rename->ret, sys_rename->flags, sys_rename->error);
  if (sys_rename->ret >= 0 && file_type != FILE_TYPE_OTHER) {
    struct text* text = text_dir_filename_init(newdir, sys_rename->newname);
    fprint_diff_files(file, data->users_groups, text, file_type);
  }
  fprint_task(file, &sys_rename->task);
  fputc('\n', file);
}

int sys_rename_cb(void* ctx, void* data, size_t data_sz UNUSED) {
  FILE* file = fopen(((struct sys_write_rename_cb_data*)ctx)->filename, "a");
  if (file) {
    fprint_sys_rename(file, data, ctx);
    fclose(file);
  } else {
    fprint_sys_rename(stdout, data, ctx);
  }
  return 0;
}
