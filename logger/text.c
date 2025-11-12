#include "logger/text.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>

#define LINES_RESERVED_DEFAULT 32

void text_delete(struct text* text) {
  /* if (!text) return; */
  if (text->buffer) free(text->buffer);
  if (text->lines) free(text->lines);
  free(text);
}

/*
 * Reallocs array of strings text->lines.
 * Return amount reserved lines in case of success and a -1 in case of failures.
 */
size_t check_update_lines_reserved(struct text* text) {
  if (text->lines_size >= text->lines_reserved) {
    text->lines_reserved <<= 1;
    const char** new_lines =
        realloc(text->lines, sizeof(const char*) * text->lines_reserved);
    if (!new_lines) return 0;
    text->lines = new_lines;
  }
  return text->lines_reserved;
}

/*
long text_file_read_lines(struct text* text, FILE* file, char* buffer, size_t
size) { long pos = ftell(file); if (pos == -1) return pos; clearerr(file); const
char* newl; while ((newl = fgets(buffer + pos, (int)(size - (size_t)pos + 1),
file))) { if (!check_update_lines_reserved(text)) return -1;
    text->lines[text->lines_size] = newl;
    ++text->lines_size;
    pos = ftell(file);
    if (pos == -1) return pos;
  }
  if (feof(file)) return pos;
  return -1;
}
*/

/*
 * Reads file line by line and fills text->lines array.
 * Returns number of lines in case of success and a 0 in case of failures.
 * Note: it doesn't check buffer size.
 */
size_t text_file_read_lines(struct text* text, FILE* file) {
  clearerr(file);
  char* buffer = text->buffer;
  text->lines[text->lines_size++] = buffer;
  for (; (*buffer = (char)fgetc(file)) != EOF; ++buffer) {
    if (*buffer != '\n') continue;
    *buffer = '\0';
    int symb;
    while ((symb = fgetc(file)) == '\n');
    if (symb == EOF) break;
    if (!check_update_lines_reserved(text)) return 0;
    *(++buffer) = (char)symb;
    text->lines[text->lines_size++] = buffer;
  }
  text->buffer_size = (size_t)(buffer - text->buffer + 1);
  return text->lines_size;
}

struct text* text_file_init(FILE* file) {
  if (fseek(file, 0, SEEK_END)) return NULL;
  long file_size = ftell(file);
  if (file_size == -1 || fseek(file, 0, SEEK_SET)) return NULL;
  struct text* text = malloc(sizeof(struct text));
  if (!text) return NULL;
  text->buffer = malloc((size_t)file_size + 1);
  text->buffer[file_size] = '\0';
  if (!text->buffer) goto clean;
  text->buffer_size = (size_t)file_size + 1;
  text->buffer_const = text->buffer;
  text->lines_reserved = LINES_RESERVED_DEFAULT;
  text->lines_size = 0;
  text->lines = malloc(sizeof(const char*) * LINES_RESERVED_DEFAULT);
  if (!text->lines) goto clean;
  if (!text_file_read_lines(text, file)) goto clean;
  return text;
clean:
  text_delete(text);
  return NULL;
}

struct text* text_filename_init(const char* filename) {
  FILE* file = fopen(filename, "r");
  if (!file) return NULL;
  struct text* text = text_file_init(file);
  fclose(file);
  return text;
}

struct text* text_dir_filename_init(const char* dirname, const char* filename) {
  if (!dirname) return text_filename_init(filename);
  int dfd = open(dirname, O_RDONLY);
  if (dfd < 0) return NULL;
  int fd = openat(dfd, filename, O_RDONLY);
  if (fd < 0) return NULL;
  FILE* file = fdopen(fd, "r");
  if (!file) return NULL;
  struct text* text = text_file_init(file);
  fclose(file);
  return text;
}

/*
 * Reads const buffer line by line and fills text->lines array.
 * Returns amount of lines in text in case of success
 * and a 0 in case of failures.
 */
size_t text_buffer_read_lines_const(struct text* text, const char* buffer) {
  text->lines[text->lines_size++] = buffer;
  for (; *buffer; ++buffer) {
    if (*buffer == '\n' && *(buffer + 1) != '\0') {
      if (!check_update_lines_reserved(text)) return 0;
      text->lines[text->lines_size] = ++buffer;
      ++text->lines_size;
    }
  }
  return text->lines_size;
}

/*
 * Reads buffer line by line and fills text->lines array.
 * Returns amount of lines in text in case of success
 * and a 0 in case of failures.
 * Note: it doesn't check buffer size.
 */
size_t text_buffer_read_lines(struct text* text, const char* buffer_const) {
  char* buffer = text->buffer;
  text->lines[text->lines_size++] = buffer;
  for (; (*buffer = *buffer_const); ++buffer_const, ++buffer) {
    if (*buffer_const != '\n') continue;
    *buffer = '\0';
    while (*(++buffer_const) == '\n');
    if (!(*buffer_const)) break;
    if (!check_update_lines_reserved(text)) return 0;
    *(++buffer) = *buffer_const;
    text->lines[text->lines_size++] = buffer;
  }
  text->buffer_size = (size_t)(buffer - text->buffer + 1);
  return text->lines_size;
}

/*
 * Generic function for allocating text structure from given buffer
 * and filling struct members to default values.
 * Returns pointer to text in case of success and a NULL in case of failures.
 */
struct text* text_buffer_generic_init(const char* buffer, size_t size) {
  if (!buffer) return NULL;
  struct text* text = malloc(sizeof(struct text));
  if (!text) return NULL;
  text->buffer = NULL;
  text->buffer_size = size;
  text->lines_reserved = LINES_RESERVED_DEFAULT;
  text->lines_size = 0;
  text->lines = malloc(sizeof(const char*) * LINES_RESERVED_DEFAULT);
  if (!text->lines) goto clean;
  return text;
clean:
  text_delete(text);
  return NULL;
}

struct text* text_buffer_init(const char* buffer, size_t size) {
  struct text* text = text_buffer_generic_init(buffer, size);
  if (!text) return NULL;
  text->buffer = malloc(size * sizeof(char));
  text->buffer[size - 1] = '\0';
  if (!text->buffer) goto clean;
  if (!memcpy(text->buffer, buffer, size)) goto clean;
  if (!text_buffer_read_lines(text, text->buffer)) goto clean;
  text->buffer_const = text->buffer;
  return text;
clean:
  text_delete(text);
  return NULL;
}

struct text* text_buffer_const_init(const char* buffer, size_t size) {
  struct text* text = text_buffer_generic_init(buffer, size);
  if (!text) return NULL;
  text->buffer_const = buffer;
  if (!text_buffer_read_lines_const(text, buffer)) goto clean;
  return text;
clean:
  text_delete(text);
  return NULL;
}

/*
char* text_realloc_buffer(struct text* text, size_t size) {
  char* buffer_new = realloc(text->buffer, size);
  if (!buffer_new) return NULL;
  if (!text->buffer) {
    memcpy(buffer_new, text->buffer_const, text->buffer_size);
  }
  buffer_new[size - 1] = '\0';
  text->buffer_size = size;
  if (buffer_new == text->buffer) return buffer_new;
  text->buffer = buffer_new;
  text->buffer_const = buffer_new;
  text->lines_size = 0;
  // if (!text_buffer_read_lines(text, buffer_new)) return NULL;
  return buffer_new;
}
*/
