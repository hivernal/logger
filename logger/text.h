#ifndef LOGGER_TEXT_H_
#define LOGGER_TEXT_H_

#include <stdio.h>
#include <stddef.h>

struct text {
  size_t buffer_size;
  size_t lines_size;
  size_t lines_reserved;
  const char** lines;
  const char* buffer_const;
  char* buffer;
};

/*
 * Reads file and fills text structure.
 * Returns pointer to text in case of success and a NULL in case of failures.
 */
struct text* text_file_init(FILE* file);

/*
 * Reads filename file and fills text structure.
 * Returns pointer to text in case of success and a NULL in case of failures.
 */
struct text* text_filename_init(const char* filename);

/*
 * Reads filename file from dirname directory and fills text structure.
 * Returns pointer to text in case of success and a NULL in case of failures.
 */
struct text* text_dir_filename_init(const char* dirname, const char* filename);

/*
 * Reads buffer and fills text structure.
 * Returns pointer to text in case of success and a NULL in case of failures.
 */
struct text* text_buffer_init(const char* buffer, size_t size);

/*
 * Reads constant buffer and fills text structure.
 * Doesn't allocate text->buffer,
 * but only sets text->buffer_const to given buffer.
 * Returns a pointer to text in case of success and a NULL in case of failures.
 */
struct text* text_buffer_const_init(const char* buffer, size_t size);

/*
 * Reallocates text->buffer to given size.
 * Sets text->lines values to new buffer
 * if buffer has been moved after reallocating
 * Returns pointer to new buffer in case of success
 * and a NULL in case of failures.
 */
char* text_realloc_buffer(struct text* text, size_t size);

/* Releases text members and text pointer. */
void text_delete(struct text* text);

#endif  // LOGGER_TEXT_H_
