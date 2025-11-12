#ifndef LOGGER_HASH_H_
#define LOGGER_HASH_H_

#include <openssl/evp.h>

struct hash {
  EVP_MD_CTX* ctx;
  EVP_MD* md;
  int len;
};

/*
 * Initializes hash via algorithm alg.
 * Returns pointer to hash in case of a success and a NULL in case of a
 * failures.
 * */
struct hash* hash_init(const char* alg);

/*
 * Initializes hash->ctx and hash->md.
 * Returns 0 in case of a success and a 0 in case of a failures.
 */
int hash_ctx_md_init(struct hash* hash, const char* alg);

/* Frees hash->ctx and hash->md. Doesn't free hash */
void hash_delete(struct hash* hash);

/* Frees hash->ctx, hash->md and hash. */
void hash_delete_ptr(struct hash* hash);

/* Gets hash of the file. */
unsigned char* hash_file(FILE* file, const struct hash* hash);

/*
 * Gets hash of the file defined by the filename.
 * Returns pointer to the allocated hash memory in case of a success and a
 * NULL in case of failures. Returned pointer must be released later.
 */
unsigned char* hash_filename(const char* filename, const struct hash* hash);

/*
 * Gets hash of the file defined by the filename inside directory dirname.
 * Returns pointer to the allocated hash memory in case of a success and a
 * NULL in case of failures. Returned pointer must be released later.
 * */
unsigned char* hash_dir_filename(const char* dirname, const char* filename,
                                 const struct hash* hash);

#endif  // LOGGER_HASH_H_
