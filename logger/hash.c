#include "hash.h"
#include <fcntl.h>

int hash_ctx_md_init(struct hash* hash, const char* alg) {
  if (!(hash->ctx = EVP_MD_CTX_new())) return 1;
  if (!(hash->md = EVP_MD_fetch(NULL, alg, NULL))) {
    free(hash->ctx);
    return 1;
  }
  if ((hash->len = EVP_MD_get_size(hash->md)) <= 0) {
    free(hash->ctx);
    free(hash->md);
    return 1;
  }
  return 0;
}

struct hash* hash_init(const char* alg) {
  struct hash* hash = malloc(sizeof(struct hash));
  if (!hash) return NULL;
  if (hash_ctx_md_init(hash, alg)) {
    free(hash);
    return NULL;
  }
  return hash;
}

void hash_delete(struct hash* hash) {
  if (hash->ctx) EVP_MD_CTX_free(hash->ctx);
  if (hash->md) EVP_MD_free(hash->md);
}

void hash_delete_ptr(struct hash* hash) {
  hash_delete(hash);
  free(hash);
}

unsigned char* hash_file(FILE* file, const struct hash* hash) {
  unsigned char* digest = NULL;
  if (fseek(file, 0, SEEK_END) == -1) return NULL;
  long file_size;
  if ((file_size = ftell(file)) == -1) return NULL;
  if (fseek(file, 0, SEEK_SET) == -1) return NULL;
  char* data = malloc((size_t)file_size);
  if (!data) return NULL;
  fread(data, (size_t)file_size, 1, file);
  if (!EVP_DigestInit_ex(hash->ctx, hash->md, NULL)) goto clean;
  if (!EVP_DigestUpdate(hash->ctx, data, (size_t)file_size)) goto clean;
  if (!(digest = OPENSSL_malloc((size_t)hash->len))) goto clean;
  if (!EVP_DigestFinal_ex(hash->ctx, digest, NULL)) {
    free(digest);
    digest = NULL;
  }
clean:
  free(data);
  return digest;
}

unsigned char* hash_filename(const char* filename, const struct hash* hash) {
  FILE* file = fopen(filename, "r");
  if (!file) return NULL;
  unsigned char* digest = hash_file(file, hash);
  fclose(file);
  return digest;
}

unsigned char* hash_dir_filename(const char* dirname, const char* filename,
                                 const struct hash* hash) {
  int dfd = open(dirname, O_RDONLY);
  if (dfd < 0) return NULL;
  int fd = openat(dfd, filename, O_RDONLY);
  if (fd < 0) return NULL;
  FILE* file = fdopen(fd, "r");
  if (!file) return NULL;
  unsigned char* digest = hash_file(file, hash);
  fclose(file);
  return digest;
}
