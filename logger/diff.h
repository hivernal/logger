#ifndef LOGGER_DIFF_H_
#define LOGGER_DIFF_H_

struct diff_callbacks {
  int (*cmp)(const void*, int, const void*, int);
  void (*add)(const void*, int);
  void (*del)(const void*, int);
};

void diff(const void* a, int n, const void* b, int m,
          const struct diff_callbacks* callbacks);

#endif  //  LOGGER_DIFF_H_
