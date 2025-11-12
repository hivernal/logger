#ifndef LOGGER_DIFF_H_
#define LOGGER_DIFF_H_

struct diff_callbacks {
  int (*cmp)(const void*, int, const void*, int);
  void (*add)(const void*, int, void*);
  void (*del)(const void*, int, void*);
};

void diff(const void* a, int n, const void* b, int m,
          const struct diff_callbacks* callbacks, void* data);

#endif  //  LOGGER_DIFF_H_
