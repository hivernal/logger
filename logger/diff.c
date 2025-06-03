#include "logger/diff.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct box {
  int x1, x2, y1, y2, d;
};

struct box* box_copy(const struct box* a, struct box* b) {
  return memcpy(b, a, sizeof(struct box));
}

void box_fill(struct box* box, int x1, int y1, int x2, int y2, int d) {
  box->x1 = x1;
  box->x2 = x2;
  box->y1 = y1;
  box->y2 = y2;
  box->d = d;
};

typedef int (*cmp_elements)(const void* a, int i, const void* b, int j);

int search_path(int* fv, int* bv, int d, int d_max, int delta, const void* a,
                const void* b, struct box* box, cmp_elements cmp) {
  int x, y;
  for (int k = d; k >= -d; k -= 2) {
    const int c = k - delta;
    const int k_off = k + d_max;
    if (k == -d || (k != d && fv[k_off - 1] < fv[k_off + 1])) {
      x = fv[k_off + 1];
    } else {
      x = fv[k_off - 1] + 1;
    }
    y = x - box->x1 - k + box->y1;
    while (x < box->x2 && y < box->y2 && cmp(a, x, b, y)) {
      ++x;
      ++y;
    }
    fv[k_off] = x;
    if ((delta & 1) && c >= -(d - 1) && c <= d - 1) {
      const int py = bv[k_off];
      const int px = py - box->y1 + k + box->x1;
      if (x >= px) {
        box_fill(box, px, py, x, y, 2 * d - 1);
        return 1;
      }
    }
  }

  for (int c = d; c >= -d; c -= 2) {
    const int k = c + delta;
    const int k_off = k + d_max;
    if (c == -d || (c != d && bv[k_off - 1] > bv[k_off + 1])) {
      y = bv[k_off + 1];
    } else {
      y = bv[k_off - 1] - 1;
    }
    x = y - box->y1 + k + box->x1;
    while (x > box->x1 && y > box->y1 && cmp(a, x - 1, b, y - 1)) {
      --x;
      --y;
    }
    bv[k_off] = y;
    if (!(delta & 1) && k >= -d && k <= d) {
      const int px = fv[k_off];
      if (x <= px) {
        const int py = px - box->x1 - k + box->y1;
        box_fill(box, x, y, px, py, 2 * d);
        return 1;
      }
    }
  }
  return 0;
};

int find_middle(const void* a, const void* b, struct box* box,
                cmp_elements cmp) {
  const int n = box->x2 - box->x1;
  const int m = box->y2 - box->y1;
  const int delta = n - m, max = m + n;
  const int d_max = (max + (max & 1)) / 2;
  int* fv = malloc(sizeof(int) * (size_t)(max + (max & 1) + 1));
  int* bv = malloc(sizeof(int) * (size_t)(max + (max & 1) + 1));
  fv[1 + d_max] = box->x1;
  bv[1 + d_max + delta] = box->y2;
  for (int d = 0; d <= d_max; ++d) {
    if (search_path(fv, bv, d, d_max, delta, a, b, box, cmp)) {
      free(fv);
      free(bv);
      return 1;
    }
  }
  free(fv);
  free(bv);
  return 0;
}

void shortest_edit_script(const void* a, const void* b, const struct box* box,
                          const struct diff_callbacks* callbacks) {
  struct box copy;
  box_copy(box, &copy);
  while (copy.x1 < copy.x2 && copy.y1 < copy.y2 &&
         callbacks->cmp(a, copy.x1, b, copy.y1)) {
    ++copy.x1;
    ++copy.y1;
  }
  while (copy.x2 > copy.x1 && copy.y2 > copy.y1 &&
         callbacks->cmp(a, copy.x2 - 1, b, copy.y2 - 1)) {
    --copy.x2;
    --copy.y2;
  }
  const int n = copy.x2 - copy.x1, m = copy.y2 - copy.y1;
  if (n > 0 && m > 0) {
    struct box middle;
    box_copy(&copy, &middle);
    if (!find_middle(a, b, &middle, callbacks->cmp)) return;
    struct box box1 = {
        .x1 = copy.x1, .y1 = copy.y1, .x2 = middle.x1, .y2 = middle.y1};
    struct box box2 = {
        .x1 = middle.x2, .y1 = middle.y2, .x2 = copy.x2, .y2 = copy.y2};
    shortest_edit_script(a, b, &box1, callbacks);
    shortest_edit_script(a, b, &box2, callbacks);
  } else if (n > 0) {
    for (int i = copy.x1; i < copy.x2; ++i) callbacks->del(a, i);
  } else {
    for (int i = copy.y1; i < copy.y2; ++i) callbacks->add(b, i);
  }
}

void longest_common_subseq(const void* a, const void* b, const struct box* box,
                           const struct diff_callbacks* callbacks) {
  const int n = box->x2 - box->x1, m = box->y2 - box->y1;
  if (n > 0 && m <= 0) {
    for (int i = box->x1; i < box->x2; ++i) callbacks->del(a, i);
    return;
  } else if (m > 0 && n <= 0) {
    for (int i = box->y1; i < box->y2; ++i) callbacks->add(b, i);
    return;
  } else if (n <= 0 && m <= 0) {
    return;
  }
  struct box middle;
  box_copy(box, &middle);
  if (!find_middle(a, b, &middle, callbacks->cmp)) return;
  if (middle.d > 1) {
    struct box box1 = {
        .x1 = box->x1, .y1 = box->y1, .x2 = middle.x1, .y2 = middle.y1};
    struct box box2 = {
        .x1 = middle.x2, .y1 = middle.y2, .x2 = box->x2, .y2 = box->y2};
    longest_common_subseq(a, b, &box1, callbacks);
    longest_common_subseq(a, b, &box2, callbacks);
  } else if (m > n) {
    callbacks->add(b, middle.y1 - 1);
  } else {
    callbacks->del(a, middle.x1 - 1);
  }
}

void diff(const void* a, int n, const void* b, int m,
          const struct diff_callbacks* callbacks) {
  struct box box = {.x1 = 0, .y1 = 0, .x2 = n, .y2 = m};
  // longest_common_subseq(a, b, &box, callbacks);
  shortest_edit_script(a, b, &box, callbacks);
}
