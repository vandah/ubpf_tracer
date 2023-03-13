#ifndef HASH_CHAINS_H
#define HASH_CHAINS_H

#include <stdint.h>
#include <stdlib.h>

struct THashCell {
  uint64_t m_Key;
  int64_t m_Value;
  struct THashCell *m_Next;
};

struct THashMap {
  uint64_t m_Size;
  struct THashCell **m_Map;
};

enum THmapResult {
  HMAP_SUCCESS = 0,
  HMAP_BADARGUMENT,
  HMAP_ALLOCFAIL,
  HMAP_NOTFOUND,
};

struct THashMap *hmap_init(uint64_t size, int *errcode);

int hmap_put(struct THashMap *hmap, uint64_t key, int64_t value);

int hmap_get(struct THashMap *hmap, uint64_t key, int64_t *value);

int hmap_print(struct THashMap *hmap);

void hmap_destroy(struct THashMap *hmap);

#endif /* HASH_CHAINS_H */
