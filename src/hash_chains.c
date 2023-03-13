#include "hash_chains.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct THashMap *hmap_init(uint64_t size, int *errcode) {
  printf("hmap_init(%lu)\n", size);
  if (errcode == NULL) {
    return NULL;
  }
  if (size == 0) {
    *errcode = HMAP_BADARGUMENT;
    return NULL;
  }

  struct THashMap *hmap = (struct THashMap *)calloc(1, sizeof(struct THashMap));

  if (hmap == NULL) {
    *errcode = HMAP_ALLOCFAIL;
    return NULL;
  }

  hmap->m_Size = size;
  hmap->m_Map = (struct THashCell **)calloc(size, sizeof(struct THashCell *));

  if (hmap->m_Map == NULL) {
    *errcode = HMAP_ALLOCFAIL;
    return NULL;
  }

  *errcode = HMAP_SUCCESS;

  return hmap;
}

struct THashCell *hmap_new_cell(uint64_t key, int64_t value) {
  struct THashCell *cell = (struct THashCell *)malloc(sizeof(struct THashCell));
  if (cell == NULL)
    return NULL;

  cell->m_Key = key;
  cell->m_Value = value;
  cell->m_Next = NULL;

  return cell;
}

int hmap_put(struct THashMap *hmap, uint64_t key, int64_t value) {
  printf("hmap_put(%lu, %ld)\n", key, value);
  if (hmap == NULL) {
    return HMAP_BADARGUMENT;
  }

  uint64_t map_idx = key % hmap->m_Size;
  struct THashCell *current = hmap->m_Map[map_idx];
  struct THashCell *prev;
  if (current == NULL) {
    struct THashCell *cell = hmap_new_cell(key, value);
    if (cell == NULL) {
      return HMAP_ALLOCFAIL;
    }
    hmap->m_Map[map_idx] = cell;
    return HMAP_SUCCESS;
  }

  while (current != NULL) {
    if (current->m_Key == key) {
      current->m_Value = value;
      return HMAP_SUCCESS;
    }
    prev = current;
    current = current->m_Next;
  }

  struct THashCell *cell = hmap_new_cell(key, value);
  if (cell == NULL) {
    return HMAP_ALLOCFAIL;
  }
  prev->m_Next = cell;
  return HMAP_SUCCESS;
}

int hmap_get(struct THashMap *hmap, uint64_t key, int64_t *value) {
  printf("hmap_get(%lu)\n", key);
  if (hmap == NULL || value == NULL) {
    return HMAP_BADARGUMENT;
  }

  uint64_t map_idx = key % hmap->m_Size;

  struct THashCell *current = hmap->m_Map[map_idx];
  while (current != NULL) {
    if (current->m_Key == key) {
      *value = current->m_Value;
      return HMAP_SUCCESS;
    }
    current = current->m_Next;
  }

  return HMAP_NOTFOUND;
}

int hmap_print(struct THashMap *hmap) {
  printf("hmap_print()\n");
  if (hmap == NULL) {
    return HMAP_BADARGUMENT;
  }

  struct THashCell *current;
  for (uint64_t i = 0; i < hmap->m_Size; ++i) {
    current = hmap->m_Map[i];
    while (current != NULL) {
      printf("%lu: %ld\n", current->m_Key, current->m_Value);
      current = current->m_Next;
    }
  }

  return HMAP_SUCCESS;
}

void hmap_destroy(struct THashMap *hmap) {
  printf("hmap_destroy()\n");
  if (hmap == NULL)
    return;
  struct THashCell *current, *next;
  for (uint64_t i = 0; i < hmap->m_Size; ++i) {
    current = hmap->m_Map[i];
    while (current != NULL) {
      next = current->m_Next;
      free(current);
      current = next;
    }
  }
  free(hmap->m_Map);
  free(hmap);
}
