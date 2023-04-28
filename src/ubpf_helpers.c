#include "ubpf_helpers.h"

struct THashMap *g_bpf_map = NULL;
struct ArrayListWithLabels *additional_helpers = NULL;

void destruct_cell_l2(struct THashCell *cell) { free(cell->m_Value); }
void *create_cell_l2() {
  uint64_t *cell = calloc(1, sizeof(uint64_t));
  return cell;
}

void destruct_cell_l1(struct THashCell *cell) {
  hmap_destroy(cell->m_Value);
  free(cell->m_Value);
}

void *create_cell_l1() {
  int err = 0;
  return hmap_init(101, &destruct_cell_l2, &create_cell_l2, &err);
}

struct THashMap *init_bpf_map() {
  int err = 0;
  return hmap_init(101, &destruct_cell_l1, &create_cell_l1, &err);
}

uint64_t bpf_map_get(uint64_t key1, uint64_t key2) {
  if (g_bpf_map == NULL) {
    g_bpf_map = init_bpf_map();
  }
  struct THmapValueResult *hmap_entry_l1 = hmap_get(g_bpf_map, key1);
  if (hmap_entry_l1->m_Result == HMAP_SUCCESS) {
    struct THmapValueResult *hmap_entry_l2 =
        hmap_get(hmap_entry_l1->m_Value, key2);
    if (hmap_entry_l2->m_Result == HMAP_SUCCESS) {
      uint64_t value = *(uint64_t *)hmap_entry_l2->m_Value;
      printf("(GET) bpf_map[%lu][%lu] = %lu\n", key1, key2, value);
      return value;
    }
  }
  printf("(GET) bpf_map[%lu][%lu] = X\n", key1, key2);
  return UINT64_MAX;
}

void bpf_map_put(uint64_t key1, uint64_t key2, uint64_t value) {
  printf("(PUT) bpf_map[%lu][%lu] = %lu\n", key1, key2, value);
  if (g_bpf_map == NULL) {
    g_bpf_map = init_bpf_map();
  }
  struct THmapValueResult *hmap_entry_l1 = hmap_get_or_create(g_bpf_map, key1);
  if (hmap_entry_l1->m_Result == HMAP_SUCCESS) {
    uint64_t *value_copy = calloc(1, sizeof(uint64_t));
    *value_copy = value;
    struct THmapValueResult *hmap_entry_l2 =
        hmap_put(hmap_entry_l1->m_Value, key2, value_copy);
    if (hmap_entry_l2->m_Result != HMAP_SUCCESS) {
      free(value_copy);
    }
  }
}

void bpf_map_del(uint64_t key1, uint64_t key2) {
  printf("(DEL) bpf_map[%lu][%lu]", key1, key2);
  if (g_bpf_map == NULL) {
    return;
  }

  struct THmapValueResult *hmap_entry_l1 = hmap_get(g_bpf_map, key1);
  if (hmap_entry_l1->m_Result == HMAP_NOTFOUND) {
    return;
  }

  struct THashMap *map_l2 = hmap_entry_l1->m_Value;

  if (hmap_entry_l1->m_Result == HMAP_SUCCESS) {
    hmap_del(map_l2, key2);
    if (map_l2->m_Elems == 0) {
      hmap_del(g_bpf_map, key1);
    }
  }
}

uint64_t bpf_unwind(uint64_t i) { return i; }

// we put in function pointers so don't free the values
void helper_list_destruct_entry(struct LabeledEntry *entry) {
  free(entry->m_Label);
}

struct ArrayListWithLabels *init_helper_list() {
  return list_init(4, &helper_list_destruct_entry);
}

void additional_helpers_list_add(const char *label, void *function_ptr) {
  if (additional_helpers == NULL) {
    additional_helpers = init_helper_list();
  }
  list_add_elem(additional_helpers, label, function_ptr);
}

void additional_helpers_list_del(const char *label) {
  if (additional_helpers != NULL) {
    list_remove_elem(additional_helpers, label);
  }
}

#define register_helper(idx, label, fun_ptr)                                   \
  {                                                                            \
    printf("%s: %lu\n", label, idx);                                           \
    ubpf_register(vm, idx, label, fun_ptr);                                    \
  }

struct ubpf_vm *init_vm(struct ArrayListWithLabels *helper_list) {
  struct ubpf_vm *vm = ubpf_create();
  uint64_t function_index = 0;
  register_helper(function_index, "bpf_map_get", bpf_map_get);
  function_index++;
  register_helper(function_index, "bpf_map_put", bpf_map_put);
  function_index++;
  register_helper(function_index, "bpf_map_del", bpf_map_del);
  function_index++;

  if (helper_list == NULL) {
    helper_list = additional_helpers;
  }

  if (helper_list != NULL) {
    for (uint64_t i = 0; i < helper_list->m_Length; ++i) {
      struct LabeledEntry elem = helper_list->m_List[i];
      register_helper(function_index, elem.m_Label, elem.m_Value);
      function_index++;
    }
  }

  register_helper(function_index, "bpf_unwind", bpf_unwind);
  ubpf_set_unwind_function_index(vm, function_index);
  return vm;
}

void *readfile(const char *path, size_t maxlen, size_t *len) {
  FILE *file = fopen(path, "r");

  if (file == NULL) {
    fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
    return NULL;
  }

  char *data = calloc(maxlen, 1);
  size_t offset = 0;
  size_t rv;
  while ((rv = fread(data + offset, 1, maxlen - offset, file)) > 0) {
    offset += rv;
  }

  if (ferror(file)) {
    fprintf(stderr, "Failed to read %s: %s\n", path, strerror(errno));
    fclose(file);
    free(data);
    return NULL;
  }

  if (!feof(file)) {
    fprintf(stderr,
            "Failed to read %s because it is too large (max %u bytes)\n", path,
            (unsigned)maxlen);
    fclose(file);
    free(data);
    return NULL;
  }

  fclose(file);
  if (len) {
    *len = offset;
  }
  return (void *)data;
}

int bpf_exec(const char *filename, void *args, size_t args_size,
             void (*print_fn)(char *str)) {
  struct ubpf_vm *vm = init_vm(NULL);
  size_t code_len;
  void *code = readfile(filename, 1024 * 1024, &code_len);
  if (code == NULL) {
    return 1;
  }
  char *errmsg;
  int rv;
  rv = ubpf_load(vm, code, code_len, &errmsg);
  free(code);

  if (rv < 0) {
    size_t buf_size = 100 + strlen(errmsg);
    wrap_print_fn(buf_size, "Failed to load code: %s\n", errmsg);

    free(errmsg);
    ubpf_destroy(vm);
    return 1;
  }

  uint64_t ret;
  if (ubpf_exec(vm, args, args_size, &ret) < 0) {
    ret = UINT64_MAX;
    print_fn("BPF program execution failed.\n");
  }
  wrap_print_fn(100, YAY("BPF program returned: %lu\n"), ret);
  ubpf_unload_code(vm);
  return 0;
}
