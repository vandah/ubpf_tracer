#include "ubpf_tracer.h"

struct UbpfTracer *g_tracer = NULL;

void destruct_cell(struct THashCell *elem) {
  free(elem->m_Value);
  elem->m_Value = NULL;
}

void destruct_entry(struct LabeledEntry *entry) {
  free(entry->m_Label);
  free(entry->m_Value);
}

void *nop_map_init() {
  uint64_t *value = malloc(sizeof(uint64_t));
  *value = 0;
  return (void *)value;
}

void vm_map_destruct_cell(struct THashCell *elem) {
  list_destroy(elem->m_Value);
  destruct_cell(elem);
}

void vm_map_destruct_entry(struct LabeledEntry *entry) {
  ubpf_destroy(entry->m_Value);
  destruct_entry(entry);
}

void *init_arraylist() { return (void *)list_init(10, &vm_map_destruct_entry); }

struct UbpfTracer *init_tracer() {
  struct UbpfTracer *tracer = malloc(sizeof(struct UbpfTracer));
  int map_result;
  tracer->vm_map =
      hmap_init(101, &vm_map_destruct_cell, &init_arraylist, &map_result);
  tracer->nop_map = hmap_init(101, &destruct_cell, &nop_map_init, &map_result);

  load_debug_symbols(tracer);

  return tracer;
}

struct UbpfTracer *get_tracer() { return g_tracer; }

void load_debug_symbols(struct UbpfTracer *tracer) {
  printf("Loading debug symbols...\n");
  FILE *file_debug_sym = fopen("debug.sym", "r");
  uint32_t symbols_size = 1;

  tracer->symbols_cnt = 0;
  tracer->symbols = malloc(sizeof(struct DebugInfo) * symbols_size);
  while (!feof(file_debug_sym)) {
    if (symbols_size <= tracer->symbols_cnt) {
      symbols_size *= 2;
      tracer->symbols =
          realloc(tracer->symbols, sizeof(struct DebugInfo) * symbols_size);
    }
    uint64_t *sym_addr = &tracer->symbols[tracer->symbols_cnt].address;
    char *sym_type = tracer->symbols[tracer->symbols_cnt].type;
    char *sym_id = tracer->symbols[tracer->symbols_cnt].identifier;
    if (fscanf(file_debug_sym, "%lx %s %s\n", sym_addr, sym_type, sym_id) !=
            3 ||
        feof(file_debug_sym))
      break;

    tracer->symbols_cnt++;
  }
  printf("Loaded all symbols\n");
}

void insert_bpf_program(const char *function_name, const char *bpf_filename) {
  if (g_tracer == NULL) {
    g_tracer = init_tracer();
  }
  void *traced_function_address =
      find_function_address(g_tracer, function_name);
  if (traced_function_address == NULL) {
    fprintf(stderr, "Can't insert BPF program.\n");
    return;
  }

  size_t code_len;
  void *bpf_program = readfile(bpf_filename, 1024 * 1024, &code_len);
  // TODO: verify bpf_program here

  struct ubpf_vm *vm = init_vm();
  char *errmsg;
  ubpf_load(vm, bpf_program, code_len, &errmsg);
  printf("function address = %p\n", traced_function_address);

  printf("get or create entry\n");
  struct THmapValueResult *hmap_entry =
      hmap_get_or_create(g_tracer->vm_map, (uint64_t)traced_function_address +
                                               CALL_INSTRUCTION_SIZE);
  if (hmap_entry->m_Result == HMAP_SUCCESS) {
    printf("get list\n");
    struct ArrayListWithLabels *list = hmap_entry->m_Value;
    printf("create label\n");
    char *label = malloc(strlen(bpf_filename));
    strcpy(label, bpf_filename);
    printf("add element\n");
    list_add_elem(list, label, vm);

    printf("insert instruction\n");
    void *run_bpf_address = (void *)&run_bpf_program;
    uint8_t call_function[CALL_INSTRUCTION_SIZE];
    call_function[0] = CALL_OPCODE;
    uint32_t offset = (uint32_t)(run_bpf_address - traced_function_address -
                                 sizeof(call_function));
    memcpy(&(call_function[1]), &offset, sizeof(offset));
    memcpy(traced_function_address, call_function, sizeof(call_function));
  }
}

uint64_t find_function_start(struct UbpfTracer *tracer, uint64_t search_value) {
  struct THmapValueResult *map_entry = hmap_get(tracer->nop_map, search_value);
  if (map_entry->m_Result == HMAP_SUCCESS) {
    return *(uint64_t *)map_entry->m_Value;
  }

  uint64_t start = 0;
  uint64_t end = tracer->symbols_cnt - 1;

  uint32_t steps = 0;
  while (end > start && steps < 30) {
    steps++;
    uint64_t current = (end + start + 1) / 2;
    if (search_value < tracer->symbols[current].address) {
      end = current - 1;
    } else if (current == end ||
               search_value < tracer->symbols[current + 1].address) {
      return tracer->symbols[current].address;
    } else {
      start = current;
    }
  }
  return start;
}

void *find_function_address(struct UbpfTracer *tracer,
                            const char *function_name) {
  void *addr = NULL;
  void *addr_next = NULL;

  for (uint32_t i = 0; i < tracer->symbols_cnt; ++i) {
    if (strcmp(function_name, tracer->symbols[i].identifier) == 0) {
      addr = (void *)tracer->symbols[i].address;
      // if it's not the last one then save address of the next function
      if (i != tracer->symbols_cnt - 1) {
        addr_next = (void *)tracer->symbols[i + 1].address;
      } else {
        // let's not try more than 100 bytes
        addr_next = addr + 100;
      }
    }
  }

  if (addr == NULL) {
    fprintf(stderr, "Function not found.\n");
    return NULL;
  }

  uint8_t nopl[] = {0x0f, 0x1f, 0x44, 0x00, 0x00};

  uint8_t nopl_idx = 0;
  uint8_t *nopl_addr = NULL;
  bool found_nopl = false;
  for (uint8_t *i = addr; i < (uint8_t *)addr_next; ++i) {
    if (*i == nopl[nopl_idx]) {
      if (nopl_idx == 0) {
        nopl_addr = i;
      }
      if (nopl_idx < sizeof(nopl) - 1) {
        nopl_idx++;
      } else {
        found_nopl = true;
        break;
      }
    } else {
      nopl_idx = 0;
    }
  }
  if (!found_nopl) {
    fprintf(stderr, "Nopl not found in function.\n");
    return NULL;
  }

  return nopl_addr;
}

void run_bpf_program() {
  void *ret_addr = __builtin_return_address(0);
  uint64_t function_address = find_function_start(g_tracer, (uint64_t)ret_addr);

  printf("run_bpf_program:\n");
  printf("return address = %p\n", ret_addr);
  // printf("function_address = %ld\n", function_address);

  // find vm in the vm_map
  struct THmapValueResult *hmap_entry =
      hmap_get(g_tracer->vm_map, (uint64_t)ret_addr);
  if (hmap_entry->m_Result == HMAP_SUCCESS) {
    struct ArrayListWithLabels *list = hmap_entry->m_Value;
    printf("found %lu attached programs\n", list->m_Length);
    for (uint64_t i = 0; i < list->m_Length; ++i) {
      struct LabeledEntry list_item = list->m_List[i];
      printf("executing BPF program: %s\n", list_item.m_Label);
      struct ubpf_vm *vm = list_item.m_Value;

      size_t ctx_size = sizeof(struct UbpfTracerCtx);
      struct UbpfTracerCtx *ctx = malloc(ctx_size);
      ctx->traced_function_address = ret_addr;

      uint64_t ret;
      if (ubpf_exec(vm, ctx, ctx_size, &ret) < 0)
        ret = UINT64_MAX;
      printf("BPF program returned: %lu\n", ret);
      free(ctx);
    }
  } else {
    printf("hmap_get failed: %d\n", hmap_entry->m_Result);
  }
  printf("end of run_bpf_program\n---------\n");
}

int ubpf_run_file(const char *filename, struct ubpf_vm *vm) {
  size_t code_len;
  void *code = readfile(filename, 1024 * 1024, &code_len);
  if (code == NULL) {
    return 1;
  }
  size_t mem_len = 1024;
  void *mem = calloc(mem_len, sizeof(int));
  char *errmsg;
  int rv;
  rv = ubpf_load(vm, code, code_len, &errmsg);
  free(code);

  if (rv < 0) {
    fprintf(stderr, "Failed to load code: %s\n", errmsg);
    free(errmsg);
    ubpf_destroy(vm);
    return 1;
  }

  uint64_t ret;

  if (ubpf_exec(vm, mem, mem_len, &ret) < 0)
    ret = UINT64_MAX;
  ubpf_unload_code(vm);
  free(mem);
  return 0;
}

__attribute__((noinline)) int run_test_file() {
  uint64_t *ret_addr = __builtin_return_address(0);
  printf("------\nrun_test_file()\n");
  printf("return address=%p\n", ret_addr);
  struct ubpf_vm *test_vm = ubpf_create();
  init_vm(test_vm);
  return ubpf_run_file("test.bin", test_vm);
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
