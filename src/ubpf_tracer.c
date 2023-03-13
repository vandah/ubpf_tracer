#include "ubpf_tracer.h"
#include "ubpf.h"
#include <stdint.h>

struct UbpfTracer *init_tracer() {
  struct UbpfTracer *tracer = malloc(sizeof(struct UbpfTracer));
  tracer->vm_map = NULL;

  load_debug_symbols(tracer);

  return tracer;
}

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

void insert_bpf_program(struct UbpfTracer *tracer, const char *function_name,
                        const char *bpf_filename) {
  void *traced_function_address = find_function_address(tracer, function_name);

  size_t code_len;
  void *bpf_program = readfile(bpf_filename, 1024 * 1024, &code_len);

  struct ubpf_vm *vm = init_vm();
  char *errmsg;
  ubpf_load(vm, bpf_program, code_len, &errmsg);
  printf("function address = %p\n", traced_function_address);

  // TODO: tracer->vm_map[function_address] += vm

  // TODO: insert the call instruction
  void *run_bpf_address = (void *)&run_bpf_program;
  uint8_t call_function[5];
  call_function[0] = CALL_OPCODE;
  uint32_t offset = (uint32_t)(run_bpf_address - traced_function_address -
                               sizeof(call_function));
  memcpy(&(call_function[1]), &offset, sizeof(offset));
  memcpy(traced_function_address, call_function, sizeof(call_function));
}

void *find_function_address(struct UbpfTracer *tracer,
                            const char *function_name) {
  void *addr = NULL;

  for (uint32_t i = 0; i < tracer->symbols_cnt; ++i) {
    if (strcmp(function_name, tracer->symbols[i].identifier) == 0) {
      addr = (void *)tracer->symbols[i].address;
    }
  }

  if (addr == NULL) {
    fprintf(stderr, "Function not found.\n");
    return NULL;
  }

  return addr + FUNCTION_BEGIN_OFFSET;
}

void run_bpf_program() {
  // TODO: find address of the function with return address
  void *ret_addr = __builtin_return_address(0);
  printf("return address = %p\n", ret_addr);
  // TODO: find vm in the vm_map
  // TODO: fill memory (add address of hmap for storage?)
  // TODO: ubpf_exec
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
