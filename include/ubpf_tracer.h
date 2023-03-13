#ifndef UBPF_TRACER_H
#define UBPF_TRACER_H
#include "hash_chains.h"
#include "ubpf_helpers.h"

#include <ubpf.h>
#include <ubpf_config.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// struct ubpf_vm *vm;
// struct THashMap *hmap;

#define FUNCTION_BEGIN_OFFSET 4
#define CALL_OPCODE 0xe8

struct UbpfTracer {
  struct DebugInfo *symbols; // { function_name -> function_address }
  uint32_t symbols_cnt;
  void *vm_map; // { function_address -> List<ubpf_vm> }
};

struct DebugInfo {
  uint64_t address;
  char type[20];
  char identifier[50];
};

struct UbpfTracer *init_tracer();
void load_debug_symbols(struct UbpfTracer *tracer);
void *find_function_address(struct UbpfTracer *tracer,
                            const char *function_name);
void insert_bpf_program(struct UbpfTracer *tracer, const char *function_name,
                        const char *bpf_filename);
void run_bpf_program();

void *readfile(const char *path, size_t maxlen, size_t *len);
int ubpf_run_file(const char *filename, struct ubpf_vm *vm);
__attribute__((noinline)) int run_test_file();

#endif /* UBPF_TRACER_H */
