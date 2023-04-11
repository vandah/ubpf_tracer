#ifndef UBPF_TRACER_H
#define UBPF_TRACER_H
#include "arraylist.h"
#include "hash_chains.h"
#include "ubpf_helpers.h"

#include <ubpf.h>
#include <ubpf_config.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define FUNCTION_BEGIN_OFFSET 8
#define CALL_OPCODE 0xe8

struct UbpfTracer {
  struct DebugInfo *symbols; // { function_name -> function_address }
  uint32_t symbols_cnt;
  struct THashMap *vm_map;  // { function_address -> List<ubpf_vm> }
  struct THashMap *nop_map; // { function_address -> nop_address }
};

struct UbpfTracerCtx {
  uint64_t traced_function_address;
};

struct DebugInfo {
  uint64_t address;
  char type[20];
  char identifier[50];
};

struct UbpfTracer *init_tracer();
struct UbpfTracer *get_tracer();
void load_debug_symbols(struct UbpfTracer *tracer);
void *find_function_address(struct UbpfTracer *tracer,
                            const char *function_name);
void insert_bpf_program(const char *function_name, const char *bpf_filename);
void run_bpf_program();

void *readfile(const char *path, size_t maxlen, size_t *len);
int ubpf_run_file(const char *filename, struct ubpf_vm *vm);
__attribute__((noinline)) int run_test_file();

#endif /* UBPF_TRACER_H */
