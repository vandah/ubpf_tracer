#include "ubpf_helpers.h"
#include "ubpf.h"
#include <stdio.h>

void count(void *function_id) { printf("count\n"); }

void notify(void *function_id) { printf("notify\n"); }

uint64_t unwind(uint64_t i) { return i; }

struct ubpf_vm *init_vm() {
  struct ubpf_vm *vm = ubpf_create();
  uint64_t function_index = 0;
  ubpf_register(vm, function_index++, "count", (void *)count);
  ubpf_register(vm, function_index++, "notify", notify);

  ubpf_register(vm, function_index, "unwind", unwind);
  ubpf_set_unwind_function_index(vm, function_index);
  return vm;
}
