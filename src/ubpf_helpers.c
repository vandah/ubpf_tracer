#include "ubpf_helpers.h"
#include "ubpf_tracer.h"

uint64_t bpf_map_get(void *function_address, uint64_t key) {
  return 0;
  printf("map_get\n");
}

void bpf_map_put(void *function_address, uint64_t key, uint64_t value) {
  printf("map_put\n");
}

void bpf_notify(void *function_id) {
  printf("notify %p\n", function_id);

  struct UbpfTracer *tracer = get_tracer();
  printf("symbols_cnt: %d\n", tracer->symbols_cnt);
}

uint64_t bpf_unwind(uint64_t i) { return i; }

struct ubpf_vm *init_vm() {
  struct ubpf_vm *vm = ubpf_create();
  uint64_t function_index = 0;
  ubpf_register(vm, function_index++, "bpf_map_get", bpf_map_get);
  ubpf_register(vm, function_index++, "bpf_map_put", bpf_map_put);
  ubpf_register(vm, function_index++, "bpf_notify", bpf_notify);

  ubpf_register(vm, function_index, "bpf_unwind", bpf_unwind);
  ubpf_set_unwind_function_index(vm, function_index);
  return vm;
}
