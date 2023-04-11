#ifndef UBPF_HELPERS_H
#define UBPF_HELPERS_H

#include <stdio.h>
#include <sys/types.h>
#include <ubpf.h>

#define CALL_INSTRUCTION_SIZE 5

uint64_t bpf_map_get(void *function_address, uint64_t key);
void bpf_map_put(void *function_address, uint64_t key, uint64_t value);
void bpf_notify(void *function_address);

struct ubpf_vm *init_vm();

#endif /* UBPF_HELPERS_H */
