#ifndef UBPF_HELPERS_H
#define UBPF_HELPERS_H
#include "ubpf.h"

#include <stdio.h>
#include <sys/types.h>

void count(void *function_id);
void notify(void *function_id);
struct ubpf_vm *init_vm();

#endif /* UBPF_HELPERS_H */
