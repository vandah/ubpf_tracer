#ifndef UBPF_HELPERS_H
#define UBPF_HELPERS_H

#include "arraylist.h"
#include "hash_chains.h"

#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <ubpf.h>

#define ERR(st) "\033[0m\033[1;31m" st "\033[0m"
#define YAY(st) "\033[0m\033[1;32m" st "\033[0m"
#define wrap_print_fn(BUF_SIZE, ...)                                           \
  {                                                                            \
    char *buf = calloc(BUF_SIZE, sizeof(char));                                \
    snprintf(buf, BUF_SIZE, __VA_ARGS__);                                      \
    print_fn(buf);                                                             \
    free(buf);                                                                 \
  }

// BPF helperes
uint64_t bpf_map_get(uint64_t key1, uint64_t key2);
void bpf_map_put(uint64_t key1, uint64_t key2, uint64_t value);
long long bpf_strtoll(const char *st, int base);
unsigned long long bpf_strtoull(const char *st, int base);

struct ubpf_vm *init_vm(struct ArrayListWithLabels *helper_list);
struct ArrayListWithLabels *init_helper_list();

void *readfile(const char *path, size_t maxlen, size_t *len);

// shell commands
int bpf_exec(const char *filename, void *args, size_t args_size,
             void (*print_fn)(char *str));

#endif /* UBPF_HELPERS_H */
