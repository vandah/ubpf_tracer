#include "ubpf_tracer.h"
#include <stdio.h>

__attribute__((noinline)) int mytest() { return 1; }

__attribute__((noinline)) void myfun() {
  printf("hello from myfun\n");
  return;
}

int main() {
  printf("Hello world!\n");
  struct UbpfTracer *tracer = init_tracer();
  char function_name[50], bpf_filename[50];
  printf("Function name:\n");
  scanf("%s", function_name);
  printf("BPF file name:\n");
  scanf("%s", bpf_filename);

  printf("function name = %s, bpf filename = %s\n", function_name,
         bpf_filename);
  insert_bpf_program(tracer, function_name, bpf_filename);

  return 0;
}
