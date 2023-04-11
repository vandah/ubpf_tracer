all: build/libubpf_tracer.a
clean:
	rm -rf build/*

.PHONY: all clean

INCLUDES=-Iinclude/ -Iubpf/vm/inc
EXTRA_CFLAGS=-mno-red-zone -Werror -pg -mrecord-mcount -mnop-mcount
CFLAGS=-Wall $(INCLUDES)

build/arraylist.o: src/arraylist.c include/arraylist.h
	gcc -c $(CFLAGS) -o $@ $<

build/hash_chains.o: src/hash_chains.c include/hash_chains.h
	gcc -c $(CFLAGS) -o $@ $<

build/ubpf_helpers.o: src/ubpf_helpers.c include/ubpf_helpers.h \
 ubpf/vm/inc/ubpf.h ubpf/vm/inc/ubpf_config.h
	gcc -c $(CFLAGS) -o $@ $<

build/ubpf_tracer.o: src/ubpf_tracer.c include/ubpf_tracer.h \
 include/arraylist.h include/hash_chains.h ubpf/vm/inc/ubpf.h \
 ubpf/vm/inc/ubpf_config.h include/ubpf_helpers.h
	ar rcs $@ $^
