#!/bin/sh

# filter
clang -O2 -target bpf -c -g port_restrict.bpf.c -o bin/port_restrict.o

# front end
clang -O2 port_restrict_loader.c -o bin/port_restrict_loader -lbpf

# use LIBBPF_LOG_LEVEL=debug when running the front end for debugging

# detach
 clang -O2 detach.c -o bin/detach -lbpf