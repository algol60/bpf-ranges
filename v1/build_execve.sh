#!/bin/sh

clang -O2 -c -g -target bpf -o execve_prog.o execve_prog.bpf.c

ok=$?
if [ $ok ]; then
  file execve_prog.o
fi
