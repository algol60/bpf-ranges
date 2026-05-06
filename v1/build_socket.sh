#!/bin/sh

name=socket_prog

clang -O2 -c -g -target bpf -o $name.o $name.bpf.c

ok=$?
if [ $ok ]; then
  file $name.o
fi

# After this is successful, detach the previous load; load the new programs.
#
# # rm -rf /sys/fs/bpf/socket_prog
# # bpftool prog loadall socket_prog.o /sys/fs/bpf/socket_prog autoattach

