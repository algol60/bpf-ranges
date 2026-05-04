https://fksvs.github.io/posts/setting-up-ebpf-dev-env/

# Install matching headers
$ sudo dnf install kernel-devel-$(uname -r) kernel-headers-$(uname -r)

##

Verify that your kernel ships with BTF:

$  grep CONFIG_DEBUG_INFO_BTF /boot/config-$(uname -r)
# should return: CONFIG_DEBUG_INFO_BTF=y

and confirm the BTF object is present:

$ ls /sys/kernel/btf/vmlinux

##

Toolchain

$ sudo dnf install clang llvm bpftool elfutils-libelf-devel libbpf libbpf-devel bpftrace

(32-bit libraries, eBPF)
# dnf install glibc-devel.i686

##

(load and pin)

# bpftool prog load execve_prog.o /sys/fs/bpf/execve_prog autoattach

When there is more than one program in the .o, use loadall.

# bpftool prog loadall socket_prog.o /sys/fs/bpf/socket_prog autoattach
# bpftool prog show

Watch printk traces (don't use printk unless debugging):
# cat /sys/kernel/debug/tracing/trace_pipe

To unpin more than one program:
rm -rf /sys/fs/bpf/socket_prog

vmlinux.h

eBPF programs need to interact with kernel data structures reliably across
different kernel versions. Instead of using various "#include <linux/...>" headers,
generate a copy of vmlinux.h and include it (which may cause warnings),
or copy things out of it.

To generate a copy of vmlinux.h:
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

bpftrace -e 'tracepoint:syscalls:sys_enter_bind { printf("%s (PID %d) is binding a socket\n", comm, pid); }'

sys_enter_connect ?

Loading a Program

Use the bpftool prog load command to load a compiled BPF object file into the kernel and pin it to a path to keep it alive.

Command:
 sudo bpftool prog load <object_file.o> <pin_path> [type <type>]

Example:
 sudo bpftool prog load hello.bpf.o /sys/fs/bpf/my_progi

.Auto-attach: Adding autoattach to the command will automatically attach the program to its target (like a tracepoint or interface) immediately after loading.

Unloading a Program

In eBPF, a program remains in the kernel as long as there is a reference to it (such as a pinned file, an active attachment, or an open file descriptor). To "unload" it, you must remove all these references.

Detach from the interface: If the program is attached to a network interface (e.g., XDP), you must first detach it.

XDP Example: sudo bpftool net detach xdp dev eth0.

Delete the pin: Remove the pinned file from the BPF file system using standard file commands.

Command:
 sudo rm /sys/fs/bpf/my_prog.

# cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve
# bfptrace -lv tracepoint:syscalls:sys_enter_execve

... sys_enter_bind
... sys_enter_connect

If your Linux distribution does not automatically mount the BPF file system you can do so manually by executing mount -t bpf bpffs /sys/fs/bpf as root or making it part of a setup/initialization script.
