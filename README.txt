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

(32-bit libraries)
# dnf install glibc-devel.i686

##

(load and attach)

# bpftool prog load execve_prog.o /sys/fs/bpf/execve_prog autoattach
# bpftool prog show

# cat /sys/kernel/debug/tracing/trace_pipe


bpftrace -e 'tracepoint:syscalls:sys_enter_bind { printf("%s (PID %d) is binding a socket\n", comm, pid); }'

sys_enter_connect ?

Loading a ProgramUse the bpftool prog load command to load a compiled BPF object file into the kernel and pin it to a path to keep it alive.Command: sudo bpftool prog load <object_file.o> <pin_path> [type <type>]Example: sudo bpftool prog load hello.bpf.o /sys/fs/bpf/my_prog.Auto-attach: Adding autoattach to the command will automatically attach the program to its target (like a tracepoint or interface) immediately after loading.Unloading a ProgramIn eBPF, a program remains in the kernel as long as there is a reference to it (such as a pinned file, an active attachment, or an open file descriptor). To "unload" it, you must remove all these references.Detach from the interface: If the program is attached to a network interface (e.g., XDP), you must first detach it.XDP Example: sudo bpftool net detach xdp dev eth0.Delete the pin: Remove the pinned file from the BPF file system using standard file commands.Command: sudo rm /sys/fs/bpf/my_prog.

# cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve
# bfptrace -lv tracepoint:syscalls:sys_enter_execve

... sys_enter_bind
... sys_enter_connect

If your Linux distribution does not automatically mount the BPF file system you can do so manually by executing mount -t bpf bpffs /sys/fs/bpf as root or making it part of a setup/initialization script.
