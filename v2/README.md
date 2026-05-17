# Port restrictor

Port restrictor is an eBPF program that allows users to share a Linux system
and use TCP servers (such as `panel serve` and `python -m http.server`)
without other users being able to connect to those servers.

The ports between 8000 and 8999 (inclusive) are banned. Since
HTTP applications (such as jupyter-lab) typically open default ports in
this range, users must explicitly select a different port.

Ranges of ports between 9000 and 9999 (inclusive) may be allocated
to users by specifying a text file containing lines in the format
`username,min_port,max_port`.

```
user1,9000,9009
user2,9010,9019
```

This file allocates ports 9000 to 9009 to user1, and ports 9010 to 9019 to user2.

Within the range `9000,9009`, user1 can bind to a port with a server and
connect to that port with a client. Any attempt to bind or connect to
any other port in the range `8000,10000` will be denied. For example:

```
$ python -m http.server 9999
...
PermissionError: [Errno 1] Operation not permitted
```

## Running the restrictor

This section requires root access.

The restrictor is an object file containing several BPF programs. The object file is loaded
by the `port_restrict_loader` executable. The `port_restrict.o` file must be
in the current directory.

The loader takes one parameter: the path to a configuration file as described above.

After running the loader, the BPF program will be loaded into the kernel. The loaded
programs can be seen using `bpftool`.

```
# bpftool cgroup list /sys/fs/cgroup
ID       AttachType      AttachFlags     Name
1147     cgroup_inet4_bind                 bind4_prog
1149     cgroup_inet6_bind                 bind6_prog
1150     cgroup_inet4_connect                 connect4_prog
1151     cgroup_inet6_connect                 connect6_prog
```

For extended information:

```
# bpftool prog show
...
1147: cgroup_sock_addr  name bind4_prog  tag a5d783ece975b6fe
        loaded_at 2026-05-07T17:53:29+1000  uid 0
        xlated 304B  jited 208B  memlock 4096B  map_ids 419,421
        btf_id 1051
1149: cgroup_sock_addr  name bind6_prog  tag dac51f6387ecf2d1
        loaded_at 2026-05-07T17:53:29+1000  uid 0
        xlated 376B  jited 241B  memlock 4096B  map_ids 419,421
        btf_id 1051
1150: cgroup_sock_addr  name connect4_prog  tag 5677da3d8102ecfd
        loaded_at 2026-05-07T17:53:29+1000  uid 0
        xlated 288B  jited 200B  memlock 4096B  map_ids 419,421
        btf_id 1051
1151: cgroup_sock_addr  name connect6_prog  tag 6ff87544f3b6759f
        loaded_at 2026-05-07T17:53:29+1000  uid 0
        xlated 352B  jited 242B  memlock 4096B  map_ids 419,421
        btf_id 1051
```

To update the filters, edit the config file and run the loader again. Use `bfptool`
to see the updated prgoram ids.

## Detaching BPF programs

The `detach` executable removes the restrictor programs from the kernel.

To stop running BPF programs manually, use `bpftool cgroup list /sys/fs/cgroup` to see
the programs, then use `bpftool cgroup detach` to stop them.

```
# bpftool cgroup list /sys/fs/cgroup
ID       AttachType      AttachFlags     Name
672      cgroup_inet4_bind                 bind4_prog
674      cgroup_inet6_bind                 bind6_prog
675      cgroup_inet4_connect                 connect4_prog
676      cgroup_inet6_connect                 connect6_prog

# bpftool cgroup detach /sys/fs/cgroup cgroup_inet4_bind id 672
# bpftool cgroup detach /sys/fs/cgroup cgroup_inet6_bind id 674
# bpftool cgroup detach /sys/fs/cgroup cgroup_inet4_connect id 675
# bpftool cgroup detach /sys/fs/cgroup cgroup_inet6_connect id 676
```