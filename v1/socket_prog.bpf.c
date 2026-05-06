/*
Limit socket bind and socket connect to range per-person.

All ports in the 8000-8999 range are blocked. This stops most default
HTTP ports (jupyter-lab, python -m http.server, etc).

Each uid then gets 10 ports starting at 9000.

TODO only block ports on local addresses.
*/

// enum sock_type {
// 	SOCK_STREAM = 1,
// 	SOCK_DGRAM = 2,
// 	SOCK_RAW = 3,
// 	SOCK_RDM = 4,
// 	SOCK_SEQPACKET = 5,
// 	SOCK_DCCP = 6,
// 	SOCK_PACKET = 10,
// };

#include <stdint.h>     // Standard integer definitions (e.g., uint64_t)

// Copy enough of struct socket from vmlinux.h to get the type.
//
struct socket {
	int32_t state;
	int16_t type;
	// long unsigned int flags;
	// struct file *file;
	// struct sock *sk;
	// const struct proto_ops *ops;
	// long: 64;
	// long: 64;
	// long: 64;
	// struct socket_wq wq;
};

// // bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
// #include "vmlinux.h"
// #define EPERM 1
// #define AF_INET 2

#include <string.h>
#include <errno.h>

#include <linux/net.h>
#include <linux/types.h>     // Linux-specific types (e.g., __u32, __u64)
#include <linux/bpf.h>       // eBPF map and program type definitions (e.g., BPF_MAP_TYPE_RINGBUF)
#include <bpf/bpf_helpers.h> // Helper functions provided by eBPF (e.g., bpf_get_current_pid_tgid)
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h> // For working with tracepoints

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

// A license declaration is mandatory for eBPF programs
// "Dual BSD/GPL" ensures compatibility with all helper functions
char LICENSE[] SEC("license") = "Dual BSD/GPL";

// #define LOCALHOST 0x7f000001
static const uint32_t LOCALHOST4 = 0x7f000001;
static const uint8_t LOCALHOST6[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

#if __has_include("local_if.h")
    // Include output from local_info.
    //
    #include "local_if.h"
#else
    int addresses4[] = {
    // Interface: lo
    0x7f000001, // 127.0.0.1
    };
    uint8_t addresses6[][16] = {
    // Interface: lo
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, },
    };
#endif

/*
# bpftrace -lv tracepoint:syscalls:sys_enter_bind
tracepoint:syscalls:sys_enter_bind
    int __syscall_nr
    int fd
    struct sockaddr * umyaddr
    int addrlen

# cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_bind/format
name: sys_enter_bind
ID: 1826
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:int fd;   offset:16;      size:8; signed:0;
        field:struct sockaddr * umyaddr;        offset:24;      size:8; signed:0;
        field:int addrlen;      offset:32;      size:8; signed:0;

print fmt: "fd: 0x%08lx, umyaddr: 0x%08lx, addrlen: 0x%08lx", ((unsigned long)(REC->fd)), ((unsigned long)(REC->umyaddr)), ((unsigned long)(REC->addrlen))
*/

// struct sys_enter_bind_args {
//     char _[16];         // Padding for internal tracepoint fields (not used)
//     uint64_t fd;
//     uint64_t umyaddr;   // Pointer to struct sockaddr
//     uint64_t addrlen;
// };

const int MIN_PORT = 8000;
const int BASE_PORT = 9000;
const int MAX_PORT = 10000;
const int RANGE = 10;

static int uids[] = {1000, 1001, 1002};

static int is_allowed(uint32_t uid, uint16_t port) {

    // Ports outside our range are unaffected.
    //
    if ((port<MIN_PORT) || (port>=MAX_PORT)) {
        return 0;
    } else if(port<BASE_PORT) {
        return -EPERM;
    }

    // Each user gets their own range.
    // Loop through the uids array.
    // When the matching uid is found, check the range.
    //
    int base = BASE_PORT;
    for (int i=0; i<sizeof(uids)/sizeof(int); i++) {
        const int u = uids[i];
        if (u==uid) {
            return (base<=port) && (port<base+RANGE) ? 0 : -EPERM;
        }

        base += RANGE;
    }

    return -EPERM;
}

static int restrict_sock(struct socket *sock, struct sockaddr *address, int addrlen, int ret, char *which) {

    // If the call has failed, return the failure.
    //
    if (ret != 0) {
        return ret;
    }
    // If not a "normal" user, everything is allowed.
    //
    const uint32_t uid = bpf_get_current_uid_gid() >> 32;  // Upper 32 bits = UID
    if ((uid < 1000) || (uid==65534)) {
        return 0;
    }

    bpf_printk("RESTRICT %s family=%d\n", which, address->sa_family);

    if (address->sa_family == AF_INET) {
        // Which address and port?
        //
        struct sockaddr_in *sin4 = (struct sockaddr_in *)address;
        uint16_t port = bpf_ntohs(sin4->sin_port);
        uint32_t addr4 = bpf_ntohl(sin4->sin_addr.s_addr);

        // Print to kernel debug trace buffer for quick testing/logging.
        // View this with: sudo cat /sys/kernel/debug/tracing/trace_pipe.
        //
        short int stype = sock->type;
        bpf_printk("RESTRICT4 %s family=%d uid=%u addr=0c%08x port=%u type=%u\n", which, address->sa_family, uid, addr4, port, stype);

        // TODO only block local addresses.
        if (addr4!=LOCALHOST4) {
            return -EPERM;
        }

        return is_allowed(uid, port);
    } else if (address->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)address;
        in_port_t port =  bpf_ntohs(sin6->sin6_port);
        struct in6_addr dst_addr;
        bpf_probe_read_kernel(&dst_addr, sizeof(dst_addr), &sin6->sin6_addr);

        short int stype = sock->type;
        bpf_printk("RESTRICT6 %s family=%d uid=%u addr=%pI6c port=%u type=%u\n", which, address->sa_family, uid, &dst_addr, port, stype);

        // TODO only block local addresses.
        int is_localhost = memcmp(dst_addr.s6_addr, LOCALHOST6, sizeof(dst_addr)) == 0;
        if (!is_localhost) {
            return -EPERM;
        }

        return is_allowed(uid, port);
    }

    return 0;
}

SEC("lsm/socket_bind")
int BPF_PROG(restrict_bind, struct socket *sock, struct sockaddr *address, int addrlen, int ret) {
    return restrict_sock(sock, address, addrlen, ret, "BIND");
}

// int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

/*
# bpftrace -lv tracepoint:syscalls:sys_enter_connect
tracepoint:syscalls:sys_enter_connect
    int __syscall_nr
    int fd
    struct sockaddr * uservaddr
    int addrlen

# cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_connect/format
name: sys_enter_connect
ID: 1818
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:int fd;   offset:16;      size:8; signed:0;
        field:struct sockaddr * uservaddr;      offset:24;      size:8; signed:0;
        field:int addrlen;      offset:32;      size:8; signed:0;

print fmt: "fd: 0x%08lx, uservaddr: 0x%08lx, addrlen: 0x%08lx", ((unsigned long)(REC->fd)), ((unsigned long)(REC->uservaddr)), ((unsigned long)(REC->addrlen))
*/

SEC("lsm/socket_connect")
int BPF_PROG(restrict_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret) {
    return restrict_sock(sock, address, addrlen, ret, "CONNECT");
}
