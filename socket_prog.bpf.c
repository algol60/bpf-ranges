/*
Limit socket bind and socket connect ta range per-person.
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

struct socket {
	int state;
	short int type;
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

#include <stdint.h>          // Standard integer definitions (e.g., uint64_t)
#include <string.h>
#include <errno.h>

#include <linux/net.h>
#include <linux/types.h>     // Linux-specific types (e.g., __u32, __u64)
#include <linux/bpf.h>       // eBPF map and program type definitions (e.g., BPF_MAP_TYPE_RINGBUF)
#include <bpf/bpf_helpers.h> // Helper functions provided by eBPF (e.g., bpf_get_current_pid_tgid)
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h> // For working with tracepoints
#include <linux/limits.h>    // For PATH_MAX (maximum file path length)

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

// A license declaration is mandatory for eBPF programs
// "Dual BSD/GPL" ensures compatibility with all helper functions
char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define LOCALHOST 0x7f000001
static const uint8_t localhost_bytes[] =
        { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

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

static int is_allowed(uint32_t uid, uint16_t port) {
    if ((port<=1023)
        || ((uid==1000) && (10000<=port) && (port<10010))
        || ((uid==1001) && (10010<=port) && (port<10019))
    ) {
        return 0;
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

    // Only IPv4 allowed.
    // Disable IPv6, or test for it here.
    //
    // if (address->sa_family == AF_INET6) {
    //     return 0;//-EPERM;
    // }
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
        bpf_printk("RESTRICT %s family=%d uid=%u addr=%u port=%u type=%u\n", which, address->sa_family, uid, addr4, port, stype);

        if (addr4!=LOCALHOST) {
            return -EPERM;
        }

        return is_allowed(uid, port);
    } else if (address->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)address;
        in_port_t port =  bpf_ntohs(sin6->sin6_port);
        struct in6_addr dst_addr;
        bpf_probe_read_kernel(&dst_addr, sizeof(dst_addr), &sin6->sin6_addr);

        short int stype = sock->type;
        bpf_printk("RESTRICT %s family=%d uid=%u addr=%pI6c port=%u type=%u\n", which, address->sa_family, uid, &dst_addr, port, stype);

        int is_localhost = memcmp(dst_addr.s6_addr, localhost_bytes, sizeof(dst_addr)) == 0;
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

// // Define a ring buffer map to transfer events from kernel space to user space
// // This map will live in the ".maps" ELF section and is required for event streaming
// struct {
//     __uint(type, BPF_MAP_TYPE_RINGBUF); // Specify that this is a ring buffer map
//     __uint(max_entries, 32768);         // Maximum size (in bytes) of the buffer
// } exec_ringbuf SEC(".maps");            // SEC macro tells the loader this is a BPF map

// // Define the structure of the event we will send to user space
// // This includes metadata (pid, uid, timestamp) and the executed filename
// struct event_t {
//     int pid;                          // Process ID
//     int uid;                          // User ID
//     long int timestamp;               // Timestamp in nanoseconds
//     char filename[PATH_MAX];          // Executed filename (full path)
// };

// // This struct matches the tracepoint argument format for sys_enter_execve
// // To find the exact layout of any syscall tracepoint, inspect:
// // /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format
// struct sys_enter_execve_args {
//     char _[16];         // Padding for internal tracepoint fields (not used)
//     uint64_t filename_ptr; // Pointer to the filename string
//     uint64_t argv;         // Pointer to argv
//     uint64_t envp;         // Pointer to envp
// };

// // Define the eBPF program that will run on the tracepoint "sys_enter_execve"
// // This tracepoint is triggered whenever a process calls execve()
// SEC("tracepoint/syscalls/sys_enter_execve")
// int trace_execve(struct sys_enter_execve_args *ctx)
// {
//     struct event_t *event;

//     // Reserve space in the ring buffer for our event
//     // If the reservation fails (e.g., buffer is full), exit early
//     event = bpf_ringbuf_reserve(&exec_ringbuf, sizeof(*event), 0);
//     if (!event) {
//         return 0;
//     }

//     // Capture metadata: current process ID, user ID, and timestamp
//     event->pid = bpf_get_current_pid_tgid() >> 32; // Upper 32 bits = PID
//     event->uid = bpf_get_current_uid_gid() >> 32;  // Upper 32 bits = UID
//     event->timestamp = bpf_ktime_get_ns();         // Nanosecond-resolution timestamp

//     // Read the filename pointer from tracepoint arguments
//     char *filename_ptr = (char *)ctx->filename_ptr;

//     // Safely copy the filename string from user space into our event struct
//     // If the read fails (e.g., invalid pointer), discard the event and return
//     if (bpf_probe_read_user_str(event->filename, PATH_MAX, filename_ptr) < 0) {
//         bpf_ringbuf_discard(event, 0); // Release reserved space in the ringbuf
//         return -1;
//     }

//     // Print to kernel debug trace buffer for quick testing/logging
//     // You can view this with: sudo cat /sys/kernel/debug/tracing/trace_pipe
//     bpf_printk("%d %d %s\n", event->pid, event->uid, event->filename);

//     // Submit the event to the ring buffer so it can be consumed in user space
//     bpf_ringbuf_submit(event, 0);

//     return 0;
// }
