/*
Limit socket bind and socket connect to range per-person.

All ports in the 8000-8999 range are blocked. This stops most default
HTTP ports (jupyter-lab, python -m http.server, etc).

Each uid then gets 10 ports starting at 9000.

clang -O2 -target bpf -c -g port_restrict.bpf.c -o port_restrict.o
*/

#include <errno.h>

#include <linux/bpf.h>       // eBPF map and program type definitions.
#include <bpf/bpf_helpers.h> // Helper functions provided by eBPF.
#include <bpf/bpf_endian.h>

// Map to store UID -> port range mappings.
//
struct port_range {
    __u16 min_port;
    __u16 max_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, __u32); // UID
    __type(value, struct port_range); // half-open [min_port, max_port)
} user_port_map SEC(".maps");

// This range is completely banned.
// 8xxx tends to be where http servers default to.
//
const int BAN_MIN_PORT = 8000;
const int BAN_MAX_PORT = 9000;

// No restrictions >= port 10000.
//
const int BAN_PORT_LIMIT = 10000;

const int ALLOW = 1;
const int DENY = 0;

/*
Is this uid allowed to use this port?
Returns 0 if yes, _EPERM if no.
*/
static __always_inline int is_port_allowed(const __u32 uid, const __u16 port) {

    // PORTS in the BAN range are banned.
    // Ports outside our total range are unaffected.
    //
    if ((port>=BAN_MIN_PORT) && (port<BAN_MAX_PORT)) {
        return DENY;
    }

    if ((port < BAN_MIN_PORT) || (port >= BAN_PORT_LIMIT)) {
        return ALLOW;
    }

    struct port_range *range = bpf_map_lookup_elem(&user_port_map, &uid);
    if (range) {
        return ((range->min_port <= port) && (port <range->max_port)) ? ALLOW : DENY;
    }

    // uid not found.
    //
    return DENY;
}

// Restrict bind() calls.
//
SEC("cgroup/bind4")
int bind4_prog(struct bpf_sock_addr *ctx) {
    __u16 port = bpf_ntohs(ctx->user_port);

    if (port == 0) {
        // Kernel-assigned port.
        return ALLOW;
    }

    __u32 dst_ip = bpf_ntohl(ctx->user_ip4);
    if (dst_ip == 0) {
        return DENY;
    }

    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    return is_port_allowed(uid, port);
}

SEC("cgroup/bind6")
int bind6_prog(struct bpf_sock_addr *ctx) {
    __u16 port = bpf_ntohs(ctx->user_port);

    if (port == 0) {
        // Kernel-assigned port.
        return ALLOW;
    }

    __u32 *ip6 = ctx->user_ip6;
    if ((ip6[0] == 0) && (ip6[1] == 0) && (ip6[2] == 0) && (ip6[3] == 0)) {
        return DENY;
    }

    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    return is_port_allowed(uid, port);
}

/*
Restrict connect() calls to localhost.
*/
SEC("cgroup/connect4")
int connect4_prog(struct bpf_sock_addr *ctx) {
    // Check for all 127.0.0.0/8 addresses.
    //
    __u32 dst_ip = bpf_ntohl(ctx->user_ip4);
    if ((dst_ip & 0xFF000000) == 0x7F000000) {
        __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        __u16 port = bpf_ntohs(ctx->user_port);
        return is_port_allowed(uid, port);
    }

    return ALLOW;
}

SEC("cgroup/connect6")
int connect6_prog(struct bpf_sock_addr *ctx) {
    // Check for all ::1 addresses.
    //
    __u32 *ip6 = ctx->user_ip6;
    if ((ip6[0] == 0) && (ip6[1] == 0) && (ip6[2] == 0) && (ip6[3] == bpf_htonl(1))) {
        __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        __u16 port = bpf_ntohs(ctx->user_port);
        return is_port_allowed(uid, port);
    }

    return ALLOW;
}