#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#define GHOST_AF_INET 2
#define GHOST_AF_INET6 10
#define GHOST_IPPROTO_TCP 6
#define GHOST_IPPROTO_UDP 17
#define GHOST_TCP_LISTEN 10

struct ghostscan_listener_key {
    __u8 proto;
    __u8 family;
    __u16 port;
    __u8 addr[16];
};

struct ghostscan_listener_value {
    __u32 state;
    __u32 netns_inum;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ghostscan_listener_key);
    __type(value, struct ghostscan_listener_value);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ghostscan_listener_sockets SEC(".maps");

static __always_inline void record_sock_common(const struct sock_common *common, __u8 proto, __u32 state)
{
    if (!common) {
        return;
    }

    __u16 fam = 0;
    BPF_CORE_READ_INTO(&fam, common, skc_family);
    if (fam != GHOST_AF_INET && fam != GHOST_AF_INET6) {
        return;
    }

    __u16 num = 0;
    BPF_CORE_READ_INTO(&num, common, skc_num);
    if (num == 0) {
        return;
    }

    if (proto == GHOST_IPPROTO_TCP && state != GHOST_TCP_LISTEN) {
        return;
    }

    struct ghostscan_listener_key key = {
        .proto = proto,
        .family = fam,
        .port = num,
        .addr = {0},
    };

    if (fam == GHOST_AF_INET) {
        __be32 v4 = 0;
        BPF_CORE_READ_INTO(&v4, common, skc_rcv_saddr);
        __builtin_memcpy(&key.addr[0], &v4, sizeof(v4));
    } else {
        struct in6_addr v6 = {};
        BPF_CORE_READ_INTO(&v6, common, skc_v6_rcv_saddr);
        __builtin_memcpy(&key.addr[0], &v6, sizeof(v6));
    }

    struct ghostscan_listener_value value = {
        .state = state,
        .netns_inum = 0,
    };

    struct net *net = NULL;
    BPF_CORE_READ_INTO(&net, common, skc_net.net);
    if (net) {
        value.netns_inum = BPF_CORE_READ(net, ns.inum);
    }

    bpf_map_update_elem(&ghostscan_listener_sockets, &key, &value, BPF_ANY);
}

SEC("iter/tcp")
int ghostscan_iter_tcp(struct bpf_iter__tcp *ctx)
{
    struct sock_common *common = ctx->sk_common;
    __u32 state = 0;

    if (common) {
        state = BPF_CORE_READ(common, skc_state);
    }

    record_sock_common(common, GHOST_IPPROTO_TCP, state);
    return 0;
}

SEC("iter/udp")
int ghostscan_iter_udp(struct bpf_iter__udp *ctx)
{
    struct sock_common *common = NULL;
    struct udp_sock *udp = ctx->udp_sk;
    if (udp) {
        common = &udp->inet.sk.__sk_common;
    }
    __u32 state = 0;

    if (common) {
        state = BPF_CORE_READ(common, skc_state);
    }

    record_sock_common(common, GHOST_IPPROTO_UDP, state);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
