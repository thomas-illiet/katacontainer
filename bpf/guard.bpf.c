// SPDX-License-Identifier: Apache-2.0
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/socket.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* UAPI headers intentionally omit these libc constants for BPF builds. */
#define AF_INET 2
#define AF_INET6 10
#define SOCK_STREAM 1
#define SOCK_DGRAM 2

enum metric_id {
	METRIC_ALLOWED = 0,
	METRIC_DENIED = 1,
	METRIC_DENIED_IPV4 = 2,
	METRIC_DENIED_IPV6 = 3,
	METRIC_DENIED_PROTOCOL = 4,
	METRIC_LOOKUP_ERROR = 5,
	METRIC_MAX = 6,
};

struct ipv4_lpm_key {
	__u32 prefixlen;
	__u8 protocol;
	__u8 pad;
	__u8 port[2];
	__u8 address[4];
};

struct ipv6_lpm_key {
	__u32 prefixlen;
	__u8 protocol;
	__u8 pad;
	__u8 port[2];
	__u8 address[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct ipv4_lpm_key);
	__type(value, __u8);
} allowed_ipv4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct ipv6_lpm_key);
	__type(value, __u8);
} allowed_ipv6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, METRIC_MAX);
	__type(key, __u32);
	__type(value, __u64);
} counters SEC(".maps");

static __always_inline void count(__u32 id)
{
	__u64 *value = bpf_map_lookup_elem(&counters, &id);
	if (value)
		__sync_fetch_and_add(value, 1);
}

static __always_inline int is_loopback4(__u32 address)
{
	return (bpf_ntohl(address) & 0xff000000U) == 0x7f000000U;
}

static __always_inline int is_loopback6(const __u32 address[4])
{
	return address[0] == 0 && address[1] == 0 && address[2] == 0 &&
	       address[3] == bpf_htonl(1);
}

static __always_inline int check4(struct bpf_sock_addr *ctx)
{
	if (is_loopback4(ctx->user_ip4)) {
		count(METRIC_ALLOWED);
		return 1;
	}
	struct ipv4_lpm_key key = {
		.prefixlen = 64,
		.protocol = ctx->protocol,
	};
	__builtin_memcpy(key.port, &ctx->user_port, sizeof(key.port));
	__builtin_memcpy(key.address, &ctx->user_ip4, sizeof(key.address));
	if (bpf_map_lookup_elem(&allowed_ipv4, &key)) {
		count(METRIC_ALLOWED);
		return 1;
	}
	count(METRIC_DENIED);
	count(METRIC_DENIED_IPV4);
	return 0;
}

static __always_inline int check6(struct bpf_sock_addr *ctx)
{
	if (is_loopback6(ctx->user_ip6)) {
		count(METRIC_ALLOWED);
		return 1;
	}
	struct ipv6_lpm_key key = {
		.prefixlen = 160,
		.protocol = ctx->protocol,
	};
	__builtin_memcpy(key.port, &ctx->user_port, sizeof(key.port));
	__builtin_memcpy(key.address, ctx->user_ip6, sizeof(key.address));
	if (bpf_map_lookup_elem(&allowed_ipv6, &key)) {
		count(METRIC_ALLOWED);
		return 1;
	}
	count(METRIC_DENIED);
	count(METRIC_DENIED_IPV6);
	return 0;
}

SEC("cgroup/connect4")
int guard_connect4(struct bpf_sock_addr *ctx) { return check4(ctx); }

SEC("cgroup/connect6")
int guard_connect6(struct bpf_sock_addr *ctx) { return check6(ctx); }

SEC("cgroup/sendmsg4")
int guard_sendmsg4(struct bpf_sock_addr *ctx) { return check4(ctx); }

SEC("cgroup/sendmsg6")
int guard_sendmsg6(struct bpf_sock_addr *ctx) { return check6(ctx); }

SEC("cgroup/sock_create")
int guard_sock_create(struct bpf_sock *ctx)
{
	if (ctx->family != AF_INET && ctx->family != AF_INET6)
		return 1;

	if ((ctx->type == SOCK_STREAM && (ctx->protocol == 0 || ctx->protocol == IPPROTO_TCP)) ||
	    (ctx->type == SOCK_DGRAM && (ctx->protocol == 0 || ctx->protocol == IPPROTO_UDP)))
		return 1;

	count(METRIC_DENIED);
	count(METRIC_DENIED_PROTOCOL);
	return 0;
}

char LICENSE[] SEC("license") = "Apache-2.0";
