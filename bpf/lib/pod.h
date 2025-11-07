#pragma once

#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/ip.h>

#include "ip.h"

#define DEFAULT_POD_MAP_MAX_ENTRIES	8192

#define CGROUP_SKB_DROP	0
#define CGROUP_SKB_PASS	1

struct pod_key {
	__be32	saddr;
	__be32	daddr;
	__be16	sport;
	__be16	dport;
	__u8	protocol;
	__u8	pad[3];
};

struct pod_val {
	__u64	bytes;
	__u64	last_seen;
};

static __always_inline bool parse_pod_key(struct pod_key *key, struct __sk_buff *skb, __u64 l3_off) {
	struct iphdr *ip = 0;

	if (!parse_iphdr(skb, l3_off, &ip)) {
		return false;
	}

	key->saddr = ip->saddr;
	key->daddr = ip->daddr;
	key->protocol = ip->protocol;

	struct {
		__be16 sport;
		__be16 dport;
	} __attribute__((packed)) ports;

	if (bpf_skb_load_bytes(skb, l3_off + ip->ihl * 4, &ports, 4) < 0) {
		return false;
	}

	key->sport = ports.sport;
	key->dport = ports.dport;

	return true;
}

static __always_inline struct pod_val *get_pod_value(struct pod_key *key, void *map) {
	struct pod_val *v = bpf_map_lookup_elem(map, key);
	if (v) {
		return v;
	}

	struct pod_val init = {};
	int ret = bpf_map_update_elem(map, key, &init, BPF_NOEXIST);
	if (ret && ret != -EEXIST) {
		return NULL;
	}

	/*
	 * In this case:
	 * - Creation Succeeded (ret == 0), or
	 * - Due to a race condition, someone has already created it (ret == -EEXIST)
	 */
	return bpf_map_lookup_elem(map, key);
}