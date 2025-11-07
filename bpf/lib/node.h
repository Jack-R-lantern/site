#pragma once

#include <linux/bpf.h>
#include <linux/ip.h>

#include "ip.h"

#define DEFAULT_NODE_MAP_MAX_ENTRIES	8192

struct node_key {
	__be32	saddr;
	__be32	daddr;
	__u8	protocol;
	__u8	pad[7];
};

struct node_val {
	__u64	bytes;
	__u64	last_seen;
};

static __always_inline void parse_node_key(struct node_key *key, struct __sk_buff *skb) {
	struct iphdr *ip = 0;
	parse_iphdr(skb, &ip);

	key->saddr = ip->saddr;
	key->daddr = ip->daddr;
	key->protocol = ip->protocol;
}

static __always_inline struct node_val *get_node_value(struct node_key *key, void* map) {
	struct node_val *v = bpf_map_lookup_elem(map, key);
	if (v) {
		return v;
	}

	struct node_val init = {};
	int ret = bpf_map_update_elem(map, key, &init, BPF_NOEXIST);
	if (ret && ret != -EEXIST) {
		return NULL;	// -ENOMEM, -E2BIG 
	}

	/*
	 * In this case:
	 * - Creation Succeeded (ret == 0), or
	 * - Due to a race condition, someone has already created it (ret == -EEXIST)
	 */
	return bpf_map_lookup_elem(map, key);
}