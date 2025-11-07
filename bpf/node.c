#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>

#include "lib/eth.h"
#include "lib/ip.h"
#include "lib/node.h"


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct node_key);
	__type(value, struct node_val);
	__uint(max_entries, DEFAULT_NODE_MAP_MAX_ENTRIES);
} node_ingress_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct node_key);
	__type(value, struct node_val);
	__uint(max_entries, DEFAULT_NODE_MAP_MAX_ENTRIES);
} node_egress_map SEC(".maps");

/*
 * The section name above the program is not important.
 * This is merely a configuration for compatibility with libbpf.
 * Since the program type is BPF_PROG_TYPE_SCHED_CLS,
 * it can be attached to tcx or netkit.
 */


SEC("tcx/ingress")
int node_ingress(struct __sk_buff *skb) {
	__be16 proto = 0;
	struct node_key key = {};
	struct node_val val = {};

	if (!validate_ethertype(skb, &proto)) {
		goto skip;
	}

	switch (proto) {
	case bpf_htons(ETH_P_IP):
		if (!parse_node_key(&key, skb)) {
			goto skip;
		}

		struct node_val *exist = 0;
		exist = get_node_value(&key, &node_ingress_map);

		// TODO
		// - case exist null how to handling
		// - errno NOMEM
		if (exist) {
			__sync_fetch_and_add(&exist->bytes, skb->len);
			exist->last_seen = bpf_ktime_get_ns();
		}
		break;
	default:
		goto skip;
	}	
skip:
	return TC_ACT_OK;
}

SEC("tcx/egress")
int node_egress(struct __sk_buff *skb) {
	__be16 proto = 0;
	struct node_key key = {};
	struct node_val val = {};

	if (!validate_ethertype(skb, &proto)) {
		goto skip;
	}

	switch (proto) {
	case bpf_htons(ETH_P_IP):
		if (!parse_node_key(&key, skb)) {
			goto skip;
		}

		struct node_val *exist = 0;
		exist = get_node_value(&key, &node_egress_map);

		// TODO
		// - case exist null how to handling
		// - errno NOMEM
		if (exist) {
			__sync_fetch_and_add(&exist->bytes, skb->len);
			exist->last_seen = bpf_ktime_get_ns();
		}
	
		break;
	default:
		goto skip;
	}	
skip:
	return TC_ACT_OK;
}