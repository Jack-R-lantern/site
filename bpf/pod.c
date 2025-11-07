#include <linux/bpf.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>

#include "lib/eth.h"
#include "lib/pod.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct pod_key);
	__type(value, struct pod_val);
	__uint(max_entries, DEFAULT_POD_MAP_MAX_ENTRIES);
} pod_ingress_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct pod_key);
	__type(value, struct pod_val);
	__uint(max_entries, DEFAULT_POD_MAP_MAX_ENTRIES);
} pod_egress_map SEC(".maps");

/*
 * The section name above the program is not important.
 * This is merely a configuration for compatibility with libbpf.
 * Since the program type is BPF_PROG_TYPE_SCHED_CLS,
 * it can be attached to tcx or netkit.
 */


SEC("tcx/ingress")
int tc_pod_ingress(struct __sk_buff *skb) {
	__be16 proto = 0;
	struct pod_key key = {};
	struct pod_val val = {};

	if (!validate_ethertype(skb, &proto)) {
		goto skip;
	}

	switch (proto) {
	case bpf_htons(ETH_P_IP):
		if (!validate_iphdr(skb, ethhdr_len(skb))) {
			goto skip;
		}
		parse_pod_key(&key, skb, ethhdr_len(skb));

		struct pod_val *exist = 0;
		exist = get_pod_value(&key, &pod_ingress_map);

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
int tc_pod_egress(struct __sk_buff *skb) {
	__be16 proto = 0;
	struct pod_key key = {};
	struct pod_val val = {};

	if (!validate_ethertype(skb, &proto)) {
		goto skip;
	}

	switch (proto) {
	case bpf_htons(ETH_P_IP):
		if (!validate_iphdr(skb, ethhdr_len(skb))) {
			goto skip;
		}
		parse_pod_key(&key, skb, ethhdr_len(skb));

		struct pod_val *exist = 0;
		exist = get_pod_value(&key, &pod_egress_map);

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

/*
 * The section name above the program is not important.
 * This is merely a configuration for compatibility with libbpf.
 * Since the program type is BPF_PROG_TYPE_CGROUP_SKB,
 */

SEC("cgroup_skb/ingress")
int cgroup_pod_ingress(struct __sk_buff *skb) {
	struct pod_key key = {};
	struct pod_val val = {};

	if (!validate_iphdr(skb, 0)) {
		goto skip;
	}

	switch (skb->protocol) {
	case bpf_htons(ETH_P_IP):
		parse_pod_key(&key, skb, 0);

		struct pod_val *exist = 0;
		exist = get_pod_value(&key, &pod_ingress_map);

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
	return CGROUP_SKB_PASS;
}

SEC("cgroup_skb/egress")
int cgroup_pod_egress(struct __sk_buff *skb) {
	struct pod_key key = {};
	struct pod_val val = {};

	if (!validate_iphdr(skb, 0)) {
		goto skip;
	}

	switch (skb->protocol) {
	case bpf_htons(ETH_P_IP):
		parse_pod_key(&key, skb, 0);

		struct pod_val *exist = 0;
		exist = get_pod_value(&key, &pod_egress_map);

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
	return CGROUP_SKB_PASS;
}