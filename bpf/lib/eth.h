#pragma once

#include <stdbool.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define VLAN_HLEN	4

static __always_inline bool eth_is_supported_ethertype(__be16 proto) {
	/* non-Ethernet II unsupported */
	return proto >= bpf_htons(ETH_P_802_3_MIN);
}

static __always_inline __u64 ethhdr_len(struct __sk_buff *skb) {
	if (skb->vlan_present) {
		return ETH_HLEN + VLAN_HLEN;
	} else {
		return ETH_HLEN;
	}
}

static __always_inline bool validate_ethertype(struct __sk_buff *skb, __u16* proto) {
	const __u64 tot_len = ethhdr_len(skb);
	void *data_end = (void*)(unsigned long long)skb->data_end;
	void *data = (void*)(unsigned long long)skb->data;
	struct ethhdr *eth;

	if (data + tot_len > data_end) {
		return false;
	}

	eth = data;

	*proto = eth->h_proto;

	return eth_is_supported_ethertype(*proto);
}