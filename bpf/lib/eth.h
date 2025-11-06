#pragma once

#include <stdbool.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

static __always_inline bool eth_is_supported_ethertype(__be16 proto) {
	/* non-Ethernet II unsupported */
	return proto >= bpf_htons(ETH_P_802_3_MIN);
}

static __always_inline bool validate_ethertype(struct __sk_buff *skb, int l2_off, __u16* proto) {
	const __u64 tot_len = l2_off + ETH_HLEN;
	void *data_end = (void*)(unsigned long long)skb->data_end;
	void *data = (void*)(unsigned long long)skb->data;
	struct ethhdr *eth;

	if (data + tot_len > data_end) {
		return false;
	}

	eth = data + l2_off;

	*proto = eth->h_proto;

	return eth_is_supported_ethertype(*proto);
}