#pragma once

#include <stdbool.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

static __always_inline bool validate_iphdr(struct __sk_buff *skb, __u64 l3_off) {
	const __u64 tot_len = l3_off + sizeof(struct iphdr);
	void *data_end = (void*)(unsigned long long)skb->data_end;
	void *data = (void*)(unsigned long long)(skb->data) + l3_off;

	if (data + tot_len > data_end) {
		return false;
	}

	return true;
}

static __always_inline void parse_iphdr(struct __sk_buff *skb, struct iphdr **ip) {
	void *data = (void*)(unsigned long long)(skb->data) + ETH_HLEN;
	*ip = (struct iphdr*)data;
}