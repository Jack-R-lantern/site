#pragma once

#include <linux/bpf.h>
#include <linux/ip.h>

static __always_inline bool validate_iphdr(struct __sk_buff *skb, int l3_off, struct iphdr **ip) {
	const __u64 tot_len = l3_off + sizeof(struct iphdr);
	void *data_end = (void*)(unsigned long long)skb->data_end;
	void *data = (void*)(unsigned long long)(skb->data + l3_off);

	if (data + tot_len > data_end) {
		return false;
	}

	*ip = (struct iphdr*)data;

	return true;
}