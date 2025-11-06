#pragma once

#include <linux/bpf.h>

#define DEFAULT_POD_MAP_MAX_ENTRIES	8192

#define CGROUP_SKB_DROP	0
#define CGROUP_SKB_PASS	1

struct pod_key {
	__u32	saddr;
	__u32	daddr;
	__u8	proto;
	__u16	dport;
	__u8	pad[5];
};
