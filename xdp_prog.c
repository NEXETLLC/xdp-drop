#include <stdint.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/ip.h>
#include <linux/udp.h>
#define SEC(NAME) __attribute__((section(NAME), used))

#define htons(x) ((__be16)___constant_swab16((x)))
#define htonl(x) ((__be32)___constant_swab32((x)))

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

#define bpf_printk(fmt, ...)                              \
({                                                        \
  char ____fmt[] = fmt;                                   \
  bpf_trace_printk(____fmt, sizeof(____fmt),              \
                   ##__VA_ARGS__);                        \
})

SEC("xdp_drop")
int xdp_drop_prog(struct xdp_md *ctx) {

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;

	uint64_t nh_off = sizeof(*eth);
    if (data + nh_off > data_end) {
		return XDP_PASS;
	}

	uint16_t h_proto = eth->h_proto;
    if (h_proto == htons(ETH_P_IP)) {
		struct iphdr *iph = data + nh_off;
		struct udphdr *udph = data + nh_off + sizeof(struct iphdr);
		if (udph + 1 > (struct udphdr *)data_end) {
			return XDP_PASS;
		}
		if (iph->protocol == IPPROTO_UDP 
		    && udph->source == htons(123)) {
			return XDP_DROP;
		}
	}


        return XDP_PASS;
}

char _license[] SEC("license") = "GPL";