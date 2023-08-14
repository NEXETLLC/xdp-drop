//  Author: Linkin Shan <cs@nexet.hk>
//  Date: 2023-08-15
//  Description:
//  XDP program to filter VLAN tagged packets with VLAN ID 103 and UDP packets with port 123.
//  Main purpose is to prevent NTP amplification attacks.
#include <stdint.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/ip.h>
#include <linux/udp.h>
#define SEC(NAME) __attribute__((section(NAME), used))

// VLAN header structure definition
struct vlan_hdr {
    __be16 h_vlan_TCI;                     // VLAN Tag Control Information
    __be16 h_vlan_encapsulated_proto;      // Encapsulated frame's Ethertype field
};

// Function to convert 16-bit host byte order value to network byte order.
static inline __be16 htons(__u16 hostshort) {
return ((__be16) ((hostshort & 0xFF) << 8) | ((hostshort & 0xFF00) >> 8));
}

// Function to convert 32-bit host byte order value to network byte order.
static inline __be32 htonl(__u32 hostlong) {
return ((__be32) ((hostlong & 0xFF) << 24) | ((hostlong & 0xFF00) << 8) | ((hostlong & 0xFF0000) >> 8) | ((hostlong & 0xFF000000) >> 24));
}

// Main XDP program
SEC("xdp")
int filter_vlan_and_udp_prog(struct xdp_md *ctx) {
    // Pointers to packet data and end of packet
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;   // Ethernet header
    struct iphdr *iph;           // IP header

    // Ensure the packet has enough data for Ethernet header
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    // Check if packet is VLAN tagged
    if (eth->h_proto == htons(ETH_P_8021Q)) {
        struct vlan_hdr *vhdr = (struct vlan_hdr *)(eth + 1);
        // Ensure the packet has enough data for VLAN header
        if ((void *)(vhdr + 1) > data_end)
            return XDP_PASS;
        // Drop packets with VLAN ID 103
        if (vhdr->h_vlan_TCI == htons(103))
            return XDP_DROP;
        // Only process packets with IP payload
        if (vhdr->h_vlan_encapsulated_proto != htons(ETH_P_IP))
            return XDP_PASS;
        iph = (struct iphdr *)(vhdr + 1);
    } else if (eth->h_proto == htons(ETH_P_IP)) {
        iph = (struct iphdr *)(eth + 1);
    } else {
        return XDP_PASS;
    }

    // Ensure the packet has enough data for IP header
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    // Check if the packet is UDP
    if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)(iph + 1);
        // Ensure the packet has enough data for UDP header
        if ((void *)(udph + 1) > data_end)
            return XDP_PASS;
        // Drop packets with UDP port 123 (either source or destination)
        if (udph->source == htons(123) || udph->dest == htons(123))
            return XDP_DROP;
    }

    // Allow all other packets
    return XDP_PASS;
}

// License required for loading the BPF program into the kernel
char _license[] SEC("license") = "GPL";
