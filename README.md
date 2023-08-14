# Author: 

Linkin Shan <cs@nexet.hk>

## Description:

XDP program to filter VLAN tagged packets with VLAN ID 103 and UDP packets with port 123. Main purpose is to prevent NTP amplification attacks.



## The XDP program:


- Check Vlan Tagged packets.

```c
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
    
```