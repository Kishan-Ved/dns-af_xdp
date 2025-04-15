/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/in.h>          /* For __constant_htons and __constant_ntohs */
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/bpf.h>
#include <linux/ipv6.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_packet.h>


struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xsks_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 64);
} xdp_stats_map SEC(".maps");

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

/* Packet parsing helpers.
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in network byte order.
 */

static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
    void *data_end,
    struct ethhdr **ethhdr)
{
    struct ethhdr *eth = nh->pos;
    int hdrsize = sizeof(*eth);

    // Check that the full Ethernet header is within packet bounds
    if ((void*)nh->pos + hdrsize > data_end)
    return -1;

    nh->pos += hdrsize;
    *ethhdr = eth;

    return eth->h_proto; // in network byte order
}


static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
    void *data_end,
    struct ipv6hdr **ip6hdr)
{
    struct ipv6hdr *ip6h = nh->pos;

    /* Pointer-arithmetic bounds check; pointer +1 points to after end of
    * thing being pointed to. We will be using this style in the remainder
    * of the tutorial.
    */
   if ((void*)ip6h + sizeof(*ip6h) > data_end)
   return -1;


    nh->pos = ip6h + 1;
    *ip6hdr = ip6h;

    return ip6h->nexthdr;
}


static __always_inline int parse_iphdr(struct hdr_cursor *nh,
    void *data_end,
    struct iphdr **iphdr)
{
    struct iphdr *iph = nh->pos;
    int hdrsize;

    if (iph + 1 > data_end)
    return -1;

    hdrsize = iph->ihl * 4;
    /* Sanity check packet field is valid */
    if(hdrsize < sizeof(*iph))
    return -1;

    /* Variable-length IPv4 header, need to use byte-based arithmetic */
    if (nh->pos + hdrsize > data_end)
    return -1;

    nh->pos += hdrsize;
    *iphdr = iph;

    return iph->protocol;
}

/*
 * parse_udphdr: parse the udp header and return the length of the udp payload
 */
static __always_inline int parse_udphdr(struct hdr_cursor *nh,
    void *data_end,
    struct udphdr **udphdr)
{
    int len;
    struct udphdr *h = nh->pos;

    if ((void*)h + sizeof(*h) > data_end)
    return -1;

    nh->pos  = h + 1;
    *udphdr = h;

    len = bpf_ntohs(h->len) - sizeof(struct udphdr);
    if (len < 0)
    return -1;

    return len;
}


SEC("xdp_dns_filter")
int xdp_dns_filter_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    int index = ctx->rx_queue_index;

    struct ethhdr *eth;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
    struct udphdr *udphdr;

    struct hdr_cursor nh;
    int eth_type;
	int ip_type;
    int udp_len;

    /* Start next header cursor position at data start */
    nh.pos = data;

    /* Parse the Ethernet and IP headers */
    eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type != IPPROTO_UDP)
			return XDP_PASS;
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
		if (ip_type != IPPROTO_UDP)
			return XDP_PASS;
	} else {
		return XDP_PASS;
	}

    /* Check if the packet is a DNS query */
    if (ip_type == IPPROTO_UDP) {
        udp_len = parse_udphdr(&nh, data_end, &udphdr);
        if (udp_len < 0)
            return XDP_PASS;

        // Only process DNS queries: UDP dest port must be 53
        if (udphdr->dest != bpf_htons(53))
            return XDP_PASS;  
        
        /* A set entry here means that the correspnding queue_id
            * has an active AF_XDP socket bound to it. */
        if (bpf_map_lookup_elem(&xsks_map, &index))
            return bpf_redirect_map(&xsks_map, index, 0);
    }

    return XDP_PASS; // Pass all other packets
}

char _license[] SEC("license") = "GPL";