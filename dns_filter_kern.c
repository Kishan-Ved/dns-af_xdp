/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>          /* For __constant_htons and __constant_ntohs */
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xsks_map SEC(".maps");

/* Manual header parsing functions */
static inline int parse_ethhdr(void **data, void *data_end, struct ethhdr **eth)
{
    struct ethhdr *eth_hdr = *data;
    if ((void *)eth_hdr + sizeof(*eth_hdr) > data_end)
        return -1;

    *eth = eth_hdr;
    *data = (void *)eth_hdr + sizeof(*eth_hdr);
    return __constant_htons(eth_hdr->h_proto); /* Return protocol in host byte order */
}

static inline int parse_iphdr(void **data, void *data_end, struct iphdr **iph)
{
    struct iphdr *ip_hdr = *data;
    if ((void *)ip_hdr + sizeof(*ip_hdr) > data_end)
        return -1;

    /* Check IP header length (ihl is in 4-byte units) */
    if ((void *)ip_hdr + (ip_hdr->ihl * 4) > data_end)
        return -1;

    *iph = ip_hdr;
    *data = (void *)ip_hdr + (ip_hdr->ihl * 4);
    return ip_hdr->protocol; /* Return protocol number */
}

static inline int parse_udphdr(void **data, void *data_end, struct udphdr **udph)
{
    struct udphdr *udp_hdr = *data;
    if ((void *)udp_hdr + sizeof(*udp_hdr) > data_end)
        return -1;

    *udph = udp_hdr;
    *data = (void *)udp_hdr + sizeof(*udp_hdr);
    return 0; /* Success */
}

SEC("xdp_dns_filter")
int xdp_dns_filter_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct udphdr *udph;
    int eth_type, ip_type;
    __u32 index = ctx->rx_queue_index;

    /* Parse Ethernet header */
    eth_type = parse_ethhdr(&data, data_end, &eth);
    if (eth_type < 0)
        return XDP_PASS;
    if (eth_type != __constant_htons(ETH_P_IP))
        return XDP_PASS;
    
    bpf_printk("\n\n ############### \n\n");
    bpf_printk("Received packet on queue %d\n", index);
    bpf_printk("Ethernet source: %pM\n", eth->h_source);
    bpf_printk("Ethernet destination: %pM\n", eth->h_dest);
    bpf_printk("Ethernet type: %x\n", eth_type);

    /* Parse IPv4 header */
    ip_type = parse_iphdr(&data, data_end, &iph);
    if (ip_type < 0)
        return XDP_PASS;
    if (ip_type != 17) /* 17 = UDP protocol number */
        return XDP_PASS;

    /* Parse UDP header */
    if (parse_udphdr(&data, data_end, &udph) < 0)
        return XDP_PASS;

    /* Check if this is a DNS packet (port 53) */
    if (__constant_ntohs(udph->dest) == 53 || __constant_ntohs(udph->source) == 53) {
        /* Redirect to AF_XDP socket if one is bound to this queue */
        if (bpf_map_lookup_elem(&xsks_map, &index))
            return bpf_redirect_map(&xsks_map, index, XDP_PASS);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";