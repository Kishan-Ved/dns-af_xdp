/* SPDX-License-Identifier: GPL-2.0 */

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/resource.h>

#include <bpf/bpf.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <stdlib.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include <netinet/ip.h>	  // for struct iphdr
#include <netinet/udp.h>  // for struct udphdr
#include <net/ethernet.h> // for struct ethhdr
#include <netinet/ip6.h>  // for struct ip6_hdr

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <jansson.h> // You'll need to install libjansson-dev

#define NUM_FRAMES 4096
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE 64
#define INVALID_UMEM_FRAME UINT64_MAX
#define DNS_PORT 53
#define MAX_DNS_PACKET 512


int pkt_counter = 0;
static struct xdp_program *prog;
int xsk_map_fd;
bool custom_xsk = false;
struct config cfg = {
	.ifindex = -1,
};

struct xsk_umem_info
{
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};
struct stats_record
{
	uint64_t timestamp;
	uint64_t rx_packets;
	uint64_t rx_bytes;
	uint64_t tx_packets;
	uint64_t tx_bytes;
};
struct xsk_socket_info
{
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;

	uint64_t umem_frame_addr[NUM_FRAMES];
	uint32_t umem_frame_free;

	uint32_t outstanding_tx;

	struct stats_record stats;
	struct stats_record prev_stats;
};

static inline __u32 xsk_ring_prod__free(struct xsk_ring_prod *r)
{
	r->cached_cons = *r->consumer + r->size;
	return r->cached_cons - r->cached_prod;
}

static const char *__doc__ = "AF_XDP kernel bypass example\n";

static const struct option_wrapper long_options[] = {

	{{"help", no_argument, NULL, 'h'},
	 "Show help",
	 false},

	{{"dev", required_argument, NULL, 'd'},
	 "Operate on device <ifname>",
	 "<ifname>",
	 true},

	{{"skb-mode", no_argument, NULL, 'S'},
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument, NULL, 'N'},
	 "Install XDP program in native mode"},

	{{"auto-mode", no_argument, NULL, 'A'},
	 "Auto-detect SKB or native mode"},

	{{"force", no_argument, NULL, 'F'},
	 "Force install, replacing existing program on interface"},

	{{"copy", no_argument, NULL, 'c'},
	 "Force copy mode"},

	{{"zero-copy", no_argument, NULL, 'z'},
	 "Force zero-copy mode"},

	{{"queue", required_argument, NULL, 'Q'},
	 "Configure interface receive queue for AF_XDP, default=0"},

	{{"poll-mode", no_argument, NULL, 'p'},
	 "Use the poll() API waiting for packets to arrive"},

	{{"quiet", no_argument, NULL, 'q'},
	 "Quiet mode (no output)"},

	{{"filename", required_argument, NULL, 1},
	 "Load program from <file>",
	 "<file>"},

	{{"progname", required_argument, NULL, 2},
	 "Load program from function <name> in the ELF file",
	 "<name>"},

	{{0, 0, NULL, 0}, NULL, false}};

static bool global_exit;

static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size)
{
	struct xsk_umem_info *umem;
	int ret;

	umem = calloc(1, sizeof(*umem));
	if (!umem)
		return NULL;

	ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
						   NULL);
	if (ret)
	{
		errno = -ret;
		return NULL;
	}

	umem->buffer = buffer;
	return umem;
}

static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk)
{
	uint64_t frame;
	if (xsk->umem_frame_free == 0)
		return INVALID_UMEM_FRAME;

	frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
	xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
	return frame;
}

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame)
{
	assert(xsk->umem_frame_free < NUM_FRAMES);

	xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

static uint64_t xsk_umem_free_frames(struct xsk_socket_info *xsk)
{
	return xsk->umem_frame_free;
}

static struct xsk_socket_info *xsk_configure_socket(struct config *cfg,
													struct xsk_umem_info *umem)
{
	struct xsk_socket_config xsk_cfg;
	struct xsk_socket_info *xsk_info;
	uint32_t idx;
	int i;
	int ret;
	uint32_t prog_id;

	xsk_info = calloc(1, sizeof(*xsk_info));
	if (!xsk_info)
		return NULL;

	xsk_info->umem = umem;
	xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	xsk_cfg.xdp_flags = cfg->xdp_flags;
	xsk_cfg.bind_flags = cfg->xsk_bind_flags;
	xsk_cfg.libbpf_flags = (custom_xsk) ? XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD : 0;
	ret = xsk_socket__create(&xsk_info->xsk, cfg->ifname,
							 cfg->xsk_if_queue, umem->umem, &xsk_info->rx,
							 &xsk_info->tx, &xsk_cfg);
	if (ret)
		goto error_exit;

	if (custom_xsk)
	{
		ret = xsk_socket__update_xskmap(xsk_info->xsk, xsk_map_fd);
		if (ret)
			goto error_exit;
	}
	else
	{
		/* Getting the program ID must be after the xdp_socket__create() call */
		if (bpf_xdp_query_id(cfg->ifindex, cfg->xdp_flags, &prog_id))
			goto error_exit;
	}

	/* Initialize umem frame allocation */
	for (i = 0; i < NUM_FRAMES; i++)
		xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;

	xsk_info->umem_frame_free = NUM_FRAMES;

	/* Stuff the receive path with buffers, we assume we have enough */
	ret = xsk_ring_prod__reserve(&xsk_info->umem->fq,
								 XSK_RING_PROD__DEFAULT_NUM_DESCS,
								 &idx);

	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
		goto error_exit;

	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
		*xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) =
			xsk_alloc_umem_frame(xsk_info);

	xsk_ring_prod__submit(&xsk_info->umem->fq,
						  XSK_RING_PROD__DEFAULT_NUM_DESCS);

	return xsk_info;

error_exit:
	errno = -ret;
	return NULL;
}


// Structure to hold DNS response data
struct dns_response
{
    uint8_t payload[MAX_DNS_PACKET];
    size_t len;
    // char ipstr[INET6_ADDRSTRLEN];
};


static void complete_tx(struct xsk_socket_info *xsk)
{
	unsigned int completed;
	uint32_t idx_cq;

	if (!xsk->outstanding_tx)
		return;

	sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

	/* Collect/free completed TX buffers */
	completed = xsk_ring_cons__peek(&xsk->umem->cq,
									XSK_RING_CONS__DEFAULT_NUM_DESCS,
									&idx_cq);

	if (completed > 0)
	{
		for (int i = 0; i < completed; i++)
			xsk_free_umem_frame(xsk,
								*xsk_ring_cons__comp_addr(&xsk->umem->cq,
														  idx_cq++));

		xsk_ring_cons__release(&xsk->umem->cq, completed);
		xsk->outstanding_tx -= completed < xsk->outstanding_tx ? completed : xsk->outstanding_tx;
	}
}

static inline __sum16 csum16_add(__sum16 csum, __be16 addend)
{
	uint16_t res = (uint16_t)csum;

	res += (__u16)addend;
	return (__sum16)(res + (res < (__u16)addend));
}

static inline __sum16 csum16_sub(__sum16 csum, __be16 addend)
{
	return csum16_add(csum, ~addend);
}

static inline void csum_replace2(__sum16 *sum, __be16 old, __be16 new)
{
	*sum = ~csum16_add(csum16_sub(~(*sum), old), new);
}

static inline uint16_t udp6_checksum(struct ip6_hdr *ip6, struct udphdr *udp, uint8_t *payload, int payload_len)
{
    uint32_t sum = 0;
    uint16_t *ptr;
    int i;

    // Pseudo-header: src/dst IPv6 addresses
    ptr = (uint16_t *)&ip6->ip6_src;
    for (i = 0; i < 8; i++)
        sum += ntohs(ptr[i]);
    ptr = (uint16_t *)&ip6->ip6_dst;
    for (i = 0; i < 8; i++)
        sum += ntohs(ptr[i]);

    // Length, next header
    sum += ntohs(ip6->ip6_plen);
    sum += IPPROTO_UDP;

    // UDP header
    ptr = (uint16_t *)udp;
    for (i = 0; i < sizeof(struct udphdr) / 2; i++)
        sum += ntohs(ptr[i]);

    // Payload
    ptr = (uint16_t *)payload;
    for (i = 0; i < payload_len / 2; i++)
        sum += ntohs(ptr[i]);
    if (payload_len % 2)
        sum += ntohs(payload[payload_len - 1] << 8);

    // Fold 32-bit sum to 16 bits
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}

static void parse_dns_query_name(uint8_t *dns_payload, char *hostname)
{
    int pos = 0, hostname_pos = 0;
    uint8_t len;

    while ((len = dns_payload[pos]) != 0)
    {
        if (pos + len + 1 > 255)
            break; // Prevent buffer overflow
        if (hostname_pos > 0)
            hostname[hostname_pos++] = '.';
        memcpy(hostname + hostname_pos, dns_payload + pos + 1, len);
        hostname_pos += len;
        pos += len + 1;
    }
    hostname[hostname_pos] = '\0';
}


static struct dns_response *resolve_and_log_ip(const char *hostname, uint8_t *dns_payload, int dns_payload_len, int sock, struct sockaddr_in *resolver_addr)
{
    struct dns_response *result = malloc(sizeof(struct dns_response));
	if (!result) {
		fprintf(stderr, "Failed to allocate dns_response\n");
		return NULL;
	}
	memset(result, 0, sizeof(struct dns_response));

	// Load existing cache
	json_t *cache;
	json_error_t error;

	FILE *cache_fp = fopen("dns_mappings.json", "r");
	if (cache_fp) {
		cache = json_loadf(cache_fp, 0, &error);
		fclose(cache_fp);
	} else {
		cache = json_object();
	}

	if (!cache || !json_is_object(cache)) {
		cache = json_object();
	}

	if (json_object_size(cache) >= 1024) {
		const char *key_to_remove = NULL;
		void *iter = json_object_iter(cache);
		if (iter) {
			key_to_remove = json_object_iter_key(iter);
			json_object_del(cache, key_to_remove);
		}

	}

	json_t *cached_bin_path = json_object_get(cache, hostname);
	if (cached_bin_path) {
		const char *cached_bin_filepath = json_string_value(cached_bin_path);
		printf("[Cache Hit] %s\n", hostname);

		FILE *bin_fp = fopen(cached_bin_filepath, "rb");
		if (!bin_fp) {
			fprintf(stderr, "Failed to open cached file: %s\n", cached_bin_filepath);
			json_decref(cache);
			free(result);
			return NULL;
		}

		fseek(bin_fp, 0, SEEK_END);
		size_t file_size = ftell(bin_fp);
		fseek(bin_fp, 0, SEEK_SET);

		result->len = file_size;
		fread(result->payload, 1, file_size, bin_fp);
		fclose(bin_fp);
		json_decref(cache);
		return result;
	}

	/*
	MAIN CRUX - CREATE A UDP SOCKET AND SEND A DNS QUERY
	RECEIVE THE RESPONSE BACK AND LOG INTO CACHE
	*/

	// Send query
	if (sendto(sock, dns_payload, dns_payload_len, 0, (struct sockaddr *)resolver_addr, sizeof(*resolver_addr)) < 0) {
		fprintf(stderr, "Failed to send query: %s\n", strerror(errno));
		free(result);
		json_decref(cache);
		return NULL;
	}

	// Receive response
	uint8_t response[MAX_DNS_PACKET];
	ssize_t response_len = recvfrom(sock, response, MAX_DNS_PACKET, 0, NULL, NULL);
	if (response_len < 0) {
		fprintf(stderr, "Failed to receive response: %s\n", strerror(errno));
		close(sock);
		free(result);
		json_decref(cache);
		return NULL;
	}

	// Copy response to result
	memcpy(result->payload, response, response_len);
	result->len = response_len;

	// Generate a unique filename for the binary response
	char bin_filename[256];
	snprintf(bin_filename, sizeof(bin_filename), "./payloadCache/response_%s.bin", hostname);

	FILE *bin_fp = fopen(bin_filename, "wb");
	if (bin_fp) {
		fwrite(response, 1, response_len, bin_fp);
		fclose(bin_fp);
	}

	// Add the mapping to the cache JSON
	json_object_set_new(cache, hostname, json_string(bin_filename));

	FILE *save_fp = fopen("dns_mappings.json", "w");
	if (save_fp) {
		json_dumpf(cache, save_fp, JSON_INDENT(2));
		fclose(save_fp);
	}
	json_decref(cache);

	printf("[Resolved] %s\n", hostname);
	return result;

}

static bool process_packet(struct xsk_socket_info *xsk, uint64_t addr, uint32_t len, int sock, struct sockaddr_in *resolver_addr)
{
    uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);
    struct ethhdr *eth = (struct ethhdr *)pkt;
    struct dns_response *dns_res = NULL;
    bool is_ipv4 = (ntohs(eth->h_proto) == ETH_P_IP);
    bool is_ipv6 = (ntohs(eth->h_proto) == ETH_P_IPV6);
    uint32_t tx_idx = 0;
    int ret;

    if (is_ipv4) {
        struct iphdr *ip = (struct iphdr *)(pkt + sizeof(struct ethhdr));
        if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)((uint8_t *)ip + ip->ihl * 4);
            uint8_t *dns_payload = (uint8_t *)udp + sizeof(struct udphdr);
			int dns_payload_len = ntohs(udp->len) - sizeof(struct udphdr);
            char hostname[256];
            parse_dns_query_name(dns_payload + 12, hostname);
            dns_res = resolve_and_log_ip(hostname, dns_payload, dns_payload_len, sock, resolver_addr);

            if (!dns_res || dns_res->len == 0) {
                fprintf(stderr, "No valid response for %s\n", hostname);
                if (dns_res) free(dns_res);
                return false;
            }

            int question_len = 0;

            // Parse question length
            while (dns_payload[12 + question_len] != 0x00 && (12 + question_len) < dns_payload_len) {
                question_len++;
            }
            question_len += 5; // Null byte + QTYPE + QCLASS
            if (question_len + 12 > dns_payload_len) {
                fprintf(stderr, "Invalid question length for %s\n", hostname);
                free(dns_res);
                return false;
            }

			memcpy(dns_payload, dns_res->payload, dns_res->len);
			udp->len = htons(dns_res->len + sizeof(struct udphdr));
			ip->tot_len = htons(dns_res->len + sizeof(struct udphdr) + ip->ihl * 4);
			len = sizeof(struct ethhdr) + ip->ihl * 4 + sizeof(struct udphdr) + dns_res->len;
			udp->check = 0;
			// udp->check = csum16_add(csum16_sub(~ip->check, htons(udp->len)), udp->len);

            // Swap addresses
            uint8_t tmp_mac[ETH_ALEN];
            memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
            memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
            memcpy(eth->h_source, tmp_mac, ETH_ALEN);
            uint32_t tmp_ip = ip->saddr;
            ip->saddr = ip->daddr;
            ip->daddr = tmp_ip;
        }
    } else if (is_ipv6) {
        struct ip6_hdr *ip6 = (struct ip6_hdr *)(pkt + sizeof(struct ethhdr));
        if (ip6->ip6_nxt == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)(pkt + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));
            uint8_t *dns_payload = (uint8_t *)udp + sizeof(struct udphdr);
            int dns_payload_len = ntohs(udp->len) - sizeof(struct udphdr);
            char hostname[256];
            parse_dns_query_name(dns_payload + 12, hostname);
            dns_res = resolve_and_log_ip(hostname, dns_payload, dns_payload_len, sock, resolver_addr);

            if (!dns_res || dns_res->len == 0) {
                fprintf(stderr, "No valid response for %s\n", hostname);
                if (dns_res) free(dns_res);
                return false;
            }

            int question_len = 0;

            // Parse question length
            while (dns_payload[12 + question_len] != 0x00 && (12 + question_len) < dns_payload_len) {
                question_len++;
            }
            question_len += 5;
            if (question_len + 12 > dns_payload_len) {
                fprintf(stderr, "Invalid question length for %s\n", hostname);
                free(dns_res);
                return false;
            }

			memcpy(dns_payload, dns_res->payload, dns_res->len);
			udp->len = htons(dns_res->len + sizeof(struct udphdr));
			ip6->ip6_plen = htons(dns_res->len + sizeof(struct udphdr));
			len = sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + sizeof(struct udphdr) + dns_res->len;
			udp->check = 0;
			udp->check = udp6_checksum(ip6, udp, dns_payload, dns_res->len);

            uint8_t tmp_mac[ETH_ALEN];
            memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
            memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
            memcpy(eth->h_source, tmp_mac, ETH_ALEN);
            struct in6_addr tmp_ip;
            memcpy(&tmp_ip, &ip6->ip6_src, sizeof(tmp_ip));
            memcpy(&ip6->ip6_src, &ip6->ip6_dst, sizeof(tmp_ip));
            memcpy(&ip6->ip6_dst, &tmp_ip, sizeof(tmp_ip));
        }
    }

    if (dns_res) {
        free(dns_res);
    }

    ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
    if (ret != 1) {
        fprintf(stderr, "Failed to reserve TX slot\n");
        return false;
    }

    xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->addr = addr;
    xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len = len;
    xsk_ring_prod__submit(&xsk->tx, 1);
    xsk->outstanding_tx++;

    xsk->stats.tx_bytes += len;
    xsk->stats.tx_packets++;
    pkt_counter++;
    // printf("Packet %d sent: %s\n", pkt_counter, dns_res && dns_res->ipstr[0] ? dns_res->ipstr : "unknown");
    return true;
}

static void handle_receive_packets(struct xsk_socket_info *xsk, int sock, struct sockaddr_in *resolver_addr)
{
	unsigned int rcvd, stock_frames, i;
	uint32_t idx_rx = 0, idx_fq = 0;
	int ret;

	rcvd = xsk_ring_cons__peek(&xsk->rx, RX_BATCH_SIZE, &idx_rx);
	if (!rcvd)
		return;

	/* Stuff the ring with as much frames as possible */
	stock_frames = xsk_prod_nb_free(&xsk->umem->fq,
									xsk_umem_free_frames(xsk));

	if (stock_frames > 0)
	{

		ret = xsk_ring_prod__reserve(&xsk->umem->fq, stock_frames,
									 &idx_fq);

		/* This should not happen, but just in case */
		while (ret != stock_frames)
			ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd,
										 &idx_fq);

		for (i = 0; i < stock_frames; i++)
			*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) =
				xsk_alloc_umem_frame(xsk);

		xsk_ring_prod__submit(&xsk->umem->fq, stock_frames);
	}

	/* Process received packets */
	for (i = 0; i < rcvd; i++)
	{
		uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
		uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;

		if (!process_packet(xsk, addr, len, sock, resolver_addr))
			xsk_free_umem_frame(xsk, addr);

		xsk->stats.rx_bytes += len;
	}

	xsk_ring_cons__release(&xsk->rx, rcvd);
	xsk->stats.rx_packets += rcvd;

	/* Do we need to wake up the kernel for transmission */
	complete_tx(xsk);
}

static void rx_and_process(struct config *cfg,
						   struct xsk_socket_info *xsk_socket, int sock, struct sockaddr_in *resolver_addr)
{
	struct pollfd fds[2];
	int ret, nfds = 1;

	memset(fds, 0, sizeof(fds));
	fds[0].fd = xsk_socket__fd(xsk_socket->xsk);
	fds[0].events = POLLIN;

	while (!global_exit)
	{
		if (cfg->xsk_poll_mode)
		{
			ret = poll(fds, nfds, -1);
			if (ret <= 0 || ret > 1)
				continue;
		}
		handle_receive_packets(xsk_socket, sock, resolver_addr);
	}
}

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static uint64_t gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0)
	{
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(EXIT_FAIL);
	}
	return (uint64_t)t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

static double calc_period(struct stats_record *r, struct stats_record *p)
{
	double period_ = 0;
	__u64 period = 0;

	period = r->timestamp - p->timestamp;
	if (period > 0)
		period_ = ((double)period / NANOSEC_PER_SEC);

	return period_;
}

static void stats_print(struct stats_record *stats_rec,
						struct stats_record *stats_prev)
{
	uint64_t packets, bytes;
	double period;
	double pps; /* packets per sec */
	double bps; /* bits per sec */

	char *fmt = "%-12s %'11lld pkts (%'10.0f pps)"
				" %'11lld Kbytes (%'6.0f Mbits/s)"
				" period:%f\n";

	period = calc_period(stats_rec, stats_prev);
	if (period == 0)
		period = 1;

	packets = stats_rec->rx_packets - stats_prev->rx_packets;
	pps = packets / period;

	bytes = stats_rec->rx_bytes - stats_prev->rx_bytes;
	bps = (bytes * 8) / period / 1000000;

	printf(fmt, "AF_XDP RX:", stats_rec->rx_packets, pps,
		   stats_rec->rx_bytes / 1000, bps,
		   period);

	packets = stats_rec->tx_packets - stats_prev->tx_packets;
	pps = packets / period;

	bytes = stats_rec->tx_bytes - stats_prev->tx_bytes;
	bps = (bytes * 8) / period / 1000000;

	printf(fmt, "       TX:", stats_rec->tx_packets, pps,
		   stats_rec->tx_bytes / 1000, bps,
		   period);

	printf("\n");
}

static void *stats_poll(void *arg)
{
	unsigned int interval = 2;
	struct xsk_socket_info *xsk = arg;
	static struct stats_record previous_stats = {0};

	previous_stats.timestamp = gettime();

	/* Trick to pretty printf with thousands separators use %' */
	setlocale(LC_NUMERIC, "en_US");

	while (!global_exit)
	{
		sleep(interval);
		xsk->stats.timestamp = gettime();
		stats_print(&xsk->stats, &previous_stats);
		previous_stats = xsk->stats;
	}
	return NULL;
}

static void exit_application(int signal)
{
	int err;

	cfg.unload_all = true;
	err = do_unload(&cfg);
	if (err)
	{
		fprintf(stderr, "Couldn't detach XDP program on iface '%s' : (%d)\n",
				cfg.ifname, err);
	}

	signal = signal;
	global_exit = true;
}

int main(int argc, char **argv)
{
	/* CREATE ONE DGRAM SOCKET HERE ITSELF! */
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));

    // Set timeout
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // Upstream resolver
	struct sockaddr_in *resolver_addr = malloc(sizeof(struct sockaddr_in));
	if (!resolver_addr) {
		fprintf(stderr, "Failed to allocate memory for resolver_addr\n");
		exit(EXIT_FAILURE);
	}
	memset(resolver_addr, 0, sizeof(struct sockaddr_in));
	resolver_addr->sin_family = AF_INET;
	resolver_addr->sin_port = htons(DNS_PORT);
	inet_pton(AF_INET, "8.8.8.8", &resolver_addr->sin_addr);

	/* END OF SOCKET CREATION */

	int ret;
	void *packet_buffer;
	uint64_t packet_buffer_size;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
	DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);
	struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
	struct xsk_umem_info *umem;
	struct xsk_socket_info *xsk_socket;
	pthread_t stats_poll_thread;
	int err;
	char errmsg[1024];

	/* Global shutdown handler */
	signal(SIGINT, exit_application);

	/* Cmdline options can change progname */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1)
	{
		fprintf(stderr, "ERROR: Required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	/* Load custom program if configured */
	if (cfg.filename[0] != 0)
	{
		struct bpf_map *map;

		custom_xsk = true;
		xdp_opts.open_filename = cfg.filename;
		xdp_opts.prog_name = cfg.progname;
		xdp_opts.opts = &opts;

		if (cfg.progname[0] != 0)
		{
			xdp_opts.open_filename = cfg.filename;
			xdp_opts.prog_name = cfg.progname;
			xdp_opts.opts = &opts;

			prog = xdp_program__create(&xdp_opts);
		}
		else
		{
			prog = xdp_program__open_file(cfg.filename,
										  NULL, &opts);
		}
		err = libxdp_get_error(prog);
		if (err)
		{
			libxdp_strerror(err, errmsg, sizeof(errmsg));
			fprintf(stderr, "ERR: loading program: %s\n", errmsg);
			return err;
		}

		err = xdp_program__attach(prog, cfg.ifindex, cfg.attach_mode, 0);
		if (err)
		{
			libxdp_strerror(err, errmsg, sizeof(errmsg));
			fprintf(stderr, "Couldn't attach XDP program on iface '%s' : %s (%d)\n",
					cfg.ifname, errmsg, err);
			return err;
		}

		/* We also need to load the xsks_map */
		map = bpf_object__find_map_by_name(xdp_program__bpf_obj(prog), "xsks_map");
		xsk_map_fd = bpf_map__fd(map);
		if (xsk_map_fd < 0)
		{
			fprintf(stderr, "ERROR: no xsks map found: %s\n",
					strerror(xsk_map_fd));
			exit(EXIT_FAILURE);
		}
	}

	/* Allow unlimited locking of memory, so all memory needed for packet
	 * buffers can be locked.
	 *
	 * NOTE: since kernel v5.11, eBPF maps allocations are not tracked
	 * through the process anymore. Now, eBPF maps are accounted to the
	 * current cgroup of which the process that created the map is part of
	 * (assuming the kernel was built with CONFIG_MEMCG).
	 *
	 * Therefore, you should ensure an appropriate memory.max setting on
	 * the cgroup (via sysfs, for example) instead of relying on rlimit.
	 */
	if (setrlimit(RLIMIT_MEMLOCK, &rlim))
	{
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
				strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Allocate memory for NUM_FRAMES of the default XDP frame size */
	packet_buffer_size = NUM_FRAMES * FRAME_SIZE;
	if (posix_memalign(&packet_buffer,
					   getpagesize(), /* PAGE_SIZE aligned */
					   packet_buffer_size))
	{
		fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
				strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Initialize shared packet_buffer for umem usage */
	umem = configure_xsk_umem(packet_buffer, packet_buffer_size);
	if (umem == NULL)
	{
		fprintf(stderr, "ERROR: Can't create umem \"%s\"\n",
				strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Open and configure the AF_XDP (xsk) socket */
	xsk_socket = xsk_configure_socket(&cfg, umem);
	if (xsk_socket == NULL)
	{
		fprintf(stderr, "ERROR: Can't setup AF_XDP socket \"%s\"\n",
				strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Start thread to do statistics display */
	if (verbose)
	{
		ret = pthread_create(&stats_poll_thread, NULL, stats_poll,
							 xsk_socket);
		if (ret)
		{
			fprintf(stderr, "ERROR: Failed creating statistics thread "
							"\"%s\"\n",
					strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	/* Receive and count packets than drop them */
	rx_and_process(&cfg, xsk_socket, sock, resolver_addr);

	/* Cleanup */
	xsk_socket__delete(xsk_socket->xsk);
	xsk_umem__delete(umem->umem);
	close(sock);

	return EXIT_OK;
}
