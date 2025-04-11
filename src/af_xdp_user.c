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

void parse_dns_query_name(uint8_t *dns_payload, char *hostname)
{
	int i = 0, j = 0;
	while (dns_payload[i] != 0)
	{
		int len = dns_payload[i];
		for (int k = 0; k < len; ++k)
		{
			hostname[j++] = dns_payload[i + 1 + k];
		}
		hostname[j++] = '.';
		i += len + 1;
	}
	hostname[j - 1] = '\0'; // Remove trailing dot
}

// Log hostname to urls.log
void log_hostname_to_file(const char *hostname)
{
	FILE *fp = fopen("urls.log", "a");
	if (fp)
	{
		fprintf(fp, "%s\n", hostname);
		fclose(fp);
	}
}

// void resolve_and_log_ip(const char *hostname) {
//     struct addrinfo hints, *res;
//     char ipstr[INET6_ADDRSTRLEN];

//     memset(&hints, 0, sizeof(hints));
//     hints.ai_family = AF_UNSPEC; // IPv4 or IPv6

//     int status = getaddrinfo(hostname, NULL, &hints, &res);
//     if (status != 0) {
//         return;  // DNS resolution failed
//     }

//     for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
//         void *addr;
//         if (p->ai_family == AF_INET) {
//             struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
//             addr = &(ipv4->sin_addr);
//         } else if (p->ai_family == AF_INET6) {
//             struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
//             addr = &(ipv6->sin6_addr);
//         } else {
//             continue;
//         }

//         inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));

//         // Log the IP address
//         FILE *fp = fopen("resolved.log", "a");
//         if (fp) {
//             fprintf(fp, "%s -> %s\n", hostname, ipstr);
//             fclose(fp);
//         }
//         break;  // Only log the first IP
//     }

//     freeaddrinfo(res);
// }

char *resolve_and_log_ip(const char *hostname)
{
	char ipstr[INET6_ADDRSTRLEN];

	// Load existing cache
	json_t *cache;
	json_error_t error;

	FILE *cache_fp = fopen("resolve.json", "r");
	if (cache_fp)
	{
		cache = json_loadf(cache_fp, 0, &error);
		fclose(cache_fp);
	}
	else
	{
		cache = json_object(); // empty cache if file doesn't exist
	}

	if (!cache || !json_is_object(cache))
	{
		cache = json_object(); // reset if malformed
	}

	// Check cache
	json_t *cached_ip = json_object_get(cache, hostname);
	if (cached_ip)
	{
		const char *cached_ip_str = strdup(json_string_value(cached_ip));
		printf("[Cache Hit] %s -> %s\n", hostname, cached_ip_str);
		json_decref(cache);
		return cached_ip_str;
	}

	// Not in cache, resolve using getaddrinfo
	struct addrinfo hints, *res;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC; // IPv4 or IPv6

	int status = getaddrinfo(hostname, NULL, &hints, &res);
	if (status != 0)
	{
		json_decref(cache);
		return NULL; // DNS resolution failed
	}

	for (struct addrinfo *p = res; p != NULL; p = p->ai_next)
	{
		void *addr;
		if (p->ai_family == AF_INET)
		{
			struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
			addr = &(ipv4->sin_addr);
		}
		else if (p->ai_family == AF_INET6)
		{
			struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
			addr = &(ipv6->sin6_addr);
		}
		else
		{
			continue;
		}

		inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));

		// Add to JSON cache
		json_object_set_new(cache, hostname, json_string(ipstr));

		// Write updated cache to file
		FILE *out_fp = fopen("resolve.json", "w");
		if (out_fp)
		{
			json_dumpf(cache, out_fp, JSON_INDENT(2));
			fclose(out_fp);
		}

		break; // Only log the first IP
	}

	freeaddrinfo(res);
	json_decref(cache);
	char *ret_ip = strdup(ipstr); // make a heap copy
	return ret_ip;
}

uint16_t checksum(uint16_t *buf, int nwords)
{
	uint32_t sum = 0;
	for (; nwords > 0; nwords--)
		sum += ntohs(*buf++);
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	return htons((~sum) & 0xFFFF);
}

uint16_t udp6_checksum(struct ip6_hdr *ip6, struct udphdr *udp, uint8_t *payload, int payload_len)
{
	struct
	{
		struct in6_addr src;
		struct in6_addr dst;
		uint32_t len;
		uint8_t zero[3];
		uint8_t nxt;
	} pseudo_hdr;

	memset(&pseudo_hdr, 0, sizeof(pseudo_hdr));
	pseudo_hdr.src = ip6->ip6_src;
	pseudo_hdr.dst = ip6->ip6_dst;
	pseudo_hdr.len = htonl(sizeof(struct udphdr) + payload_len);
	pseudo_hdr.nxt = IPPROTO_UDP;

	// Combine pseudo header, UDP header, and payload into one buffer
	int total_len = sizeof(pseudo_hdr) + sizeof(struct udphdr) + payload_len;
	uint8_t *buf = malloc(total_len);
	memcpy(buf, &pseudo_hdr, sizeof(pseudo_hdr));
	memcpy(buf + sizeof(pseudo_hdr), udp, sizeof(struct udphdr));
	memcpy(buf + sizeof(pseudo_hdr) + sizeof(struct udphdr), payload, payload_len);

	uint16_t result = checksum((uint16_t *)buf, (total_len + 1) / 2);
	free(buf);
	return result;
}

static bool process_packet(struct xsk_socket_info *xsk,
						   uint64_t addr, uint32_t len)
{
	uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

	// Modified
	// uint8_t *dns_payload = pkt + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

	// char hostname[256];
	// parse_dns_query_name(dns_payload + 12, hostname);  // Skip DNS header (12 bytes)
	// log_hostname_to_file(hostname);

	struct ethhdr *eth = (struct ethhdr *)pkt;
	char *ip_hostname;

	if (ntohs(eth->h_proto) == ETH_P_IP)
	{
		struct iphdr *ip = (struct iphdr *)(pkt + sizeof(struct ethhdr));

		if (ip->protocol == IPPROTO_UDP)
		{
			struct udphdr *udp = (struct udphdr *)((uint8_t *)ip + ip->ihl * 4);
			uint8_t *dns_payload = (uint8_t *)udp + sizeof(struct udphdr);

			char hostname[256];
			parse_dns_query_name(dns_payload + 12, hostname);
			log_hostname_to_file(hostname);
			ip_hostname = resolve_and_log_ip(hostname);
		}
	}
	else if (ntohs(eth->h_proto) == ETH_P_IPV6)
	{
		struct ip6_hdr *ip6 = (struct ip6_hdr *)(pkt + sizeof(struct ethhdr));

		if (ip6->ip6_nxt == IPPROTO_UDP)
		{
			struct udphdr *udp = (struct udphdr *)(pkt + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));
			uint8_t *dns_payload = (uint8_t *)udp + sizeof(struct udphdr);

			char hostname[256];
			parse_dns_query_name(dns_payload + 12, hostname);
			log_hostname_to_file(hostname);
			ip_hostname = resolve_and_log_ip(hostname);
		}
	}

	printf("Hostname: %s\n", ip_hostname);

	/* Log the raw packet into a file */
	FILE *log_file = fopen("packet_log.txt", "ab");
	if (log_file)
	{
		fwrite(pkt, 1, len, log_file);
		fclose(log_file);
	}
	else
	{
		fprintf(stderr, "Failed to open packet log file\n");
	}
	pkt_counter++;
	printf("Packet %d logged\n", pkt_counter);
	/* Lesson#3: Write an IPv6 ICMP ECHO parser to send responses
	 *
	 * Some assumptions to make it easier:
	 * - No VLAN handling
	 * - Only if nexthdr is ICMP
	 * - Just return all data with MAC/IP swapped, and type set to
	 *   ICMPV6_ECHO_REPLY
	 * - Recalculate the icmp checksum */

	if (true)
	{
		int ret;
		uint32_t tx_idx = 0;
		uint8_t tmp_mac[ETH_ALEN];
		struct in6_addr tmp_ip;

		struct ethhdr *eth = (struct ethhdr *)pkt;

		if (ntohs(eth->h_proto) == ETH_P_IP)
		{
			struct iphdr *ip = (struct iphdr *)(pkt + sizeof(struct ethhdr));

			if (ip->protocol == IPPROTO_UDP)
			{
				struct udphdr *udp = (struct udphdr *)((uint8_t *)ip + ip->ihl * 4);
				uint8_t *dns_payload = (uint8_t *)udp + sizeof(struct udphdr);

				// Create a DNS reply packet with a random IP address
				uint8_t dns_reply[512]; // Buffer for DNS reply
				memset(dns_reply, 0, sizeof(dns_reply));

				// Copy the DNS header from the request
				memcpy(dns_reply, dns_payload, 12);

				// Set the response flags
				dns_reply[2] |= 0x80; // Set QR (response) bit
				dns_reply[3] |= 0x80; // Set RA (Recursion Available) bit

				// Copy the question section
				int question_len = len - (dns_payload - pkt) - 12;
				memcpy(dns_reply + 12, dns_payload + 12, question_len);

				// Add the answer section
				int answer_offset = 12 + question_len;
				memcpy(dns_reply + answer_offset, dns_payload + 12, question_len); // Copy the question as the answer name
				answer_offset += question_len;

				// Set the answer type (A record) and class (IN)
				dns_reply[answer_offset++] = 0x00;
				dns_reply[answer_offset++] = 0x01; // Type A
				dns_reply[answer_offset++] = 0x00;
				dns_reply[answer_offset++] = 0x01; // Class IN

				// Set the TTL (Time to Live)
				dns_reply[answer_offset++] = 0x00;
				dns_reply[answer_offset++] = 0x00;
				dns_reply[answer_offset++] = 0x00;
				dns_reply[answer_offset++] = 0x3C; // TTL = 60 seconds

				// Set the data length (4 bytes for IPv4 address)
				dns_reply[answer_offset++] = 0x00;
				dns_reply[answer_offset++] = 0x04;

				// Add a random IPv4 address as the answer
				dns_reply[answer_offset++] = 192;
				dns_reply[answer_offset++] = 168;
				dns_reply[answer_offset++] = 1;
				dns_reply[answer_offset++] = 100;

				// Update the UDP length
				udp->len = htons(answer_offset + sizeof(struct udphdr) - (dns_payload - pkt));

				// Copy the DNS reply back to the packet
				memcpy(dns_payload, dns_reply, answer_offset);

				// Update the IP length
				ip->tot_len = htons(answer_offset + sizeof(struct udphdr) + ip->ihl * 4);

				// Recalculate the UDP checksum
				udp->check = 0;
				udp->check = csum16_add(udp->check, htons(answer_offset + sizeof(struct udphdr)));
			}
		}
		else if (ntohs(eth->h_proto) == ETH_P_IPV6)
		{
			// struct ethhdr *eth = (struct ethhdr *)pkt;
			struct ip6_hdr *ip6 = (struct ip6_hdr *)(pkt + sizeof(struct ethhdr));

			if (ip6->ip6_nxt != IPPROTO_UDP)
				return;

			struct udphdr *udp = (struct udphdr *)(pkt + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));
			uint8_t *dns_payload = (uint8_t *)(udp + 1);
			int dns_payload_len = ntohs(udp->len) - sizeof(struct udphdr);

			// Allocate DNS reply buffer
			uint8_t dns_reply[512];
			memset(dns_reply, 0, sizeof(dns_reply));

			// Copy DNS header
			memcpy(dns_reply, dns_payload, 12);

			// Set flags: response, recursion available
			dns_reply[2] |= 0x80;
			dns_reply[3] |= 0x80;

			// Set answer count to 1
			dns_reply[6] = 0x00;
			dns_reply[7] = 0x01;

			// Copy question section
			int question_len = 0;
			while (dns_payload[12 + question_len] != 0x00 && (12 + question_len) < dns_payload_len)
			{
				question_len++;
			}
			question_len += 5; // +1 for null, +4 for QTYPE and QCLASS

			memcpy(dns_reply + 12, dns_payload + 12, question_len);

			// Write answer section with compression pointer
			int offset = 12 + question_len;
			dns_reply[offset++] = 0xC0;
			dns_reply[offset++] = 0x0C; // pointer to the question

			// Type A (IPv4)
			dns_reply[offset++] = 0x00;
			dns_reply[offset++] = 0x01;

			// Class IN
			dns_reply[offset++] = 0x00;
			dns_reply[offset++] = 0x01;

			// TTL
			dns_reply[offset++] = 0x00;
			dns_reply[offset++] = 0x00;
			dns_reply[offset++] = 0x00;
			dns_reply[offset++] = 0x3C;

			// RDLENGTH = 4
			dns_reply[offset++] = 0x00;
			dns_reply[offset++] = 0x04;

			// Random IPv4 address (e.g., 192.168.1.100)
			// dns_reply[offset++] = 123;
			// dns_reply[offset++] = 123;
			// dns_reply[offset++] = 123;
			// dns_reply[offset++] = 123;
			struct in_addr ip_addr;
			if (inet_pton(AF_INET, ip_hostname, &ip_addr) == 1)
			{
				memcpy(&dns_reply[offset], &ip_addr, 4);
				offset += 4;
			}
			else
			{
				fprintf(stderr, "Invalid IP address format: %s\n", ip_hostname);
				return; // or handle the error appropriately
			}

			// Handle OPT (EDNS0) Additional Record if present
			int opt_start = 12 + question_len + 16;			  // question + 16-byte answer
			int opt_len = dns_payload_len - (opt_start - 12); // Remaining bytes in original payload

			if (opt_len > 0 && dns_payload[opt_start + 1] == 0x00 && dns_payload[opt_start + 3] == 0x29)
			{
				// Confirm it's an OPT RR (Type 41 = 0x0029)
				memcpy(dns_reply + offset, dns_payload + opt_start, opt_len);
				offset += opt_len;

				// Set ARCOUNT = 1 (1 Additional Record)
				dns_reply[10] = 0x00;
				dns_reply[11] = 0x01;
			}
			else
			{
				// No additional record
				dns_reply[10] = 0x00;
				dns_reply[11] = 0x00;
			}

			int dns_reply_len = offset;

			// Copy DNS reply back to original packet
			memcpy(dns_payload, dns_reply, dns_reply_len);

			// Update UDP length
			udp->len = htons(dns_reply_len + sizeof(struct udphdr));

			// Update IPv6 payload length
			ip6->ip6_plen = htons(dns_reply_len + sizeof(struct udphdr));

			// Recompute UDP checksum
			udp->check = 0;
			udp->check = udp6_checksum(ip6, udp, dns_payload, dns_reply_len);

			// Swap MACs
			uint8_t tmp_mac[ETH_ALEN];
			memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
			memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
			memcpy(eth->h_source, tmp_mac, ETH_ALEN);

			// Swap IPv6 addresses
			struct in6_addr tmp_ip;
			memcpy(&tmp_ip, &ip6->ip6_src, sizeof(tmp_ip));
			memcpy(&ip6->ip6_src, &ip6->ip6_dst, sizeof(tmp_ip));
			memcpy(&ip6->ip6_dst, &tmp_ip, sizeof(tmp_ip));

			printf("Processed IPv6 packet\n");
		}

		// struct ethhdr *eth = (struct ethhdr *) pkt;
		// struct ipv6hdr *ipv6 = (struct ipv6hdr *) (eth + 1);
		// struct icmp6hdr *icmp = (struct icmp6hdr *) (ipv6 + 1);

		// if (ntohs(eth->h_proto) != ETH_P_IPV6 ||
		//     len < (sizeof(*eth) + sizeof(*ipv6) + sizeof(*icmp)) ||
		//     ipv6->nexthdr != IPPROTO_ICMPV6 ||
		//     icmp->icmp6_type != ICMPV6_ECHO_REQUEST)
		// 	return false;

		// memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
		// memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
		// memcpy(eth->h_source, tmp_mac, ETH_ALEN);

		// memcpy(&tmp_ip, &ipv6->saddr, sizeof(tmp_ip));
		// memcpy(&ipv6->saddr, &ipv6->daddr, sizeof(tmp_ip));
		// memcpy(&ipv6->daddr, &tmp_ip, sizeof(tmp_ip));

		// icmp->icmp6_type = ICMPV6_ECHO_REPLY;

		// csum_replace2(&icmp->icmp6_cksum,
		// 	      htons(ICMPV6_ECHO_REQUEST << 8),
		// 	      htons(ICMPV6_ECHO_REPLY << 8));

		/* Here we sent the packet out of the receive port. Note that
		 * we allocate one entry and schedule it. Your design would be
		 * faster if you do batch processing/transmission */

		// /* Reserve a transmit slot */
		ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
		if (ret != 1)
		{
			/* No more transmit slots, drop the packet */
			return false;
		}

		/* Submit the packet for transmission */
		xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->addr = addr;
		xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len = len;
		xsk_ring_prod__submit(&xsk->tx, 1);
		xsk->outstanding_tx++;

		/* Print packet details */
		// uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);
		// printf("Packet submitted for transmission:\n");
		// printf("Length: %u bytes\n", len);
		// printf("Data (first 64 bytes): ");
		// for (uint32_t i = 0; i < len && i < 64; i++)
		// {
		// 	printf("%02x ", pkt[i]);
		// }
		// printf("\n");

		/* Update statistics */
		xsk->stats.tx_bytes += len;
		xsk->stats.tx_packets++;
		return true;
	}

	return false;
}

static void handle_receive_packets(struct xsk_socket_info *xsk)
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

		if (!process_packet(xsk, addr, len))
			xsk_free_umem_frame(xsk, addr);

		xsk->stats.rx_bytes += len;
	}

	xsk_ring_cons__release(&xsk->rx, rcvd);
	xsk->stats.rx_packets += rcvd;

	/* Do we need to wake up the kernel for transmission */
	complete_tx(xsk);
}

static void rx_and_process(struct config *cfg,
						   struct xsk_socket_info *xsk_socket)
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
		handle_receive_packets(xsk_socket);
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
	rx_and_process(&cfg, xsk_socket);

	/* Cleanup */
	xsk_socket__delete(xsk_socket->xsk);
	xsk_umem__delete(umem->umem);

	return EXIT_OK;
}