/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <poll.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>
#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"

#define NUM_FRAMES         4096
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE      64
#define INVALID_UMEM_FRAME UINT64_MAX

/* DNS Header structure per RFC 1035 */
struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed));

static struct xdp_program *prog;
static int xsk_map_fd;
static bool global_exit;

struct config cfg = { .ifindex = -1 };
struct xsk_umem_info {
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *buffer;
};
struct xsk_socket_info {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_umem_info *umem;
    struct xsk_socket *xsk;
    uint64_t umem_frame_addr[NUM_FRAMES];
    uint32_t umem_frame_free;
};

static const char *__doc__ = "AF_XDP DNS packet filter and parser\n";

static const struct option_wrapper long_options[] = {
    {{"help", no_argument, NULL, 'h'}, "Show help", false},
    {{"dev", required_argument, NULL, 'd'}, "Operate on device <ifname>", "<ifname>", true},
    {{"quiet", no_argument, NULL, 'q'}, "Quiet mode (no output)", false},
    {{"filename", required_argument, NULL, 'f'}, "Load XDP program from <filename>", "<filename>", true},
    {{0, 0, NULL, 0}, NULL, false}
};

/* Utility functions from advanced03-AF_XDP/af_xdp_user.c */
static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size) {
    struct xsk_umem_info *umem = calloc(1, sizeof(*umem));
    if (!umem) return NULL;
    int ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq, NULL);
    if (ret) { free(umem); errno = -ret; return NULL; }
    umem->buffer = buffer;
    return umem;
}

static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk) {
    if (xsk->umem_frame_free == 0) return INVALID_UMEM_FRAME;
    return xsk->umem_frame_addr[--xsk->umem_frame_free];
}

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame) {
    xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

static struct xsk_socket_info *xsk_configure_socket(struct config *cfg, struct xsk_umem_info *umem) {
    struct xsk_socket_info *xsk_info = calloc(1, sizeof(*xsk_info));
    if (!xsk_info) return NULL;
    xsk_info->umem = umem;

    struct xsk_socket_config xsk_cfg = {
        .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .xdp_flags = cfg->xdp_flags,
        .bind_flags = cfg->xsk_bind_flags,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD
    };
    int ret = xsk_socket__create(&xsk_info->xsk, cfg->ifname, cfg->xsk_if_queue,
                                 umem->umem, &xsk_info->rx, &xsk_info->tx, &xsk_cfg);
    if (ret) { free(xsk_info); errno = -ret; return NULL; }

    ret = xsk_socket__update_xskmap(xsk_info->xsk, xsk_map_fd);
    if (ret) { xsk_socket__delete(xsk_info->xsk); free(xsk_info); errno = -ret; return NULL; }

    for (int i = 0; i < NUM_FRAMES; i++) xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;
    xsk_info->umem_frame_free = NUM_FRAMES;

    uint32_t idx;
    ret = xsk_ring_prod__reserve(&xsk_info->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
    if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS) { free(xsk_info); return NULL; }
    for (int i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
        *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) = xsk_alloc_umem_frame(xsk_info);
    xsk_ring_prod__submit(&xsk_info->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);

    return xsk_info;
}

/* DNS parsing function */
static void parse_dns_packet(uint8_t *pkt, uint32_t len) {
    struct ethhdr *eth = (struct ethhdr *)pkt;
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    struct udphdr *udp = (struct udphdr *)((uint8_t *)ip + ip->ihl * 4);
    struct dns_header *dns = (struct dns_header *)(udp + 1);

    uint8_t *data = (uint8_t *)(dns + 1);
    uint8_t *data_end = pkt + len;

    if (data + 1 > data_end) return;

    /* Extract QNAME (domain name) */
    char domain[256] = {0};
    int offset = 0;
    uint8_t *ptr = data;

    while (ptr < data_end && *ptr != 0) {
        uint8_t label_len = *ptr++;
        if (ptr + label_len > data_end) break;
        if (offset > 0) domain[offset++] = '.';
        memcpy(domain + offset, ptr, label_len);
        offset += label_len;
        ptr += label_len;
    }

    if (offset > 0) printf("DNS Query: %s\n", domain);
}

static void handle_receive_packets(struct xsk_socket_info *xsk) {
    uint32_t idx_rx = 0;
    int rcvd = xsk_ring_cons__peek(&xsk->rx, RX_BATCH_SIZE, &idx_rx);
    if (!rcvd) return;

    for (int i = 0; i < rcvd; i++) {
        uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
        uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;
        uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);
        parse_dns_packet(pkt, len);
        xsk_free_umem_frame(xsk, addr);
    }
    xsk_ring_cons__release(&xsk->rx, rcvd);
}

static void rx_and_process(struct xsk_socket_info *xsk_socket) {
    struct pollfd fds = { .fd = xsk_socket__fd(xsk_socket->xsk), .events = POLLIN };
    while (!global_exit) {
        if (poll(&fds, 1, -1) <= 0) continue;
        handle_receive_packets(xsk_socket);
    }
}

static void exit_application(int signal) {
    int err;

    /* Detach the XDP program */
    if (prog && cfg.ifindex != -1) {
        err = xdp_program__detach(prog, cfg.ifindex, XDP_MODE_SKB, 0);
        if (err) {
            fprintf(stderr, "Couldn't detach XDP program: %d\n", err);
        }
    }

    /* Free the program object */
    if (prog) {
        xdp_program__close(prog);
        prog = NULL;
    }

    global_exit = true;
}

int main(int argc, char **argv) {
    signal(SIGINT, exit_application);
    parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);
    if (cfg.ifindex == -1) {
        fprintf(stderr, "ERROR: Required option --dev missing\n");
        usage(argv[0], __doc__, long_options, (argc == 1));
        return EXIT_FAIL_OPTION;
    }

    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
    DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, .open_filename = "dns_filter_kern.o",
                        .prog_name = "xdp_dns_filter_func", .opts = &opts);
    prog = xdp_program__create(&xdp_opts);
    int err = libxdp_get_error(prog);
    if (err) {
        char buf[1024];
        libxdp_strerror(err, buf, sizeof(buf));
        fprintf(stderr, "ERROR: Loading XDP program: %s\n", buf);
        return err;
    }

    err = xdp_program__attach(prog, cfg.ifindex, XDP_MODE_SKB, 0);
    if (err) {
        fprintf(stderr, "ERROR: Attaching XDP program: %d\n", err);
        return err;
    }

    struct bpf_map *map = bpf_object__find_map_by_name(xdp_program__bpf_obj(prog), "xsks_map");
    xsk_map_fd = bpf_map__fd(map);
    if (xsk_map_fd < 0) {
        fprintf(stderr, "ERROR: Finding xsks_map: %s\n", strerror(-xsk_map_fd));
        return EXIT_FAIL_BPF;
    }

    void *packet_buffer;
    uint64_t packet_buffer_size = NUM_FRAMES * FRAME_SIZE;
    if (posix_memalign(&packet_buffer, getpagesize(), packet_buffer_size)) {
        fprintf(stderr, "ERROR: Allocating buffer memory\n");
        return EXIT_FAIL;
    }

    struct xsk_umem_info *umem = configure_xsk_umem(packet_buffer, packet_buffer_size);
    if (!umem) {
        fprintf(stderr, "ERROR: Creating umem: %s\n", strerror(errno));
        return EXIT_FAIL;
    }

    struct xsk_socket_info *xsk_socket = xsk_configure_socket(&cfg, umem);
    if (!xsk_socket) {
        fprintf(stderr, "ERROR: Setting up AF_XDP socket: %s\n", strerror(errno));
        return EXIT_FAIL;
    }

    rx_and_process(xsk_socket);

    xsk_socket__delete(xsk_socket->xsk);
    xsk_umem__delete(umem->umem);
    free(packet_buffer);
    free(xsk_socket);
    free(umem);
    return EXIT_OK;
}