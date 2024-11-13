#ifndef HEADER_PACKET
#define HEADER_PACKET

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <strings.h>

#include "segment.h"

struct embed_ts_hdr {
    uint32_t magic;
    uint32_t tv_sec;
    uint32_t tv_nsec;
};

#define ETH_HDR_LEN     sizeof(struct ethhdr)
#define IP4_HDR_LEN     sizeof(struct iphdr)
#define TCP_HDR_LEN     sizeof(struct tcphdr)
#define ETS_HDR_LEN     sizeof(struct embed_ts_hdr)
#define RAWTCP_DEF_PKT_LEN  (ETH_HDR_LEN + IP4_HDR_LEN + TCP_HDR_LEN + ETS_HDR_LEN)

typedef struct packet_t {
    struct ethhdr* eth_hdr;
    struct iphdr *ip_hdr;
    struct tcphdr *tcp_hdr;
    struct embed_ts_hdr* et_hdr;
    char* payload;
    int pay_len;
    char* packet;
    int pkt_len;
    struct pseudo_hdr* psd_hdr;
} packet_t;

struct ethhdr* gen_eth();
struct iphdr* gen_ipv4(const char *src_ip, const char *dst_ip, uint16_t payload_length);

void calc_ip_csum(struct iphdr *ip_hdr, unsigned short *pkt, int nbytes);

#endif
