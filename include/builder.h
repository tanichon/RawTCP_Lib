#ifndef HEADER_FORGER
#define HEADER_FORGER

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "pkt.h"
#include "segment.h"

packet_t build_std_pkt(uint16_t src_port, uint16_t dst_port,
                       const char* src_ip, const char* dst_ip,
                       uint32_t tcp_seq,
                       uint32_t pkt_len);

packet_t build_null_pkt(packet_t pkt);
int pkt_destroy(packet_t pkt);

struct pseudo_hdr* build_tcp_csum(char* pkt, struct iphdr* ip_hdr, struct tcphdr* tcp_hdr, int pay_len);
uint16_t tcp_calc_csum(char* pkt, struct pseudo_hdr* psd_hdr, struct tcphdr* tcp_hdr);
void tcp_csum_update(packet_t pkt);

void recalc_tcp_csum(packet_t pkt);
int set_TCP_flags(packet_t packet, int hex_flags);
int set_TCP_seq_num(packet_t packet, uint32_t bytes);
int set_TCP_src_port(packet_t packet, uint16_t bytes);

int embed_ts(packet_t pkt);
#endif
