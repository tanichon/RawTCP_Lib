#include <string.h>
#include <stdio.h>

#include "../include/pkt.h"

struct ethhdr* gen_eth()
{
    uint8_t da[6] = { 0x00, 0xaa, 0xaa, 0x00, 0xaa, 0xaa };
    uint8_t sa[6] = { 0x00, 0xbb, 0xbb, 0x00, 0xbb, 0xbb };

    struct ethhdr* eth = malloc(sizeof(struct ethhdr));
    bzero(eth, sizeof(struct ethhdr));

    memcpy(eth->h_dest,   da, ETH_ALEN);
    memcpy(eth->h_source, sa, ETH_ALEN);
    eth->h_proto = htons(ETH_P_IP);

    return eth;
}

struct iphdr* gen_ipv4(const char *src_ip, const char *dst_ip, uint16_t payload_length)
{
    struct iphdr* ip_hdr = malloc(sizeof(struct iphdr));
    bzero(ip_hdr, sizeof(struct iphdr));

    ip_hdr->check = 0;
    inet_pton(AF_INET, dst_ip, (void*)&(ip_hdr->daddr));
    ip_hdr->frag_off = 0;
    ip_hdr->id = htonl(54321);
    ip_hdr->ihl = 5;
    ip_hdr->protocol = 6;
    inet_pton(AF_INET, src_ip, (void*)&(ip_hdr->saddr));
    ip_hdr->tos = 0;
    ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_length);
    ip_hdr->ttl = 255;
    ip_hdr->version = 4;

    return ip_hdr;
}

/**
 * IP checksum calculation.
 * Following RFC 1071.
 * In essence 1's complement of 16-bit groups.
 */ 
unsigned short checksum(unsigned short *addr, int nbytes)
{
    long sum = 0;

    for (int j = 0; j < 10; j++)
        sum += addr[j];
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)~sum;
}

void calc_ip_csum(struct iphdr *ip_hdr, unsigned short *pkt, int nbytes)
{
    ip_hdr->check = 0;
    ip_hdr->check = checksum((unsigned short*)ip_hdr, nbytes);
}
