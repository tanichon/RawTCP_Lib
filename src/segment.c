#include "../include/segment.h"
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

struct tcphdr* gen_tcp(uint16_t src_port, uint16_t dst_port,
                       u_int32_t seq_num,
                       u_int32_t ack_num,
                       uint16_t window)
{
    struct tcphdr *tcp_hdr = malloc(sizeof(struct tcphdr));
    bzero(tcp_hdr, sizeof(struct tcphdr));

    tcp_hdr->source = htons(src_port);
    tcp_hdr->dest = htons(dst_port);

    tcp_hdr->seq = htonl(seq_num);
    tcp_hdr->ack_seq = ack_num;

    tcp_hdr->doff = 5;  //5 bytes, no options

    tcp_hdr->fin = 0;
    tcp_hdr->psh = 0;
    tcp_hdr->rst = 0;
    tcp_hdr->syn = 0;
    tcp_hdr->urg = 0;
    tcp_hdr->ack = 0;

    tcp_hdr->window = window;
    tcp_hdr->check = 0;
    tcp_hdr->urg_ptr = 0;

    return tcp_hdr;
}

struct pseudo_hdr* gen_pseudo_hdr(uint16_t pay_len, const char *src_ip, const char *dst_ip)
{
    struct pseudo_hdr *psh = malloc(sizeof(struct pseudo_hdr));
    bzero(psh, sizeof(struct pseudo_hdr));

    inet_pton(AF_INET, dst_ip, (void*)&(psh->dst_ip));
    inet_pton(AF_INET, src_ip, (void*)&(psh->src_ip));
    psh->protocol_type = IPPROTO_TCP;
    psh->reserved = 0;
    psh->segment_length = htons(pay_len+sizeof(struct tcphdr));

    return psh;
}

struct pseudo_hdr* gen_pseudo_hdr2(uint16_t pay_len, uint32_t src_ip, uint32_t dst_ip)
{
    struct pseudo_hdr *psh = malloc(sizeof(struct pseudo_hdr));
    bzero(psh, sizeof(struct pseudo_hdr));

    psh->src_ip = src_ip;
    psh->dst_ip = dst_ip;
    psh->protocol_type = IPPROTO_TCP;
    psh->reserved = 0;
    psh->segment_length = htons(pay_len+sizeof(struct tcphdr));

    return psh;
}

/**
 * TCP checksum calculation.
 * Following RFC 1071.
 * In essence 1's complement of 16-bit groups.
 */ 
unsigned short tcp_checksum(unsigned short *addr, int nbytes)
{
    long sum = 0;
    unsigned short checksum;

    while (nbytes > 1) {
        sum += (unsigned short) *addr++;
        nbytes -= 2;
    }
    if (nbytes > 0) {
        sum += htons((unsigned char)*addr);
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    checksum = ~sum;
    return checksum;
}

void compute_segment_checksum(struct tcphdr *tcp_hdr, unsigned short *addr, int nbytes)
{
    uint16_t res = tcp_checksum(addr, nbytes);
    tcp_hdr->check = res;
}

void set_segment_flags(struct tcphdr *tcphdr, int flags)
{
    int iterator = 1;
    int *result = malloc(sizeof(int)*8);
    int counter = 0;
    while (iterator <= flags) {
        if (iterator & flags) {
            result[counter] = iterator;            
        } 
        counter++;
        iterator <<= 1;
    }

    for(int ii = 0; ii < 8; ii++) {
        if((result[ii] - CWR) == 0) tcphdr->res1 = 1;
        if((result[ii] - ECE) == 0) tcphdr->res2 = 1;
        if((result[ii] - URG) == 0) tcphdr->urg = 1;
        if((result[ii] - ACK) == 0) tcphdr->ack = 1;
        if((result[ii] - PSH) == 0) tcphdr->psh = 1;
        if((result[ii] - RST) == 0) tcphdr->rst = 1;
        if((result[ii] - SYN) == 0) tcphdr->syn = 1;
        if((result[ii] - FIN) == 0) tcphdr->fin = 1;
    }
}

void set_segment_seq_num(struct tcphdr *tcp_hdr, uint32_t bytes)
{
    tcp_hdr->seq = htonl(bytes);
}

void set_segment_port(struct tcphdr *tcp_hdr, uint16_t bytes)
{
    tcp_hdr->source = htons(bytes);
}
