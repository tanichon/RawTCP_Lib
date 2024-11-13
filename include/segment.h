#ifndef __SEGMENT_H__
#define __SEGMENT_H__

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <netinet/tcp.h>
#include <stdint.h>

struct pseudo_hdr {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t reserved; 
    uint8_t protocol_type;
    uint16_t segment_length;    
};

struct tcphdr* gen_tcp(uint16_t src, uint16_t dst,
                       uint32_t seq_num, uint32_t ack_num, uint16_t window);
struct pseudo_hdr* gen_pseudo_hdr(uint16_t payload_length, const char *src_ip, const char *dst_ip);
struct pseudo_hdr* gen_pseudo_hdr2(uint16_t pay_len, uint32_t src_ip, uint32_t dst_ip);
void compute_segment_checksum(struct tcphdr *tcp_hdr, unsigned short *addr, int nbytes);

#define FIN 0x01
#define SYN 0x02
#define RST 0x04
#define PSH 0x08
#define ACK 0x10
#define URG 0x20
#define ECE 0x40
#define CWR 0x80

void set_segment_flags(struct tcphdr *tcp_hdr, int flags);
void set_segment_seq_num(struct tcphdr *tcp_hdr, uint32_t bytes);
void set_segment_port(struct tcphdr *tcp_hdr, uint16_t bytes);

#endif  //__SEGMENT_H__
