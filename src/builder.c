#include <time.h>

#include "builder.h"

void calc_tcp_csum(int pay_len,
                   const char* src_ip, const char* dst_ip,
                   struct tcphdr* tcp_hdr,
                   struct embed_ts_hdr* et_hdr)
{
    struct pseudo_hdr* psh = gen_pseudo_hdr(pay_len, src_ip, dst_ip);
    if(!psh) {
        perror("Could not allocate memory for pseudo header");
        exit(1);
    }

    uint16_t tcp_csum_sz = sizeof(struct pseudo_hdr) + TCP_HDR_LEN + pay_len + 1;
    uint16_t *tcp_checksum = malloc(tcp_csum_sz);
    bzero(tcp_checksum, tcp_csum_sz);
    if (!tcp_checksum) {
        perror("Could not allocate memory for tcp checksum");
        exit(1);
    }

    memcpy(tcp_checksum, psh, sizeof(struct pseudo_hdr));
    memcpy(tcp_checksum + (uint16_t)(sizeof(struct pseudo_hdr) / sizeof(uint16_t)), tcp_hdr, TCP_HDR_LEN);
    memcpy(tcp_checksum + (uint16_t)((sizeof(struct pseudo_hdr) + TCP_HDR_LEN) / sizeof(uint16_t)),
            et_hdr, pay_len + 1);
    compute_segment_checksum(tcp_hdr, tcp_checksum, tcp_csum_sz);

    free(psh);
    free(tcp_checksum);
}

void recalc_tcp_csum(packet_t packet)
{
    char* src_ip = malloc(sizeof(char)*32);
    inet_ntop(AF_INET, (void*)&(packet.ip_hdr->saddr), src_ip, INET_ADDRSTRLEN);
    char* dst_ip = malloc(sizeof(char)*32);
    inet_ntop(AF_INET, (void*)&(packet.ip_hdr->daddr), dst_ip, INET_ADDRSTRLEN);

    packet.tcp_hdr->check = 0;
    calc_tcp_csum(packet.pay_len, src_ip, dst_ip, packet.tcp_hdr, packet.et_hdr);
    free(src_ip);
    free(dst_ip);
}

packet_t build_std_pkt(uint16_t src_port, uint16_t dst_port,
                       const char* src_ip, const char* dst_ip,
                       uint32_t tcp_seq,
                       uint32_t data_len)
{
    struct tcphdr *tcp_hdr = gen_tcp(src_port, dst_port, tcp_seq, 0, htons(5840));
    if (!tcp_hdr) {
        perror("Could not allocate memory for tcp header");
        exit(1);
    }

    struct embed_ts_hdr* et_hdr = malloc(ETS_HDR_LEN);
    et_hdr->magic = htonl(0xbabeface);
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    et_hdr->tv_sec = htonl(ts.tv_sec);
    et_hdr->tv_nsec = htonl(ts.tv_nsec);

    char* payload = NULL;
    if (data_len > 0) {
        payload = malloc(data_len);
        for (int j = 0; j < data_len; j++) {
            payload[j] = (unsigned char)(j & 0xFF);
        }
    }
    int pay_len = ETS_HDR_LEN + data_len;

    //calc_tcp_csum(pay_len, src_ip, dst_ip, tcp_hdr, et_hdr);

    char *packet = malloc(sizeof(char) * (data_len + RAWTCP_DEF_PKT_LEN));
    bzero(packet, RAWTCP_DEF_PKT_LEN);

    struct ethhdr* eth_hdr = gen_eth();
    memcpy(packet, eth_hdr, ETH_HDR_LEN);

    struct iphdr *ip_hdr = gen_ipv4(src_ip, dst_ip, pay_len);
    memcpy(packet + ETH_HDR_LEN, ip_hdr, IP4_HDR_LEN);

    free(eth_hdr);
    free(ip_hdr);
    eth_hdr = (struct ethhdr*)packet;
    ip_hdr = (struct iphdr*)(packet + ETH_HDR_LEN);
    //printf("Total length = %02x%02x\n", packet[16] & 0xFF, packet[17] & 0xFF);

    memcpy(packet + ETH_HDR_LEN + IP4_HDR_LEN + TCP_HDR_LEN, et_hdr, ETS_HDR_LEN);
    free(et_hdr);
    et_hdr = (struct embed_ts_hdr*)(packet + ETH_HDR_LEN + IP4_HDR_LEN + TCP_HDR_LEN);

#ifdef TCPGEN_DISABLE_IP4_CSUM
    ip_hdr->check = 0;
#else
    calc_ip_csum(ip_hdr, (unsigned short*)packet, ntohs(ip_hdr->tot_len));
#endif

    struct pseudo_hdr* psd_hdr = build_tcp_csum(packet, ip_hdr, tcp_hdr, pay_len);

    memcpy(packet + ETH_HDR_LEN + IP4_HDR_LEN, tcp_hdr, TCP_HDR_LEN);
    free(tcp_hdr);
    tcp_hdr = (struct tcphdr*)(packet + ETH_HDR_LEN + IP4_HDR_LEN);

    memcpy(packet + RAWTCP_DEF_PKT_LEN, payload, data_len);
    free(payload);
    payload = packet + RAWTCP_DEF_PKT_LEN;

    packet_t result;
    result.eth_hdr = eth_hdr;
    result.ip_hdr = ip_hdr;
    result.tcp_hdr = tcp_hdr;
    result.et_hdr = et_hdr;
    result.payload = payload;
    result.packet = packet;
    result.pay_len = pay_len;
    result.pkt_len = ntohs(ip_hdr->tot_len) + 14;
    result.psd_hdr = psd_hdr;

#ifdef TCPGEN_DBG 
    printf("pkt len = %d\n", result.pkt_len);
    for(int xi = 0; xi < 54; xi += 16) {
        printf("%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x\n",
                packet[xi + 0]  & 0xFF,
                packet[xi + 1]  & 0xFF,
                packet[xi + 2]  & 0xFF,
                packet[xi + 3]  & 0xFF,
                packet[xi + 4]  & 0xFF,
                packet[xi + 5]  & 0xFF,
                packet[xi + 6]  & 0xFF,
                packet[xi + 7]  & 0xFF,
                packet[xi + 8]  & 0xFF,
                packet[xi + 9]  & 0xFF,
                packet[xi + 10] & 0xFF,
                packet[xi + 11] & 0xFF,
                packet[xi + 12] & 0xFF,
                packet[xi + 13] & 0xFF,
                packet[xi + 14] & 0xFF,
                packet[xi + 15] & 0xFF);
    }
#endif

    return result;
}

int set_TCP_flags(packet_t pkt, int hex_flags)
{
    if (hex_flags > 0x200) {
        perror("Invalid flags set");
        return -1;
    }

    set_segment_flags(pkt.tcp_hdr, hex_flags);
    recalc_tcp_csum(pkt);
    return 0;
}

int set_TCP_seq_num(packet_t pkt, uint32_t bytes)
{
    set_segment_seq_num(pkt.tcp_hdr, bytes);
    recalc_tcp_csum(pkt);
    return 0;
}

int set_TCP_src_port(packet_t pkt, uint16_t bytes)
{
    set_segment_port(pkt.tcp_hdr, bytes);
    recalc_tcp_csum(pkt);
    return 0;
}

packet_t build_null_pkt(packet_t pkt)
{
    pkt.ip_hdr  = NULL;
    pkt.packet  = NULL;
    pkt.et_hdr  = NULL;
    pkt.payload = NULL;
    pkt.pay_len = 0;
    pkt.tcp_hdr = NULL;
    pkt.psd_hdr = NULL;

    return pkt;
}

int pkt_destroy(packet_t pkt)
{
    if (pkt.packet != NULL)
        free(pkt.packet);

    pkt.et_hdr  = NULL;
    pkt.payload = NULL;
    pkt.psd_hdr = NULL;
    pkt.packet  = NULL;

    return 0;
}

int embed_ts(packet_t pkt)
{
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);

    /*
    char tstamp[32];
    sprintf(tstamp, "%08lx%08lx", ts.tv_sec, ts.tv_nsec);
    printf("%s\n", tstamp);
    */

    pkt.et_hdr->tv_sec = htonl(ts.tv_sec);
    pkt.et_hdr->tv_nsec = htonl(ts.tv_nsec);

    return 0;
}

struct pseudo_hdr* build_tcp_csum(char* pkt, struct iphdr* ip_hdr, struct tcphdr* tcp_hdr, int pay_len)
{
    struct pseudo_hdr* psd_hdr = gen_pseudo_hdr2(pay_len, ip_hdr->saddr, ip_hdr->daddr);
    tcp_hdr->check = tcp_calc_csum(pkt, psd_hdr, tcp_hdr);
    return psd_hdr;
}

uint16_t tcp_calc_csum(char* pkt, struct pseudo_hdr* psd_hdr, struct tcphdr* tcp_hdr)
{
    uint16_t* pos = (uint16_t*)pkt + ETH_HDR_LEN + IP4_HDR_LEN;
    uint32_t csum = 0;

    tcp_hdr->check = 0;

    csum += (psd_hdr->src_ip & 0xFFFF) + (psd_hdr->src_ip >> 16);
    csum += (psd_hdr->dst_ip & 0xFFFF) + (psd_hdr->dst_ip >> 16);
    csum += psd_hdr->protocol_type << 8;
    uint16_t total_len = ntohs(psd_hdr->segment_length);
    csum += htons(total_len);

    for (int i = 0; i < total_len; i += 2) {
        csum += *pos;
        pos++;
        if (csum >> 31) {
            csum = (csum & 0xFFFF) + (csum >> 16);
        }
    }
    if (total_len % 2 == 1) {
        uint16_t* tail = (uint16_t*)pos;
        csum += *tail;
    }

    while (csum >> 16) {
        csum = (csum & 0xFFFF) + (csum >> 16);
    }

    return (uint16_t)~csum;
}

void tcp_csum_update(packet_t pkt)
{
    uint32_t csum = 0;
    uint16_t tcp_len = ntohs(pkt.ip_hdr->tot_len) - (pkt.ip_hdr->ihl << 2);

    uint16_t* ip_payload = (uint16_t*)(pkt.tcp_hdr);
    pkt.tcp_hdr->check = 0;

    csum += ((pkt.ip_hdr->saddr >> 16) & 0xFFFF) + (pkt.ip_hdr->saddr & 0xFFFF);
    csum += ((pkt.ip_hdr->daddr >> 16) & 0xFFFF) + (pkt.ip_hdr->daddr & 0xFFFF);
    csum += htons(IPPROTO_TCP);
    csum += htons(tcp_len);

    while (tcp_len > 1) {
        csum += *ip_payload++;
        tcp_len -= 2;
    }
    if (tcp_len > 0) {
        uint16_t* tail = (uint16_t*)ip_payload;
        csum += *tail;
    }

    while (csum >> 16) {
        csum = (csum & 0xFFFF) + (csum >> 16);
    }

    pkt.tcp_hdr->check = (uint16_t)~csum;
}
