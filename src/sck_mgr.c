#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "../include/sck_mgr.h"

int init_skt(char* if_name)
{
    int fd;
    struct ifreq req;

    struct sockaddr_ll sa2;
    memset(&sa2, 0, sizeof(sa2));
    sa2.sll_family = PF_PACKET;
    sa2.sll_protocol = htons(ETH_P_ALL);

    fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        fprintf(stderr,"socket=%d\n",errno);
        perror("socket");
        exit(1);
    }

    memset(&req,0,sizeof(req));
    strncpy(req.ifr_name, if_name, IFNAMSIZ);
    if (ioctl(fd, SIOCGIFINDEX, &req) < 0) {
        fprintf(stderr,"ioctl=%d\n", errno);
        perror("SIOCGIFINDEX");
        close(fd);
        return -1;
    }

    sa2.sll_ifindex = req.ifr_ifindex;
    if (bind(fd, (struct sockaddr*)&sa2, sizeof(struct sockaddr_ll)) < 0) {
        fprintf(stderr,"bind=%d\n", errno);
        perror("bind");
        close(fd);
        return -1;
    }

    return fd;
}

void close_skt(int sck_fd)
{
    close(sck_fd);
}

int rawtcp_xmit(int sck_fd, packet_t pkt)
{
    int len = write(sck_fd, pkt.packet, pkt.pkt_len);
    if (len < 0) {
        perror("Write Raw socket");
        return -1;
    }

    return 0;
}
