#ifndef __SCK_MGR_H__
#define __SCK_MGR_H__

#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <unistd.h>

#include "builder.h"

int init_skt(char* if_name);
void close_skt(int sck_fd);

int rawtcp_xmit(int sck_fd, packet_t pkt);

#endif  //__SCK_MGR_H__
