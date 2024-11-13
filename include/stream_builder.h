#ifndef __STREAM_BUILDER_H__
#define __STREAM_BUILDER_H__

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "pkt.h"
#include "segment.h"
#include "stream.h"
#include "builder.h"

//Types of packet streams with hidden payloads supported
typedef enum{
    TYPE_TCP_SEQ_RAW,
    TYPE_TCP_ACK_RAW,
    TYPE_TCP_SRC_PORT
}stream_inject_type_t;

/**
 * @brief Builds packet stream with a common set of parameters
 * 
 */
stream_t build_standard_packet_stream_empty_payload(
    int stream_length,
    uint16_t source_port,
    uint16_t destination_port,
    const char* source_ip_address,
    const char* destination_ip_address
    );

void stream_destroy(stream_t stream);

stream_t stream_inject(stream_t stream, stream_inject_type_t type, char* payload, int payload_length);

#endif  //__STREAM_BUILDER_H__
