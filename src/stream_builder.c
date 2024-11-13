#include "stream_builder.h"

stream_t build_standard_packet_stream_empty_payload(int stream_length,
                                                    uint16_t src_port, uint16_t dst_port,
                                                    const char* src_ip, const char* dst_ip)
{
    stream_t stream_res;
    stream_res.packet_stream = calloc(stream_length, sizeof(packet_t));
    stream_res.stream_length = 0;
    if(stream_length < 1) {
        perror("Invalid option, requested to build empty packet stream");
        stream_res.packet_stream = NULL;
        stream_res.stream_length = 0;
        return stream_res;
    }

    for (int ii = 0; ii < stream_length; ii++) {
        packet_t pkt = build_std_pkt(src_port, dst_port, src_ip, dst_ip, ii, 4096);
        if (pkt.tcp_hdr == NULL) {
            stream_res.packet_stream = NULL;
            stream_res.stream_length = 0;
            return stream_res;
        }
        memcpy(stream_res.packet_stream + ii * (sizeof(packet_t)), (void*)&pkt, sizeof(packet_t));
        stream_res.stream_length++;
    }

    return stream_res;
}

void stream_destroy(stream_t stream)
{
    if(stream.stream_length < 1) {
        return;
    }

    for(int ii = 0; ii < stream.stream_length; ii++) {
        packet_t pkt;
        memcpy(&pkt, stream.packet_stream + ii * sizeof(packet_t), sizeof(packet_t));
        pkt_destroy(pkt);
    }
    stream.stream_length = 0;
    free(stream.packet_stream);
}

/**
 * @brief Injects a char array into a position in a packet, depending on selected mode
 * 
 * @param stream 
 * @param type 
 * @param payload 
 * @param payload_length 
 * @return stream_t 
 */
stream_t stream_inject(stream_t stream, stream_inject_type_t type, char* payload, int payload_length)
{
    if (payload_length < 1 || stream.stream_length < 1) {
        printf("Injection not possible on stream: Payload or stream too short\n");
        return stream;
    }

    switch (type) {
    case TYPE_TCP_SEQ_RAW:
        if (payload_length > stream.stream_length * 4) {
            printf("Injection not possible on stream: Stream too short for the payload\n");
            return stream;
        }
        if (payload_length % 4 != 0) {
            printf("Injection not possible on stream: This mode requires the payload length to be multiple of 4\n");
            return stream;
        }

        for (int ii = 0; ii < payload_length / 4; ii++) {
            u_int32_t bytes;
            memcpy(&bytes, payload + ii * sizeof(u_int32_t), sizeof(u_int32_t));
            set_TCP_seq_num((packet_t) * (stream.packet_stream + ii * sizeof(packet_t)), bytes);
        }
        break;
    case TYPE_TCP_ACK_RAW:
        break;
    case TYPE_TCP_SRC_PORT:
        if (payload_length > stream.stream_length * 2) {
            printf("Injection not possible on stream: Stream too short for the payload\n");
            return stream;
        }
        if (payload_length % 2 != 0) {
            printf("Injection not possible on stream: This mode requires the payload length to be multiple of 4\n");
            return stream;
        }
        for (int ii = 0; ii < payload_length / 2; ii++) {
            uint16_t bytes;
            memcpy(&bytes, payload + ii * sizeof(uint16_t), sizeof(uint16_t));
            set_TCP_src_port((packet_t) * (stream.packet_stream + ii * sizeof(packet_t)), bytes);
        }
        break;
    default:
        printf("Injection not possible on stream: Invalid type\n");
        break;
    }

    return stream;
}
