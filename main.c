#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#include <strings.h>
#include <string.h>
#include <arpa/inet.h>

#include <time.h>
#include <pthread.h>

#include "builder.h"
#include "sck_mgr.h"

#define USEC_PER_SEC 1000000
#define NSEC_PER_SEC 1000000000

typedef struct app_opts {
    int     sck_fd;
    char*   if_name;
    char*   src_ip;
    char*   dst_ip;
    int     local_port;
    int     remote_port;
    int     xmit_cnt;
    int     pay_len;
    int     duration;
} app_opts;

typedef struct stats_t {
    uint64_t pkts_sent;
    uint64_t bytes_sent;
} stats_t;

static inline int64_t calcdiff_ns(struct timespec t1, struct timespec t2)
{
    int64_t diff;
    diff = NSEC_PER_SEC * (int64_t)((int)t1.tv_sec - (int)t2.tv_sec);
    diff += ((int)t1.tv_nsec - (int)t2.tv_nsec);
    return diff;
}

static struct app_opts app;

static volatile int stats_alive_ = 0;
static stats_t stats_;
static volatile int tx_alive_ = 0;

void app_help(char* app);

static void* stats_routine(void* arg)
{
    stats_t* stats = (stats_t*)arg;
    double tx_pps = 0, tx_bps = 0;
    uint64_t sum_pkts_pre = 0, sum_bytes_pre = 0;

    struct timespec ts_b, ts_e;
    uint64_t diff;

    printf("                  | Tx rate    | Total\n");
    printf("------------------+------------|------------\n");

    clock_gettime(CLOCK_REALTIME, &ts_b);
    sleep(1);

    while(stats_alive_) {
        clock_gettime(CLOCK_REALTIME, &ts_e);
        diff = calcdiff_ns(ts_e, ts_b);
        tx_pps = (stats->pkts_sent - sum_pkts_pre) / 1e-6 / (double)diff;
        tx_bps = (stats->bytes_sent - sum_bytes_pre) * 8 / 1e-3 / (double)diff;

        printf("  %-16s|%12.4f|%12ld\n  %-16s|%12.4f|%12ld\n",
               "[Kpps], Total",
               tx_pps, stats->pkts_sent,
               "[Mbps], Total",
               tx_bps, stats->bytes_sent);
        printf("\033[3A\n");

        sum_pkts_pre = stats->pkts_sent;
        sum_bytes_pre = stats->bytes_sent;

        ts_b.tv_sec = ts_e.tv_sec;
        ts_b.tv_nsec = ts_e.tv_nsec;
        usleep(1000000);
    }

    return NULL;
}

void stats_run()
{
    if (stats_alive_ == 0) {
        stats_.pkts_sent = 0;
        stats_.bytes_sent = 0;

        pthread_t stats_thread;
        if (pthread_create(&stats_thread, NULL, stats_routine, (void*)&stats_)) {
            printf("Error creating thread.\n");
            return;
        }

        printf("%s; %s:%d > %s:%d; TCP, data len = %ld\n\n",
               app.if_name,
               app.src_ip, app.local_port,
               app.dst_ip, app.remote_port,
               app.pay_len + ETS_HDR_LEN);

        stats_alive_ = 1;
    }
}

void start_tx()
{
    packet_t pkt;
    pkt = build_std_pkt(app.local_port, app.remote_port, app.src_ip, app.dst_ip, 0, app.pay_len);

    stats_run();

    int pkt_len = 14 + 20 + 20 + 12 + app.pay_len + 4;
    uint32_t seq_num = 0;
    while (tx_alive_) {
        set_segment_seq_num(pkt.tcp_hdr, seq_num);
        embed_ts(pkt);
        tcp_csum_update(pkt);
        if (rawtcp_xmit(app.sck_fd, pkt) < 0) {
            printf("failed to xmit.\n");
            break;
        }
        stats_.pkts_sent++;
        stats_.bytes_sent += pkt_len;
        seq_num++;
    }
    printf("finishing Tx ...\n\n");

    pkt_destroy(pkt);
}

void* start_timer(void* op)
{
    int* duration = (int*)op;

    int max_cnt = *duration * 1000;
    int cnt = 0;
    while (cnt < max_cnt) {
        usleep(1000);
        cnt++;
    }
    tx_alive_ = 0;
    printf("\033[3B\n");

    pthread_exit(NULL);
}

void start_proc()
{
    tx_alive_ = 1;

    pthread_t timer;
    pthread_create(&timer, NULL, start_timer, &app.duration);

    start_tx();
    while (tx_alive_)
        usleep(1000);
}

int main(int argc, char* argv[])
{
    app.if_name = NULL;

    app.src_ip = malloc(16);
    app.dst_ip = malloc(16);
    strcpy(app.src_ip, "10.9.8.7");
    strcpy(app.dst_ip, "7.8.9.10");
    app.local_port  = 0x666;
    app.remote_port = 0x666;
    app.xmit_cnt = 100;
    app.pay_len = 0;
    app.duration = 0;

    int run_inf = 0;

    struct option long_opts[] = {
        { "if-name",    required_argument,  NULL, 'i' },
        { "src-ip",     required_argument,  NULL, 's' },
        { "dst-ip",     required_argument,  NULL, 'd' },
        { "local-port", required_argument,  NULL, 'l' },
        { "remote-port",required_argument,  NULL, 'r' },
        { "xmit-cnt",   required_argument,  NULL, 'x' },
        { "duration",   required_argument,  NULL, 'n' },
        { "payload-len",required_argument,  NULL, 'y' },
        { "help",       no_argument,        NULL, 'h' },
        { "run-infinitely", 0,          &run_inf, 1   }
    };
    const char* short_opts = "i:s:d:l:r:p:x:k:y:n:fh";
    int c, long_c;
    while((c = getopt_long(argc, argv, short_opts, long_opts, &long_c)) != -1) {
        switch (c) {
        case 'i':
            app.if_name = malloc(strlen(optarg));
            strcpy(app.if_name, optarg);
            break;
        case 's':
            strcpy(app.src_ip, optarg);
            break;
        case 'd':
            strcpy(app.dst_ip, optarg);
            break;
        case 'l':
            app.local_port = atoi(optarg);
            break;
        case 'r':
            app.remote_port = atoi(optarg);
            break;
        case 'y':
            app.pay_len = atoi(optarg);
            break;
        case 'x':
            app.xmit_cnt = atoi(optarg);
            break;
        case 'n':
            app.duration = atoi(optarg);
            break;
        case 'f':
            run_inf = 1;
            break;
        case 'h':
            app_help(argv[0]);
            return 0;
        }
    }
    if (app.if_name == NULL) {
        printf("interface name not specified\n");
        return 0;
    }

    app.sck_fd = init_skt(app.if_name);

    packet_t pkt = build_null_pkt(pkt);

    if (run_inf == 1) {
        pkt = build_std_pkt(app.local_port, app.remote_port, app.src_ip, app.dst_ip, 0, app.pay_len);
        stats_run();
        int pkt_len = 14 + 20 + 20 + 12 + app.pay_len + 4;

        uint32_t seq_num = 0;
        tx_alive_ = 1;
        while (tx_alive_) {
            set_segment_seq_num(pkt.tcp_hdr, seq_num);
            embed_ts(pkt);
            //recalc_tcp_csum(pkt);
            tcp_csum_update(pkt);
            if (rawtcp_xmit(app.sck_fd, pkt) < 0) {
                printf("failed to xmit.\n");
                break;
            }
            stats_.pkts_sent++;
            stats_.bytes_sent += pkt_len;
            seq_num++;
        }
    }
    else if (app.duration > 0) {
        start_proc();
    }
    else {
        pkt = build_std_pkt(app.local_port, app.remote_port, app.src_ip, app.dst_ip, 0, app.pay_len);
        for (int cnt = 0; cnt < app.xmit_cnt; cnt++) {
            set_TCP_seq_num(pkt, cnt);
            embed_ts(pkt);
            //recalc_tcp_csum(pkt);
            tcp_csum_update(pkt);
            rawtcp_xmit(app.sck_fd, pkt);
        }
    }

    pkt_destroy(pkt);
    close_skt(app.sck_fd);

    free(app.if_name);
    free(app.src_ip);
    free(app.dst_ip);

    return 0;
}

void app_help(char* app)
{
    printf("Usage : %s [OPTIONS]\n\n", app);

    printf("\t-i\t--if-name\t<if name>\tinterface name\n");
    printf("\t-s\t--src-ip\t<src ip>\tdefault = 10.9.8.7\n");
    printf("\t-d\t--dst-ip\t<dst ip>\tdefault = 7.8.9.10\n");
    printf("\t-l\t--local-port\t<tcp src>\tdefault = 0x666\n");
    printf("\t-r\t--remote-port\t<tcp dst>\tdefault = 0x666\n");
    printf("\t-y\t--payload-len\t<bytes>\t\tdata length except for tstamp header(12).\n \
            \t\t\t\t\tdefault is 0,\n \
            \t\t\t\t\twhich means the minimum pkt-len is 70(Eth/IPv4/TCP/tstamp/FCS).\n");
    printf("\t-x\t--xmit-cnt\t<xmit num>\txmit count. default = 100\n");
    printf("\t-n\t--duration\t<seconds>\tduration time[sec].\n");
    printf("\t-f\t--run-infinitely\t\tinfinitely works.\n");
    printf("\t-h\t--help\t\tprint this message and exit\n");
    printf("\n");
    printf("run with privilege mode.\n");
    printf("\n");
}

