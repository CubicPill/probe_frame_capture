#include <time.h>
#include <stdint.h>
#include <pcap.h>

#ifndef PROBE_FRAME_CAPTURE_CAPTURE_H
#define PROBE_FRAME_CAPTURE_CAPTURE_H

typedef struct frame_info {
    signed char ssi_signal_dBm;
    time_t timestamp;
    unsigned char src_mac[6];
    unsigned char dst_mac[6];
} frame_info;

typedef struct global_args {
    uint8_t list_all;
    char interface[16];
    uint8_t send_to_server;
    char server_addr[64];
    uint8_t has_port;
    uint16_t port;
    uint8_t filter_mac;
    char whitelist_mac[18];
} global_args;

void parse_args(int argc, char **argv, struct global_args *args);

int parse_frame(const u_char *data, struct frame_info *f);

int filter_802_11_probe_frame(const u_char *data);

int format_mac(const unsigned char *mac, char *result);

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

void list_interfaces();

void print_usage_and_exit(const char *progname);

#endif //PROBE_FRAME_CAPTURE_CAPTURE_H
