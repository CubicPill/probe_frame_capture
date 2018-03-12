#include <time.h>

#ifndef PROBE_FRAME_CAPTURE_CAPTURE_H
#define PROBE_FRAME_CAPTURE_CAPTURE_H

typedef struct frame_info {
    signed char ssi_signal_dBm;
    time_t timestamp;
    unsigned char src_mac[6];
    unsigned char dst_mac[6];
} frame_info;

int parse_frame(const u_char *data, struct frame_info *f);

int filter_802_11_probe_frame(const u_char *data);

int format_mac(const unsigned char *mac, char *result);

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);


#endif //PROBE_FRAME_CAPTURE_CAPTURE_H
