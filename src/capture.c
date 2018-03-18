#include <pcap.h>
#include "capture.h"

#include<sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include<errno.h>

struct sockaddr_in server_addr;
int sock;
char whitelist_mac[18];

int main(int argc, char *const argv[]) {
    if (argc == 2 && strcmp(argv[1], "list") == 0) {
        list_interfaces();
        exit(0);
    }
    memset(whitelist_mac, 0, 18);
    if (argc < 4) {
        fprintf(stderr, "No interface, server address or port specified!\n");
        printf("Usage: %s <interface name> <server> <port> <(Optional) MAC>\n", argv[0]);
        exit(1);
    }
    if (argc == 5) {
        if (strlen(whitelist_mac) != 17) {
            printf("Invalid MAC %s, whitelist will not be enabled\n", argv[4]);
        } else {
            strncpy(whitelist_mac, argv[4], 18);
        }
    }
    char *interface = argv[1];
    char *ip = argv[2];
    char *port = argv[3];

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons((unsigned short) strtol(port, NULL, 10));
    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        printf("inet_pton error for %s\n", ip);
        exit(1);
    }

    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];


    if ((adhandle = pcap_open_live(interface, 65536, 1, 1000, errbuf)) == NULL) {
        fprintf(stderr, "Unable to open the adapter %s \n", interface);
        return -1;
    }

    printf("\nListening on %s...\n\n", interface);

    pcap_loop(adhandle, 0, packet_handler, NULL);

    pcap_close(adhandle);
    return 0;
}

void list_interfaces() {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    for (d = alldevs; d; d = d->next) {
        printf("%s", d->name);
        if (d->description) {
            printf(" (%s)\n", d->description);
        } else {
            printf(" (No description available)\n");
        }
        i++;
    }

    if (i == 0) {
        printf("No interfaces found!\n");
    }


    pcap_freealldevs(alldevs);

}

int format_mac(const unsigned char *mac, char *result) {
    for (int i = 0; i < 6; ++i) {
        sprintf(result + 3 * i, "%02X-", mac[i]);
    }
    result[17] = '\0';
    return 1;
}


int filter_802_11_probe_frame(const u_char *data) {
    uint16_t radiotap_len = (data[0x3] << 8) | data[0x2];
    u_char frame_control = data[radiotap_len];
    if ((frame_control >> 2) == 0x10) {
        // it's 010000xx in binary, type=0x0, subtype=0x4
        return 1;
    }
    return 0;
}

int parse_frame(const u_char *data, struct frame_info *f) {
    uint16_t radiotap_len = (data[0x3] << 8) | data[0x2];
    memcpy(f->src_mac, data + radiotap_len + 0xa, 6);
    memcpy(f->dst_mac, data + radiotap_len + 0x4, 6);
    f->ssi_signal_dBm = (signed char) -(~(data[0x16] - data[0x17]) + 1);
    return 1;
}


void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    if (!filter_802_11_probe_frame(pkt_data)) {
        return;
    }


    struct frame_info f;
    time(&f.timestamp);
    parse_frame(pkt_data, &f);
    char dst_mac[18];

    char src_mac[18];
    format_mac(f.src_mac, src_mac);
    if (strlen(whitelist_mac) == 17) {
        if (strcmp(src_mac, whitelist_mac) != 0) {
            printf("Packet from %s, filtered\n", src_mac);
            return;
        }
    }
    format_mac(f.dst_mac, dst_mac);
    printf("Timestamp:%ld\nSrc:%s\nDst:%s\nSignal:%ddBm\n\n", f.timestamp, src_mac, dst_mac, f.ssi_signal_dBm);
    char send_buffer[1024];
    memset(send_buffer, 0, 1024);
    sprintf(send_buffer, "ts:%ld\nsrc:%s\ndst:%s\nsignal:%d", f.timestamp, src_mac, dst_mac, f.ssi_signal_dBm);
    sendto(sock, send_buffer, strlen(send_buffer), 0, (struct sockaddr *) &server_addr, sizeof(server_addr));


}

