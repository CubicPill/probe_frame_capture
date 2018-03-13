#include "pcap.h"
#include "capture.h"

#ifdef _WIN32

#error "Windows is not supported"
#endif

#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include<errno.h>

struct sockaddr_in server_addr;
int sock;
char whitelist_mac[18];

int main(int argc, char *const argv[]) {
    memset(whitelist_mac, 0, 18);
    if (argc < 3) {
        fprintf(stderr, "No server address or port specified!");
        exit(1);
    }
    if (argc == 4) {
        strncpy(whitelist_mac, argv[3], 18);
    }
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons((unsigned short) strtol(argv[2], NULL, 10));
    if (inet_pton(AF_INET, argv[1], &server_addr.sin_addr) <= 0) {
        printf("inet_pton error for %s\n", argv[1]);
        exit(1);
    }


    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int i = 0;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    for (d = alldevs; d; d = d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0) {
        printf("\nNo interfaces found! Make sure Libpcap / WinPcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d):", i);
    scanf("%d", &inum);

    if (inum < 1 || inum > i) {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);


    if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL) {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Libpcap / WinPcap\n", d->name);
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\nlistening on %s...\n", d->description);

    pcap_freealldevs(alldevs);
    pcap_loop(adhandle, 0, packet_handler, NULL);

    pcap_close(adhandle);
    return 0;
}

int format_mac(const unsigned char *mac, char *result) {
    for (int i = 0; i < 6; ++i) {
        sprintf(result + 3 * i, "%02X-", mac[i]);
    }
    result[17] = '\0';
    return 1;
}


int filter_802_11_probe_frame(const u_char *data) {
    u_char frame_control = data[0x20];
    if ((frame_control >> 2) == 0x10) {
        // it's 010000xx in binary, type=0x0, subtype=0x4
        return 1;
    }
    return 0;
}

int parse_frame(const u_char *data, struct frame_info *f) {
    memcpy(f->src_mac, data + 0x2a, 6);
    memcpy(f->dst_mac, data + 0x24, 6);
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

