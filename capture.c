#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "pcap.h"
#include "capture.h"

#include <stdlib.h>
#include <time.h>

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main() {
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
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
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

int format_mac(const u_char *data, char *result) {
    for (int i = 0; i < 5; ++i) {
        sprintf(result + 3 * i, "%02X-", data[i]);
    }
    sprintf(result + 15, "%02X\0", data[5]);
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

int parse_frame(const u_char *data) {
    char src_mac[18];
    char dst_mac[18];
    format_mac(data + 0x2a, src_mac);
    format_mac(data + 0x24, dst_mac);
    printf("Src:%s Dst: %s\n", src_mac, dst_mac);
    printf("Signal: -%d\n", 0xff - (data[0x16] - data[0x17]) + 1);
    return 1;

}


void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    if (!filter_802_11_probe_frame(pkt_data)) {
        return;
    }


    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;



    /* convert the timestamp to readable format */
    local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

    printf("%s,%.6li len:%d\n", timestr, header->ts.tv_usec, header->len);
    parse_frame(pkt_data);
    /*


     char *dst_mac = malloc(18);

     char *src_mac = malloc(18);
     format_mac(pkt_data, dst_mac);
     format_mac(pkt_data + 6, src_mac);
     printf("Dst:%s\n", dst_mac);
     printf("Src:%s\n", src_mac);
     free(dst_mac);

     free(src_mac);
 */


}
