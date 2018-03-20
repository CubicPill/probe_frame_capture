#include "capture.h"
#include "pcap.h"
#include "radiotap_iter.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <netdb.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

struct sockaddr_in server_addr;
int sock;
struct global_args args;
char *const filter_string = "wlan[0] >> 2 = 0x10";
char errbuf[PCAP_ERRBUF_SIZE];

int main(int argc, char **argv) {
    memset(&args, 0, sizeof(args));
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);

    parse_args(argc, argv, &args);

    if (args.list_all) {
        list_interfaces();
        exit(0);
    } else if (strlen(args.interface) == 0) {
        fprintf(stderr, "No interface specified!\n");
        print_usage_and_exit(argv[0]);
    }
    if (args.send_to_server) {
        if (!args.has_port) {
            fprintf(stderr, "No port specified!\n");
            print_usage_and_exit(argv[0]);
        }

        sock = socket(AF_INET, SOCK_DGRAM, 0);
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(args.port);
        if (inet_pton(AF_INET, args.server_addr, &server_addr.sin_addr) == -1) { /*not ip*/
            struct hostent *r;
            if ((r = gethostbyname(args.server_addr)) == NULL) { /*hostname not found*/
                fprintf(stderr, "Error: Can't find %s\n", args.server_addr);
                exit(1);
            } else {
                server_addr.sin_addr = *((struct in_addr *) r->h_addr);
            }
        }

    }

    printf("Running configurations:\n"
                   "Listen on: %s\n"
                   "Remote logging: ", args.interface);
    if (args.send_to_server) {
        printf("Yes, to %s:%d\n", args.server_addr, args.port);
    } else {
        printf("No\n");
    }
    printf("MAC filter: ");
    if (args.filter_mac) {
        printf("Yes, accept %s only\n", args.whitelist_mac);
    } else {
        printf("No\n");
    }
    struct bpf_program filter;
    memset(&filter, 0, sizeof(filter));
    pcap_t *adhandle;


    if ((adhandle = pcap_open_live(args.interface, 65536, 1, 1000, errbuf)) == NULL) {
        fprintf(stderr, "Unable to open the adapter %s: %s\n", args.interface, errbuf);
        return 1;
    }

    if (pcap_compile(adhandle, &filter, filter_string, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        pcap_perror(adhandle, "pcap_compile error: ");
        return 1;
    }
    if (pcap_setfilter(adhandle, &filter) == -1) {
        pcap_perror(adhandle, "pcap_setfilter error: ");
        return 1;
    }

    printf("\nListening on %s...\n\n", args.
            interface);

    pcap_loop(adhandle, 0, packet_handler, NULL);

    pcap_close(adhandle);
    return 0;
}

void print_usage_and_exit(const char *progname) {
    printf("Usage: %s <interface name>\n"
                   "Optional arguments:\n"
                   "-s <server>\n"
                   "-p <port>\n"
                   "--filter <MAC address>\n", progname);
    exit(1);
}

void parse_args(int argc, char **argv, struct global_args *args) {
    if (argc == 1) {
        print_usage_and_exit(argv[0]);
    } else if (argc == 2) {
        if (strncmp(argv[1], "list", 4) == 0) {
            args->list_all = 1;
        } else { /*interface*/
            strncpy(args->
                    interface, argv[1], 15);
        }

    } else {
        strncpy(args->
                interface, argv[1], 15);
        for (int i = 2; i < argc; ++i) {
            if (strncmp(argv[i], "-p", 2) == 0 && i + 1 < argc && argv[i + 1][0] != '-') {
                args->port = (uint16_t) strtol(argv[i + 1], NULL, 10);
                args->has_port = 1;
                ++i;
            } else if (strncmp(argv[i], "-s", 2) == 0 && i + 1 < argc && argv[i + 1][0] != '-') {
                strncpy(args->server_addr, argv[i + 1], 63);
                args->send_to_server = 1;
                ++i;
            } else if (strncmp(argv[i], "--filter", 8) == 0 && i + 1 < argc && argv[i + 1][0] != '-') {
                strncpy(args->whitelist_mac, argv[i + 1], 17);
                args->filter_mac = 1;
                ++i;
            }
        }
    }
}

void list_interfaces() {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i = 0;

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
    // only used for testing
    uint16_t radiotap_len = (data[0x3] << 8) | data[0x2];
    u_char frame_control = data[radiotap_len];
    if ((frame_control >> 2) == 0x10) {
        // it's 010000xx in binary, type=0x0, subtype=0x4
        return 1;
    }
    return 0;
}

int parse_frame(const u_char *data, size_t len, struct frame_info *f) {
    struct ieee80211_radiotap_iterator iter;
    int err = 0;
    err = ieee80211_radiotap_iterator_init(&iter, (struct ieee80211_radiotap_header *) data, len, NULL);
    if (err) {
        return 0;
    }
    while (!(err = ieee80211_radiotap_iterator_next(&iter))) {
        if (iter.is_radiotap_ns) {
            if (iter.this_arg_index == IEEE80211_RADIOTAP_DBM_ANTSIGNAL) {
                f->ssi_signal_dBm = *(signed char *) iter.this_arg;
            }
        }

    }
    uint16_t radiotap_len = (data[0x3] << 8) | data[0x2];
    memcpy(f->src_mac, data + radiotap_len + 0xa, 6);
    memcpy(f->dst_mac, data + radiotap_len + 0x4, 6);
    return 1;
}


void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    assert(filter_802_11_probe_frame(pkt_data));

    struct frame_info f;
    memset(&f, 0, sizeof(f));
    time(&f.timestamp);

    if (!parse_frame(pkt_data, header->len, &f)) {
        fprintf(stderr, "Error parsing frame. Corrupted?");
        return;
    }

    char dst_mac[18];
    char src_mac[18];
    format_mac(f.src_mac, src_mac);

    if (args.filter_mac) {
        if (strcmp(src_mac, args.whitelist_mac) != 0) {
            printf("Packet from %s, filtered\n", src_mac);
            return;
        }
    }
    format_mac(f.dst_mac, dst_mac);
    printf("Timestamp:%ld\nSrc:%s\nDst:%s\nSignal:%ddBm\n\n", f.timestamp, src_mac, dst_mac, f.ssi_signal_dBm);
    char send_buffer[1024];
    memset(send_buffer, 0, 1024);
    sprintf(send_buffer, "ts:%ld\nsrc:%s\ndst:%s\nsignal:%d", f.timestamp, src_mac, dst_mac, f.ssi_signal_dBm);
    if (args.send_to_server) {
        sendto(sock, send_buffer, strlen(send_buffer), 0, (struct sockaddr *) &server_addr, sizeof(server_addr));
    }

}

