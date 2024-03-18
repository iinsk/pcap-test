#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>

#define ETHER_HEADER_LEN 14
#define MAX_BYTES_TO_CAPTURE 10

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test eth0\n");
    // by unknown problem, can't find&use wlan0
    // capture eto0 packet
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void print_hex(const u_char *data, int size) {
    int bytes_to_print = size > MAX_BYTES_TO_CAPTURE ? MAX_BYTES_TO_CAPTURE : size;
    for (int i = 0; i < bytes_to_print; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

void packet_handler(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *packet) {
    struct ethhdr *eth_header = (struct ethhdr *)packet;
    if (ntohs(eth_header->h_proto) != ETHERTYPE_IP) return; // Only IP packets

    struct iphdr *ip_header = (struct iphdr *)(packet + ETHER_HEADER_LEN);
    if (ip_header->protocol != IPPROTO_TCP) return; // Only TCP packets

    struct tcphdr *tcp_header = (struct tcphdr *)((u_char *)ip_header + ip_header->ihl * 4);

    printf("Source MAC: ");
    for (int i = 0; i < ETH_ALEN; i++) {
        printf("%02x", eth_header->h_source[i]);
        if (i < ETH_ALEN - 1) printf(":");
    }

    printf("\nDestination MAC: ");
    for (int i = 0; i < ETH_ALEN; i++) {
        printf("%02x", eth_header->h_dest[i]);
        if (i < ETH_ALEN - 1) printf(":");
    }

    printf("\nSource IP: %s\n", inet_ntoa(*(struct in_addr *)&ip_header->saddr));
    printf("Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&ip_header->daddr));

    printf("Source Port: %u\n", ntohs(tcp_header->source));
    printf("Destination Port: %u\n", ntohs(tcp_header->dest));

    int data_offset = ETHER_HEADER_LEN + ip_header->ihl * 4 + tcp_header->doff * 4;
    int data_size = pkt_header->caplen - data_offset;
    if (data_size > 0) {
        printf("Payload (Hex): ");
        print_hex(packet + data_offset, data_size);
    } else {
        printf("No Payload\n");
    }
    printf("-----------------------------------------------\n");
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv)) return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        packet_handler(NULL, header, packet);
    }

    pcap_close(pcap);
    return 0;
}
