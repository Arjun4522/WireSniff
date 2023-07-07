#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <ctype.h>
#include <string.h>
#include <time.h>

#define A1(addr) inet_ntoa(addr)
#define A2(addr) inet_ntoa(addr)

char *d;
char e[PCAP_ERRBUF_SIZE];
pcap_t* c;
const u_char *p;
struct pcap_pkthdr h;
struct ether_header *ep;
bpf_u_int32 m;
bpf_u_int32 n;
struct in_addr a;
char ip[INET_ADDRSTRLEN];
char s[INET_ADDRSTRLEN];

void g(u_char *args, const struct pcap_pkthdr* ph, const u_char* pkt) {
    int i = 0;
    static int count = 0;

    struct tm *ltime;
    char timestr[16];

    ltime = localtime(&ph->ts.tv_sec);
    strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);

    ep = (struct ether_header*) pkt;
    struct ip* iph = (struct ip*)(pkt + sizeof(struct ether_header));
    struct tcphdr* tcph = (struct tcphdr*)(pkt + sizeof(struct ether_header) + iph->ip_hl * 4);
    struct udphdr* udph = (struct udphdr*)(pkt + sizeof(struct ether_header) + iph->ip_hl * 4);
    struct icmphdr* icmph = (struct icmphdr*)(pkt + sizeof(struct ether_header) + iph->ip_hl * 4);

    a.s_addr = m;
    strncpy(ip, A1(a), INET_ADDRSTRLEN);

    a.s_addr = n;
    strncpy(s, A2(a), INET_ADDRSTRLEN);

    printf("Interface: %s\n", d);
    printf("Network IP address: %s\n", s);
    printf("Source IP: %s\n", inet_ntoa(iph->ip_dst));
    printf("Source Port: %d\n", ntohs(tcph->th_dport));
    printf("Destination IP: %s\n", inet_ntoa(iph->ip_src));
    printf("Destination Port: %d\n", ntohs(tcph->th_sport));
    printf("Subnet mask: %s\n", ip);
    printf("Timestamp: %s\n", timestr);
    printf("Packet Count: %d\n", ++count);
    printf("Received Packet Size: %d\n", ph->len);

    switch (iph->ip_p) {
        case IPPROTO_TCP:
            printf("Protocol: TCP\n");
            break;
        case IPPROTO_UDP:
            printf("Protocol: UDP\n");
            break;
        case IPPROTO_ICMP:
            printf("Protocol: ICMP\n");
            break;
        default:
            printf("Protocol: Unknown\n");
            break;
    }

    printf("Payload:\n");

    for (i = 0; i < ph->len; i++) {
        if (isprint(pkt[i]))
            printf("%c ", pkt[i]);
        else
            printf(" . ");
        if ((i % 16 == 0 && i != 0) || i == ph->len - 1)
            printf("\n");
    }

    printf("\n\n");
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stdout, "Usage: %s \"interface\"\n", argv[0]);
        return 0;
    }

    d = argv[1];

    if (d == NULL) {
        fprintf(stderr, "Could not find interface: %s\n", e);
        exit(1);
    }

    if (pcap_lookupnet(d, &n, &m, e) == -1) {
        fprintf(stderr, "Error while getting interface information: %s\n", e);
        exit(1);
    }

    c = pcap_open_live(d, BUFSIZ, 1, 1000, e);
    if (c == NULL) {
        printf("pcap_open_live(): %s\n", e);
        exit(1);
    }

    printf("Waiting for traffic on interface %s....\n\n", d);

    pcap_loop(c, -1, g, NULL);

    return 0;
}

