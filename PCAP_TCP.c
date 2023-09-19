#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    struct ethhdr *eth_header = (struct ethhdr*)packet;
    struct ip *ip_header = (struct ip*)(packet + sizeof(struct ethhdr));
    struct tcphdr *tcp_header = (struct tcphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct ip));

    printf("-------------------------------------------------------\n");
    printf("TCP Protocol's Header\n\n");
    printf("Ethernet Header\n");
    printf("  Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth_header->h_source[0], eth_header->h_source[1], eth_header->h_source[2],
           eth_header->h_source[3], eth_header->h_source[4], eth_header->h_source[5]);
    printf("  Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth_header->h_dest[0], eth_header->h_dest[1], eth_header->h_dest[2],
           eth_header->h_dest[3], eth_header->h_dest[4], eth_header->h_dest[5]);

    printf("IP Header\n");
    printf("  Source IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("  Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));

    printf("TCP Header\n");
    printf("  Source Port: %u\n", ntohs(tcp_header->th_sport));
    printf("  Destination Port: %u\n", ntohs(tcp_header->th_dport));
    printf("\n");
    printf("-------------------------------------------------------\n");
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // 패킷 캡처 장치를 열기
    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
    
    if (handle == NULL) {
        fprintf(stderr, "패킷 캡처 장치 열기 실패: %s\n", errbuf);
        return 1;
    }

    // 패킷을 캡처하고 패킷 핸들러 함수 호출
    pcap_loop(handle, 0, packet_handler, NULL);
    
    // 패킷 캡처 장치 닫기
    pcap_close(handle);

    return 0;
}
