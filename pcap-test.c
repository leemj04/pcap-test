#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

#include "libnet/include/libnet/libnet-macros.h"
#include "libnet/include/libnet/libnet-headers.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
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

void print_etherhost(u_int8_t *host) {
	for(int i=0; i<ETHER_ADDR_LEN; i++) {
		printf("%02x", host[i]);
		if(i != ETHER_ADDR_LEN-1) {
			printf(":");
		}
	}
	printf("\n");
}

void print_ethernet(struct libnet_ethernet_hdr* eth_hdr) {
	printf("Src MAC : ");
	print_etherhost(eth_hdr->ether_shost);
	
	printf("Dst MAC : ");
	print_etherhost(eth_hdr->ether_dhost);
}

void print_ipaddr(struct in_addr a) {
	in_addr_t ipaddr = a.s_addr;
	for(int i=0; i<4; i++) {
		printf("%d", ipaddr & 0xFF);
		ipaddr >>= 8;
		if (i != 3) {
			printf(".");
		}
	}
	printf("\n");
}

void print_ip(struct libnet_ipv4_hdr* ip_hdr) {
	printf("Src IP : ");
	print_ipaddr(ip_hdr->ip_src);
	
	printf("Dst IP : ");
	print_ipaddr(ip_hdr->ip_dst);
}

void print_tcp(struct libnet_tcp_hdr* tcp_hdr) {
	printf("Src PORT : %d\n", ntohs(tcp_hdr->th_sport));
	printf("Dst PORT : %d\n", ntohs(tcp_hdr->th_dport));
}

void print_data(uint8_t *data, uint16_t data_len) {
	if (data_len > 20) data_len = 20;
	
	for(int i=0; i<data_len; i++) {
		printf("%02x ", data[i]);
		if (i % 8 == 7) {
			printf("\n");
		}
	}
	printf("\n");
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

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
		
		struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr*) packet;
		struct libnet_ipv4_hdr *ip_hdr = (struct libnet_ipv4_hdr*) ((uint8_t *)eth_hdr + sizeof(*eth_hdr));
		struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr*) ((uint8_t *)ip_hdr + sizeof(*ip_hdr));
		uint8_t *data = (uint8_t *) ((uint8_t *)tcp_hdr + sizeof(*tcp_hdr));
		uint16_t data_len = ntohs(ip_hdr->ip_len) - sizeof(*ip_hdr) - sizeof(*tcp_hdr);
		
		if (ip_hdr->ip_p != IPPROTO_TCP) {
			printf("Not TCP packet\n");
			continue;
		}
		
		if (ntohs(eth_hdr->ether_type) != 0x0800) {
			printf("Not IPv4 packet\n");
			continue;
		}
		
		printf("====================================================\n");
		printf("[ETHERNET]\n");
		print_ethernet(eth_hdr);
		
		printf("\n[IP]\n");
		print_ip(ip_hdr);
		
		printf("\n[TCP]\n");
		print_tcp(tcp_hdr);
		
		printf("\n[DATA]\n");
		print_data(data, data_len);
	}

	pcap_close(pcap);
}

