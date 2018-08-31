#include "stdafx.h"
#include "prtcl_hdr.h"
#include "util.h"
#pragma comment (lib, "ws2_32.lib")

eth_header *packet_parse_ethhdr(const char *cp)
{
	eth_header *hdr, *tmp;
	tmp = (eth_header *)cp;
	hdr = MALLOC(eth_header, 1);
	memset(hdr, 0, sizeof(eth_header));
	//memcpy(hdr->ether_dhost, tmp->ether_dhost, 6 * sizeof(u_int8_t));
	hdr->ether_shost.byte1 = tmp->ether_shost.byte1;
	hdr->ether_shost.byte2 = tmp->ether_shost.byte2;
	hdr->ether_shost.byte3 = tmp->ether_shost.byte3;
	hdr->ether_shost.byte4 = tmp->ether_shost.byte4;
	hdr->ether_shost.byte5 = tmp->ether_shost.byte5;
	hdr->ether_shost.byte6 = tmp->ether_shost.byte6;
	//memcpy(hdr->ether_shost, tmp->ether_shost, 6 * sizeof(u_int8_t));
	hdr->ether_dhost.byte1 = tmp->ether_dhost.byte1;
	hdr->ether_dhost.byte2 = tmp->ether_dhost.byte2;
	hdr->ether_dhost.byte3 = tmp->ether_dhost.byte3;
	hdr->ether_dhost.byte4 = tmp->ether_dhost.byte4;
	hdr->ether_dhost.byte5 = tmp->ether_dhost.byte5;
	hdr->ether_dhost.byte6 = tmp->ether_dhost.byte6;
	hdr->ether_type = ntohs(tmp->ether_type);
	return hdr;

}

arp_header * packet_parse_arphdr(const char * cp)
{	arp_header *hdr, *tmp;
	tmp = (arp_header *)cp;
	hdr = MALLOC(arp_header, 1);
	memset(hdr, '\0', sizeof(arp_header));
	hdr->hw_type = ntohs(tmp->hw_type);
	hdr->proto = ntohs(tmp->proto);
	hdr->hw_size = tmp->hw_size;
	hdr->proto_size = tmp->proto_size;
	hdr->opcode = ntohs(tmp->opcode);

	hdr->arp_shost.byte1 = tmp->arp_shost.byte1;
	hdr->arp_shost.byte2 = tmp->arp_shost.byte2;
	hdr->arp_shost.byte3 = tmp->arp_shost.byte3;
	hdr->arp_shost.byte4 = tmp->arp_shost.byte4;
	hdr->arp_shost.byte5 = tmp->arp_shost.byte5;
	hdr->arp_shost.byte6 = tmp->arp_shost.byte6;
	
	hdr->saddr.byte1 = tmp->saddr.byte1;  // Адрес источника
	hdr->saddr.byte2 = tmp->saddr.byte2;
	hdr->saddr.byte3 = tmp->saddr.byte3;
	hdr->saddr.byte4 = tmp->saddr.byte4;
	
	hdr->arp_dhost.byte1 = tmp->arp_dhost.byte1;
	hdr->arp_dhost.byte2 = tmp->arp_dhost.byte2;
	hdr->arp_dhost.byte3 = tmp->arp_dhost.byte3;
	hdr->arp_dhost.byte4 = tmp->arp_dhost.byte4;
	hdr->arp_dhost.byte5 = tmp->arp_dhost.byte5;
	hdr->arp_dhost.byte6 = tmp->arp_dhost.byte6;

	hdr->daddr.byte1 = tmp->daddr.byte1;  // Адрес источника
	hdr->daddr.byte2 = tmp->daddr.byte2;
	hdr->daddr.byte3 = tmp->daddr.byte3;
	hdr->daddr.byte4 = tmp->daddr.byte4;
	
	return hdr;
}

ip_header * packet_parse_iphdr(const char *cp)
{
	ip_header *hdr, *tmp;
	tmp = (ip_header *)cp;
	hdr = MALLOC(ip_header, 1);
	memset(hdr, '\0', sizeof(ip_header));
	//hdr->ver_ihl = tmp->ver_ihl;
	hdr->version = tmp->version;
	hdr->ihl = tmp->ihl;
	hdr->tos = tmp->tos;
	hdr->tlen = ntohs(tmp->tlen);
	hdr->id = ntohs(tmp->id);
	hdr->flags = ntohs(tmp->flags);
	hdr->ttl = tmp->ttl;
	//if (tmp->proto == IPPROTO_TCP)  hdr->proto = 'TCP';
	hdr->proto = tmp->proto;
	hdr->crc = ntohs(tmp->crc);
	hdr->saddr.byte1 = tmp->saddr.byte1;
	hdr->saddr.byte2 = tmp->saddr.byte2;
	hdr->saddr.byte3 = tmp->saddr.byte3;
	hdr->saddr.byte4 = tmp->saddr.byte4;
	hdr->daddr.byte1 = tmp->daddr.byte1;
	hdr->daddr.byte2 = tmp->daddr.byte2;
	hdr->daddr.byte3 = tmp->daddr.byte3;
	hdr->daddr.byte4 = tmp->daddr.byte4;
	return hdr;
}

ipv6_header * packet_parse_ipv6hdr(const char * cp)
{
	ipv6_header *hdr, *tmp;
	tmp = (ipv6_header *)cp;
	hdr = MALLOC(ipv6_header, 1);
	memset(hdr, '\0', sizeof(ipv6_header));
	hdr->ver_tcl_flow = ntohl(tmp->ver_tcl_flow);
	hdr->plen = tmp->plen;
	hdr->next = tmp->next;
	hdr->hlim = tmp->hlim;

	hdr->srcaddr.byte1 = ntohs(tmp->srcaddr.byte1);
	hdr->srcaddr.byte2 = ntohs(tmp->srcaddr.byte2);
	hdr->srcaddr.byte3 = ntohs(tmp->srcaddr.byte3);
	hdr->srcaddr.byte4 = ntohs(tmp->srcaddr.byte4);
	hdr->srcaddr.byte5 = ntohs(tmp->srcaddr.byte5);
	hdr->srcaddr.byte6 = ntohs(tmp->srcaddr.byte6);
	hdr->srcaddr.byte7 = ntohs(tmp->srcaddr.byte7);
	hdr->srcaddr.byte8 = ntohs(tmp->srcaddr.byte8);

	hdr->dstaddr.byte1 = ntohs(tmp->dstaddr.byte1);
	hdr->dstaddr.byte2 = ntohs(tmp->dstaddr.byte2);
	hdr->dstaddr.byte3 = ntohs(tmp->dstaddr.byte3);
	hdr->dstaddr.byte4 = ntohs(tmp->dstaddr.byte4);
	hdr->dstaddr.byte5 = ntohs(tmp->dstaddr.byte5);
	hdr->dstaddr.byte6 = ntohs(tmp->dstaddr.byte6);
	hdr->dstaddr.byte7 = ntohs(tmp->dstaddr.byte7);
	hdr->dstaddr.byte8 = ntohs(tmp->dstaddr.byte8);

	return hdr;
}

udp_header * packet_parse_updhdr(const char * cp)
{
	udp_header *hdr, *tmp;
	tmp = (udp_header *)cp;
	hdr = MALLOC(udp_header, 1);
	memset(hdr, '\0', sizeof(udp_header));
	hdr->uh_sport = ntohs(tmp->uh_sport);
	hdr->uh_dport = ntohs(tmp->uh_dport);
	hdr->crc = tmp->crc;
	hdr->len = tmp->len;
	return hdr;
}

tcp_header * packet_parse_tcphdr(const char * cp)
{
	tcp_header *hdr, *tmp;
	tmp = (tcp_header *)cp;
	hdr = MALLOC(tcp_header, 1);
	memset(hdr, '\0', sizeof(tcp_header));
	hdr->th_sport = ntohs(tmp->th_sport);
	hdr->th_dport = ntohs(tmp->th_dport);
	hdr->th_seq = ntohl(tmp->th_seq);   /* порядковый номер: 32 бита */
	hdr->th_ack = ntohl(tmp->th_ack);   /* номер подтверждения: 32 бита */
	hdr->th_x2 = tmp->th_x2;
	hdr->th_off = tmp->th_off;
	hdr->th_flags = tmp->th_flags;
	hdr->th_win = ntohs(tmp->th_win);
	hdr->th_sum = ntohs(tmp->th_sum);
	hdr->th_urp = ntohs(tmp->th_urp);
	return hdr;
}

dns_header * packet_parse_dnshdr(const char * cp)
{
	dns_header *hdr, *tmp;
	tmp = (dns_header *)cp;
	hdr = MALLOC(dns_header, 1);
	memset(hdr, 0, sizeof(dns_header));

	hdr->id = ntohs(tmp->id);
	hdr->flags = ntohs(tmp->flags);
	hdr->qdcount = ntohs(tmp->qdcount);
	hdr->ancount = ntohs(tmp->ancount);
	hdr->nscount = ntohs(tmp->nscount);
	hdr->arcount = ntohs(tmp->arcount);

	return hdr;
}
