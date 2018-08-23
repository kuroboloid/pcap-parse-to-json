#include "stdafx.h"
#include <iostream>
#include <string.h>
#include "pcap.h"
#include "packet.h"
#include <stdlib.h>
#include "http.h"
#include "util.h"
#include "prtcl_hdr.h"
#include "JsonBox.h"




packet_t* packet_new(void)
{
	packet_t *pkt;

	pkt = MALLOC(packet_t, 1);
	memset(pkt, 0, sizeof(packet_t));
	pkt->tcp_odata = NULL;
	pkt->tcp_data = pkt->tcp_odata;
	//pkt->next = NULL;

	return pkt;
}

void packet_preprocess(const pcap_pkthdr * header, const u_char * pkt_data, int pnum)
{
		const char *cp = (char*)pkt_data;
		packet_t *pkt = NULL; // новый пакет
		eth_header *ethh = NULL; 
		arp_header *arph = NULL;
		ip_header *iph = NULL;
		ipv6_header *ip6h = NULL;
		udp_header *udph = NULL;
		dns_header *dnsh = NULL;
		tcp_header *tcph = NULL;
		http_header *httph = NULL;
		
		pkt = MALLOC(packet_t, 1);
		memset(pkt, 0, sizeof(packet_t));
		pkt->tcp_odata = NULL;
		pkt->tcp_data = pkt->tcp_odata;

		/* Парсинг заголовка пакета */
		pkt->frame_sec = header->ts.tv_sec;        //время захвата
		pkt->frame_usec = header->ts.tv_usec;      //-н-
		pkt->frame_len = header->caplen;			 //длина 
		pkt->frame_number = pnum;

		/*  Ethernet */
		ethh = packet_parse_ethhdr(cp);
		pkt->eth = 1;
		pkt->eth_shost.byte1 = ethh->ether_shost.byte1;
		pkt->eth_shost.byte2 = ethh->ether_shost.byte2;
		pkt->eth_shost.byte3 = ethh->ether_shost.byte3;
		pkt->eth_shost.byte4 = ethh->ether_shost.byte4;
		pkt->eth_shost.byte5 = ethh->ether_shost.byte5;
		pkt->eth_shost.byte6 = ethh->ether_shost.byte6;
		pkt->eth_dhost.byte1 = ethh->ether_dhost.byte1;
		pkt->eth_dhost.byte2 = ethh->ether_dhost.byte2;
		pkt->eth_dhost.byte3 = ethh->ether_dhost.byte3;
		pkt->eth_dhost.byte4 = ethh->ether_dhost.byte4;
		pkt->eth_dhost.byte5 = ethh->ether_dhost.byte5;
		pkt->eth_dhost.byte6 = ethh->ether_dhost.byte6;
		pkt->eth_type = ethh->ether_type;

		cp = cp + 14;

		/*ARP*/
		if (ethh->ether_type == 0x0806) 
		{
			pkt->arp = 1;
			arph = packet_parse_arphdr(cp);
			pkt->arp_hw_type = arph->hw_type;
			pkt->arp_proto = arph->proto;
			pkt->arp_hw_size = arph->hw_size;
			pkt->arp_proto_size = arph->proto_size;
			pkt->arp_opcode = arph->opcode;

			pkt->arp_shost.byte1 = arph->arp_shost.byte1;
			pkt->arp_shost.byte2 = arph->arp_shost.byte2;
			pkt->arp_shost.byte3 = arph->arp_shost.byte3;
			pkt->arp_shost.byte4 = arph->arp_shost.byte4;
			pkt->arp_shost.byte5 = arph->arp_shost.byte5;
			pkt->arp_shost.byte6 = arph->arp_shost.byte6;

			pkt->arp_saddr.byte1 = arph->saddr.byte1;  // Адрес источника
			pkt->arp_saddr.byte2 = arph->saddr.byte2;
			pkt->arp_saddr.byte3 = arph->saddr.byte3;
			pkt->arp_saddr.byte4 = arph->saddr.byte4;

			pkt->arp_dhost.byte1 = arph->arp_dhost.byte1;
			pkt->arp_dhost.byte2 = arph->arp_dhost.byte2;
			pkt->arp_dhost.byte3 = arph->arp_dhost.byte3;
			pkt->arp_dhost.byte4 = arph->arp_dhost.byte4;
			pkt->arp_dhost.byte5 = arph->arp_dhost.byte5;
			pkt->arp_dhost.byte6 = arph->arp_dhost.byte6;

			pkt->arp_daddr.byte1 = arph->daddr.byte1;  // Адрес источника
			pkt->arp_daddr.byte2 = arph->daddr.byte2;
			pkt->arp_daddr.byte3 = arph->daddr.byte3;
			pkt->arp_daddr.byte4 = arph->daddr.byte4;
		}

		/*IPv6*/
		if (ethh->ether_type == 0x86dd) {
			if (ethh->ether_type == 0x86dd) pkt->ipv6 = 1; else  pkt->ipv6 = 0;
			ip6h = packet_parse_ipv6hdr(cp);
			pkt->ip6_version = ip6h->ver_tcl_flow >> 28;
			pkt->ipv6_tclass = (ip6h->ver_tcl_flow >> 20) & 0xff;
			pkt->ipv6_flow = ip6h->ver_tcl_flow & 0xfffff;
			pkt->ipv6_plen = ip6h->plen;
			pkt->ipv6_next = ip6h->next;
			pkt->ip_proto = pkt->ipv6_next;
			pkt->ipv6_hlim = ip6h->hlim;

			pkt->ipv6_srcaddr.byte1 = ip6h->srcaddr.byte1;
			pkt->ipv6_srcaddr.byte2 = ip6h->srcaddr.byte2;
			pkt->ipv6_srcaddr.byte3 = ip6h->srcaddr.byte3;
			pkt->ipv6_srcaddr.byte4 = ip6h->srcaddr.byte4;
			pkt->ipv6_srcaddr.byte5 = ip6h->srcaddr.byte5;
			pkt->ipv6_srcaddr.byte6 = ip6h->srcaddr.byte6;
			pkt->ipv6_srcaddr.byte7 = ip6h->srcaddr.byte7;
			pkt->ipv6_srcaddr.byte8 = ip6h->srcaddr.byte8;

			pkt->ipv6_dstaddr.byte1 = ip6h->dstaddr.byte1;
			pkt->ipv6_dstaddr.byte2 = ip6h->dstaddr.byte2;
			pkt->ipv6_dstaddr.byte3 = ip6h->dstaddr.byte3;
			pkt->ipv6_dstaddr.byte4 = ip6h->dstaddr.byte4;
			pkt->ipv6_dstaddr.byte5 = ip6h->dstaddr.byte5;
			pkt->ipv6_dstaddr.byte6 = ip6h->dstaddr.byte6;
			pkt->ipv6_dstaddr.byte7 = ip6h->dstaddr.byte7;
			pkt->ipv6_dstaddr.byte8 = ip6h->dstaddr.byte8;

			cp = cp + 40;
		}

		/*IPv4*/
		if ((ethh->ether_type == 0x0800)) {

			/*  IP заголовoк */
			pkt->ipv4 = 1;
			iph = packet_parse_iphdr(cp);
			pkt->ip_version = iph->version;
			pkt->ip_tos = iph->tos;
			pkt->ip_hdr_len = iph->ihl << 2;	/* байты */
			pkt->ip_len = iph->tlen;
			pkt->ip_id = iph->id;					// Идентификация
			pkt->ip_flags = iph->flags >> 13;			// Флаги (3 бита) 

			if (pkt->ip_flags & 0b1000) pkt->ip_ftree.rb = 1; else pkt->ip_ftree.rb = 0;
			if (pkt->ip_flags & 0b0100) pkt->ip_ftree.df = 1; else pkt->ip_ftree.df = 0;
			if (pkt->ip_flags & 0b0010) pkt->ip_ftree.mf = 1; else pkt->ip_ftree.mf = 0;

			pkt->ip_ttl = iph->ttl;					// Время жизни
			pkt->ip_proto = iph->proto;				// Протокол
			pkt->ip_crc = iph->crc;					// Контрольная сумма заголовка
			pkt->ip_srcaddr.byte1 = iph->saddr.byte1; // 0x: исходный IP-адрес 
			pkt->ip_srcaddr.byte2 = iph->saddr.byte2;
			pkt->ip_srcaddr.byte3 = iph->saddr.byte3;
			pkt->ip_srcaddr.byte4 = iph->saddr.byte4;
			pkt->ip_dstaddr.byte1 = iph->daddr.byte1; // 0x: IP-адрес получателя
			pkt->ip_dstaddr.byte2 = iph->daddr.byte2;
			pkt->ip_dstaddr.byte3 = iph->daddr.byte3;
			pkt->ip_dstaddr.byte4 = iph->daddr.byte4;

			cp = cp + 20;

		}

			if (IP_TYPE_ICMP == pkt->ip_proto) pkt->icmp = 1; else pkt->icmp = 0;
			if (IP_TYPE_IGMP == pkt->ip_proto) pkt->igmp = 1; else pkt->igmp = 0;

		/*TCP*/
		if (IP_TYPE_TCP == pkt->ip_proto) {
				pkt->tcp = 1;
				tcph = packet_parse_tcphdr(cp);
				pkt->tcp_srcport = tcph->th_sport;
				pkt->tcp_dstport = tcph->th_dport;
				pkt->tcp_seq = tcph->th_seq;
				pkt->tcp_ack = tcph->th_ack;

				pkt->tcp_flags = tcph->th_flags;

				if (tcph->th_x2 & 0b1110) pkt->tcp_ftree.res = 1; else pkt->tcp_ftree.res = 0;
				if (tcph->th_x2 & 0b0001) pkt->tcp_ftree.ns = 1; else pkt->tcp_ftree.ns = 0;

				if (pkt->tcp_flags & 0b10000000) pkt->tcp_ftree.cwr = 1; else pkt->tcp_ftree.cwr = 0;
				if (pkt->tcp_flags & 0b01000000) pkt->tcp_ftree.ecn = 1; else pkt->tcp_ftree.ecn = 0;
				if (pkt->tcp_flags & 0b00100000) pkt->tcp_ftree.urg = 1; else pkt->tcp_ftree.urg = 0;
				if (pkt->tcp_flags & 0b00010000) pkt->tcp_ftree.ack = 1; else pkt->tcp_ftree.ack = 0;
				if (pkt->tcp_flags & 0b00001000) pkt->tcp_ftree.push = 1; else pkt->tcp_ftree.push = 0;
				if (pkt->tcp_flags & 0b00000100) pkt->tcp_ftree.reset = 1; else pkt->tcp_ftree.reset = 0;
				if (pkt->tcp_flags & 0b00000010) pkt->tcp_ftree.syn = 1; else pkt->tcp_ftree.syn = 0;
				if (pkt->tcp_flags & 0b00000001) pkt->tcp_ftree.fin = 1; else pkt->tcp_ftree.fin = 0;


				pkt->tcp_win = tcph->th_win;
				pkt->tcp_hdr_len = tcph->th_off << 2;		/* байты */
				pkt->tcp_len = pkt->ip_len - 40;
				pkt->tcp_sum = tcph->th_sum;
				pkt->tcp_urp = tcph->th_urp;

				pkt->tcp_odata = NULL;
				pkt->tcp_data = pkt->tcp_odata;

				if ((pkt->tcp_srcport == 25 ) || (pkt->tcp_srcport == 583) ||
					(pkt->tcp_dstport == 25 ) || (pkt->tcp_dstport == 583))
					pkt->smtp = 1; 
				else pkt->smtp = 0; //smtp

				if ((pkt->tcp_srcport == 80) || (pkt->tcp_srcport == 8080) || (pkt->tcp_srcport == 8000) ||
					(pkt->tcp_dstport == 80) || (pkt->tcp_dstport == 8080) || (pkt->tcp_dstport == 8000))
					pkt->http = 0; 
				else pkt->http = 0;   //http
				

				/* SMTP*/

				if (pkt->smtp == 1)
				{
					cp = cp + pkt->tcp_hdr_len;
					pkt->tcp_odata = MALLOC(char, pkt->tcp_len + 1);
					pkt->tcp_data = pkt->tcp_odata;
					memset(pkt->tcp_odata, 0, pkt->tcp_len + 1);
					memcpy(pkt->tcp_odata, cp, pkt->tcp_len);
				}

				if (pkt->http == 1) {										//HTTP*/
						httph = (http_header*)(u_char*)tcph + pkt->tcp_len;
						u_char *head_end = NULL;
						int hdl = 0;
						head_end = (u_char*)IsRequest(cp, pkt->tcp_len);
						if (head_end != NULL) {             //первый пакет запроса
							hdl = head_end - (u_char*)cp + 1;
							pkt->http = HTTP_REQ;
							pkt->tcp_len = hdl;
						}
						head_end = (u_char*)IsResponse(cp, pkt->tcp_len);
						if (head_end != NULL) {
							hdl = head_end - (u_char*)cp + 1;
							pkt->http = HTTP_RSP;
							pkt->tcp_len = hdl;
						}

						pkt->tcp_odata = MALLOC(char, pkt->tcp_len + 1);
						pkt->tcp_data = pkt->tcp_odata;
						memset(pkt->tcp_odata, 0, pkt->tcp_len + 1);
						memcpy(pkt->tcp_odata, cp, pkt->tcp_len);
				}

			};

		/*UDP*/
		if (IP_TYPE_UDP == pkt->ip_proto) {
				pkt->udp = 1;
				udph = packet_parse_updhdr(cp);
				pkt->upd_srcport = udph->uh_sport;  // Исходный порт
				pkt->upd_dstport = udph->uh_dport;  // Порт назначения
				pkt->upd_len = udph->len;  // Длина 
				pkt->upd_crc = udph->crc;  // Контрольная сумма

				cp = cp + 8;

				 /*NTP*/
				if ((pkt->upd_srcport == 123) || (pkt->upd_dstport == 123)) pkt->ntp = 1; pkt->ntp = 0;

				/*DNS*/
				if ((pkt->upd_srcport == 53) || (pkt->upd_dstport == 53))
				{
					pkt->dns = 1;
					dnsh = packet_parse_dnshdr(cp);
					pkt->dns_id = dnsh->id;	//Идентификация
					pkt->dns_flags = dnsh->flags;

					if (dnsh->flags & 0x8000) pkt->dns_ftree.response = 1; else pkt->dns_ftree.response = 0;
					if (dnsh->flags & 0x7800) pkt->dns_ftree.opcode = 1; else pkt->dns_ftree.opcode = 0;
					if (dnsh->flags & 0x200) pkt->dns_ftree.truncated = 1; else pkt->dns_ftree.truncated = 0;
					if (dnsh->flags & 0x100) pkt->dns_ftree.recdesired = 1; else pkt->dns_ftree.recdesired = 0;
					if (dnsh->flags & 0x40) pkt->dns_ftree.z = 1; else pkt->dns_ftree.z = 0;
					if (dnsh->flags & 0x20) pkt->dns_ftree.ckdsbl = 1; else pkt->dns_ftree.ckdsbl = 0;

					pkt->dns_qdcount = dnsh->qdcount;
					pkt->dns_ancount = dnsh->ancount;
					pkt->dns_nscount = dnsh->nscount;
					pkt->dns_arcount = dnsh->arcount;
				}
				else pkt->dns = 0;
			}
		
		//print_packet(pkt);  /*печать пакетов*/
		packet_to_json(pkt);
		free(ethh);
		free(arph);
		free(iph);
		free(tcph);
		free(udph);
		free(dnsh);
		free(pkt);

}

void print_packet(packet_t * pkt)
{
	time_t local_tv_sec;
	struct tm ltime;
	char timestr[16];
	char timestr2[16];
	char eth1[18], eth2[18];

	/*преобразовать метку времени в читаемый формат*/
	local_tv_sec = pkt->frame_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);
	strftime(timestr2, sizeof timestr2, "%Y-%B-%d", &ltime);

	std::cout << "_index: packet-" << timestr2 << "\n";

	std::cout << "Number: " << pkt->frame_number << "\n";

	//printf("Time (sec): %lld\n",pkt->cap_sec);
	std::cout << "Time (sec): " << timestr << "\n";

	//printf("Time(usec): %lld\n", pkt->cap_usec);
	std::cout << "Time (usec): " << pkt->frame_usec << "\n";

	//printf("Length: %d\n",	pkt->raw_len);
	std::cout << "Length: " << pkt->frame_len << "\n";

	sprintf_s(eth1, "%x:%x:%x:%x:%x:%x",
		pkt->eth_dhost.byte1,
		pkt->eth_dhost.byte2,
		pkt->eth_dhost.byte3,
		pkt->eth_dhost.byte4,
		pkt->eth_dhost.byte5,
		pkt->eth_dhost.byte6);

	sprintf_s(eth2, "%x:%x:%x:%x:%x:%x",
		pkt->eth_shost.byte1,
		pkt->eth_shost.byte2,
		pkt->eth_shost.byte3,
		pkt->eth_shost.byte4,
		pkt->eth_shost.byte5,
		pkt->eth_shost.byte6);

	std::cout << "Ethernet: " << eth1 << " -> " << eth2 << "\n";
	
	printf("eth.type: %x\n", pkt->eth_type);

	printf("IP: %d.%d.%d.%d -> %d.%d.%d.%d\n",
		pkt->ip_srcaddr.byte1,
		pkt->ip_srcaddr.byte2,
		pkt->ip_srcaddr.byte3,
		pkt->ip_srcaddr.byte4,
		pkt->ip_dstaddr.byte1,
		pkt->ip_dstaddr.byte2,
		pkt->ip_dstaddr.byte3,
		pkt->ip_dstaddr.byte4);

	printf("IP-header lenght: %d\n", pkt->ip_hdr_len);

	printf("IP protocol: %d\n", pkt->ip_proto);

	printf("IP lenght: %d\n", pkt->ip_len);

	printf("TCP: %d -> %d\n",
		pkt->tcp_srcport,
		pkt->tcp_dstport);

	printf("TCP sequence number: %d\n", pkt->tcp_seq);

	printf("TCP acknowledge number: %d\n", pkt->tcp_ack);

	printf("TCP flags: %d\n", pkt->tcp_ack);

	printf("TCP window size: %d\n", pkt->tcp_win);

	printf("TCP header length: %d\n", pkt->tcp_hdr_len);

	printf("TCP payload length: %d\n", pkt->tcp_len);

	printf("Orignal TCP payload: %*s\n", pkt->tcp_odata);

	printf("Real useful data: %*s\n", pkt->tcp_data);

	printf("HTTP: %d\n", pkt->http);

	printf("\n\n");
}

void to_json()
{
   JsonBox::Value root;
   int i=4;

	root["_index"] = JsonBox::Value("packet-2017");
	root["_type"] = JsonBox::Value("pcap_file");

		root["_source"]["layers"]["frame"]["frame.number"] = JsonBox::Value("");
		root["_source"]["layers"]["frame"]["frame.time(sec)"] = JsonBox::Value("");
		root["_source"]["layers"]["frame"]["frame.time(usec)"] = JsonBox::Value("");
		root["_source"]["layers"]["frame"]["frame.len"] = JsonBox::Value("");
		i--;
		root["_source"]["layers"]["eth"]["eth.dhost"] = JsonBox::Value("");
		root["_source"]["layers"]["eth"]["eth.shost"] = JsonBox::Value("");
		root["_source"]["layers"]["eth"]["eth.type"] = JsonBox::Value("");
		i--;
		root["_source"]["layers"]["ip"]["ip.ver_ihl"] = JsonBox::Value("");
		root["_source"]["layers"]["ip"]["ip.tos"] = JsonBox::Value("");
		root["_source"]["layers"]["ip"]["ip.len"] = JsonBox::Value("");
		root["_source"]["layers"]["ip"]["ip.id"] = JsonBox::Value("");
		root["_source"]["layers"]["ip"]["ip.flags"] = JsonBox::Value("");
		root["_source"]["layers"]["ip"]["ip.ttl"] = JsonBox::Value("");
		root["_source"]["layers"]["ip"]["ip.proto"] = JsonBox::Value("");
		root["_source"]["layers"]["ip"]["ip.checksum"] = JsonBox::Value("");
		root["_source"]["layers"]["ip"]["ip.src"] = JsonBox::Value("");
		root["_source"]["layers"]["ip"]["ip.dst"] = JsonBox::Value("");
		i--;
		root["_source"]["layers"]["upd"]["upd.srcport"] = JsonBox::Value("");
		root["_source"]["layers"]["upd"]["upd.dstport"] = JsonBox::Value("");
		root["_source"]["layers"]["upd"]["upd.lenght"] = JsonBox::Value("");
		root["_source"]["layers"]["upd"]["upd.checksum"] = JsonBox::Value("");
		i--;
		root["_source"]["layers"]["tcp"]["tcp.srcport"] = JsonBox::Value("");
		root["_source"]["layers"]["tcp"]["tcp.dstport"] = JsonBox::Value("");
		root["_source"]["layers"]["tcp"]["tcp.len"] = JsonBox::Value("");
		root["_source"]["layers"]["tcp"]["tcp.seq"] = JsonBox::Value("");
		root["_source"]["layers"]["tcp"]["tcp.ack"] = JsonBox::Value("");
		root["_source"]["layers"]["tcp"]["tcp.hdr_len"] = JsonBox::Value("");
		root["_source"]["layers"]["tcp"]["tcp.flags"] = JsonBox::Value("");
		root["_source"]["layers"]["tcp"]["tcp.window_size"] = JsonBox::Value("");
		root["_source"]["layers"]["tcp"]["tcp.checksum"] = JsonBox::Value("");
		root["_source"]["layers"]["tcp"]["tcp.urgent_pointer"] = JsonBox::Value("");
	
		std::cout << root;
}

void load_from_json()
{
	std::string fname = ""; //имя дампа

	printf("Enter the number of packet:");
	std::cin >> fname;

	if (fname == "")
	{
		fprintf(stderr, "\n Error!  \n");
		return;
	}
	fname = "json//packet" + fname + ".json";

	JsonBox::Value v2;
	v2.loadFromFile(fname);
	std::cout << v2 << std::endl;
}

void packet_to_json(packet_t *pkt)
{
	JsonBox::Value jpkt;
	//JsonBox::Object  jpkt;
	time_t local_tv_sec;
	struct tm ltime;
	char usec[50], timestr[50], timestr2[30];

	std::string index = "packet-";
	std::string protocols = "";
	char eths[20], ethd[20], ips[18], ipd[18], arpms[20], arpmd[20], arpis[18], arpid[18];
	char framelen[5], ethtype[11], ipid[11], ipflags[11], ipcrc[11],
		ipv6tc[11], ipv6fw[11],
		updcrc[11], tcpflags[11], tcpcrc[11], tcpseq[11], tcpack[11],
		dnsid[11], dnsflags[11], arpproto[11], ipv6adrr[6];
	std::string ipv6s = "", ipv6d = "";
	
	std::string jsonfile = "json//packet" + std::to_string(pkt->frame_number) + ".json";
		
	/*преобразовать метку времени в читаемый формат*/
	local_tv_sec = pkt->frame_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr2, sizeof  timestr2, "%Y-%B-%d", &ltime);
	
	//strcat_s(index, timestr2);
	index = index+timestr2;

	jpkt["_index"] = JsonBox::Value(index);
	jpkt["_type"] = JsonBox::Value("pcap_file");
	jpkt["_source"]["layers"]["frame"]["frame.number"] = JsonBox::Value(pkt->frame_number);

	strftime(timestr, sizeof timestr, "%b %d, %Y %H:%M:%S", &ltime);
	sprintf_s(timestr, "%s.%d", timestr, pkt->frame_usec);

	std::string sec = std::to_string(pkt->frame_sec) + "." + std::to_string(pkt->frame_usec);
    sprintf_s(usec, "%ld.%ld", local_tv_sec, pkt->frame_usec);

	jpkt["_source"]["layers"]["frame"]["frame.time(sec)"] = JsonBox::Value(timestr);
	jpkt["_source"]["layers"]["frame"]["frame.time_epoch"] = JsonBox::Value (sec);
	sprintf_s(framelen, "%d", pkt->frame_len);
	jpkt["_source"]["layers"]["frame"]["frame.len"] = JsonBox::Value(framelen);

	if (pkt->eth == 1) protocols = protocols + "eth:ethertype";

	if (pkt->arp == 1) {
		protocols = protocols + ":arp";
		jpkt["_source"]["layers"]["frame"]["frame.coloring_rule"] = JsonBox::Value("ARP");
	}

	if (pkt->icmp == 1) {
		protocols = protocols + ":icmp";
		jpkt["_source"]["layers"]["frame"]["frame.coloring_rule"] = JsonBox::Value("ICMP");
	}

	if (pkt->igmp == 1) {
		protocols = protocols + ":igmp";
		jpkt["_source"]["layers"]["frame"]["frame.coloring_rule"] = JsonBox::Value("Routing");
	}

	if (pkt->ipv4 == 1) protocols = protocols + ":ipv4";
	if (pkt->ipv6 == 1) protocols = protocols + ":ipv6";

	if (pkt->tcp == 1) {
		protocols = protocols + ":tcp"; 
		jpkt["_source"]["layers"]["frame"]["frame.coloring_rule"] = JsonBox::Value("TCP");
	}

	if (pkt->smtp == 1) protocols = protocols + ":smtp";
	if (pkt->http == 1) protocols = protocols + ":http";
	if (pkt->udp == 1) {
		protocols = protocols + ":udp";
		jpkt["_source"]["layers"]["frame"]["frame.coloring_rules"] = JsonBox::Value("UDP");
	}
	if (pkt->dns == 1) protocols = protocols + ":dns";
	if (pkt->ntp == 1) protocols = protocols + ":ntp";

	jpkt["_source"]["layers"]["frame"]["frame.protocols"] = JsonBox::Value(protocols);

	sprintf_s(ethd, "%02x:%02x:%02x:%02x:%02x:%02x",
		pkt->eth_dhost.byte1,
		pkt->eth_dhost.byte2,
		pkt->eth_dhost.byte3,
		pkt->eth_dhost.byte4,
		pkt->eth_dhost.byte5,
		pkt->eth_dhost.byte6);

	sprintf_s(eths, "%02x:%02x:%02x:%02x:%02x:%02x",
		pkt->eth_shost.byte1,
		pkt->eth_shost.byte2,
		pkt->eth_shost.byte3,
		pkt->eth_shost.byte4,
		pkt->eth_shost.byte5,
		pkt->eth_shost.byte6);

	jpkt["_source"]["layers"]["eth"]["eth.dhost"] = JsonBox::Value(ethd);
	jpkt["_source"]["layers"]["eth"]["eth.shost"] = JsonBox::Value(eths);
	sprintf_s(ethtype, "0x%08x", pkt->eth_type);
	jpkt["_source"]["layers"]["eth"]["eth.type"] = JsonBox::Value(ethtype);

	if (pkt->arp==1)
	{		
		jpkt["_source"]["layers"]["arp"]["arp.hw.type"] = JsonBox::Value(pkt->arp_hw_type);
		sprintf_s(arpproto, "0x%08x", pkt->arp_proto);
		jpkt["_source"]["layers"]["arp"]["arp.proto.type"] = JsonBox::Value(arpproto);
		jpkt["_source"]["layers"]["arp"]["arp.hw.size"] = JsonBox::Value(pkt->arp_hw_size);
		jpkt["_source"]["layers"]["arp"]["arp.proto.size"] = JsonBox::Value(pkt->arp_proto_size);
		jpkt["_source"]["layers"]["arp"]["arp.opcode"] = JsonBox::Value(pkt->arp_proto_size);

		sprintf_s(arpms, "%02x:%02x:%02x:%02x:%02x:%02x",
			pkt->arp_shost.byte1,
			pkt->arp_shost.byte2,
			pkt->arp_shost.byte3,
			pkt->arp_shost.byte4,
			pkt->arp_shost.byte5,
			pkt->arp_shost.byte6);
		jpkt["_source"]["layers"]["arp"]["arp.src.hw_mac"] = JsonBox::Value(arpms);
		
		sprintf_s(arpis, "%03d.%03d.%03d.%03d",
			pkt->arp_saddr.byte1,
			pkt->arp_saddr.byte2,
			pkt->arp_saddr.byte3,
			pkt->arp_saddr.byte4);

		jpkt["_source"]["layers"]["arp"]["arp.src.proto"] = JsonBox::Value(arpis);

		sprintf_s(arpmd, "%02x:%02x:%02x:%02x:%02x:%02x",
			pkt->arp_dhost.byte1,
			pkt->arp_dhost.byte2,
			pkt->arp_dhost.byte3,
			pkt->arp_dhost.byte4,
			pkt->arp_dhost.byte5,
			pkt->arp_dhost.byte6);
		jpkt["_source"]["layers"]["arp"]["arp.dst.hw_mac"] = JsonBox::Value(arpmd);

		sprintf_s(arpid, "%03d.%03d.%03d.%03d",
			pkt->arp_daddr.byte1,
			pkt->arp_daddr.byte2,
			pkt->arp_daddr.byte3,
			pkt->arp_daddr.byte4);
		jpkt["_source"]["layers"]["arp"]["arp.dst.proto"] = JsonBox::Value(arpid);
	}
	
	if (pkt->ipv4 == 1)
	{
		jpkt["_source"]["layers"]["ip"]["ip.version"] = JsonBox::Value(pkt->ip_version);
		jpkt["_source"]["layers"]["ip"]["ip.hdr_len"] = JsonBox::Value(pkt->ip_hdr_len);
		jpkt["_source"]["layers"]["ip"]["ip.tos"] = JsonBox::Value(pkt->ip_tos);
		jpkt["_source"]["layers"]["ip"]["ip.len"] = JsonBox::Value(pkt->ip_len);
		sprintf_s(ipid, "0x%08x", pkt->ip_id);
		jpkt["_source"]["layers"]["ip"]["ip.id"] = JsonBox::Value(ipid);
		//sprintf_s(ipflags, "0x%08x", pkt->ip_flags);
		sprintf_s(ipflags, "0x%08x", pkt->ip_flags);
		jpkt["_source"]["layers"]["ip"]["ip.flags"] = JsonBox::Value(ipflags);
		jpkt["_source"]["layers"]["ip"]["ip.flags_tree"]["ip.flags.rb"] = JsonBox::Value(pkt->ip_ftree.rb);
		jpkt["_source"]["layers"]["ip"]["ip.flags_tree"]["ip.flags.df"] = JsonBox::Value(pkt->ip_ftree.df);
		jpkt["_source"]["layers"]["ip"]["ip.flags_tree"]["ip.flags.mf"] = JsonBox::Value(pkt->ip_ftree.mf);
		jpkt["_source"]["layers"]["ip"]["ip.ttl"] = JsonBox::Value(pkt->ip_ttl);
		jpkt["_source"]["layers"]["ip"]["ip.proto"] = JsonBox::Value(pkt->ip_proto);
		sprintf_s(ipcrc, "0x%08x", pkt->ip_crc);
		jpkt["_source"]["layers"]["ip"]["ip.checksum"] = JsonBox::Value(ipcrc);

		sprintf_s(ips, "%03d.%03d.%03d.%03d",
			pkt->ip_srcaddr.byte1,
			pkt->ip_srcaddr.byte2,
			pkt->ip_srcaddr.byte3,
			pkt->ip_srcaddr.byte4);

		sprintf_s(ipd, "%03d.%03d.%03d.%03d",
			pkt->ip_dstaddr.byte1,
			pkt->ip_dstaddr.byte2,
			pkt->ip_dstaddr.byte3,
			pkt->ip_dstaddr.byte4);

		jpkt["_source"]["layers"]["ip"]["ip.src"] = JsonBox::Value(ips);
		jpkt["_source"]["layers"]["ip"]["ip.dst"] = JsonBox::Value(ipd);
	}

	if (pkt->ipv6 == 1) {

		sprintf_s(ipv6adrr, "%x", pkt->ipv6_srcaddr.byte1); ipv6s = ipv6s + ipv6adrr; 
		sprintf_s(ipv6adrr, "%x:", pkt->ipv6_srcaddr.byte2); ipv6s = ipv6s + ipv6adrr;
		sprintf_s(ipv6adrr, "%x:", pkt->ipv6_srcaddr.byte3); ipv6s = ipv6s + ipv6adrr;
		sprintf_s(ipv6adrr, "%x:", pkt->ipv6_srcaddr.byte4); ipv6s = ipv6s + ipv6adrr;
		sprintf_s(ipv6adrr, "%x:", pkt->ipv6_srcaddr.byte5); ipv6s = ipv6s + ipv6adrr;
		sprintf_s(ipv6adrr, "%x:", pkt->ipv6_srcaddr.byte6); ipv6s = ipv6s + ipv6adrr;
		sprintf_s(ipv6adrr, "%x:", pkt->ipv6_srcaddr.byte7); ipv6s = ipv6s + ipv6adrr;
		sprintf_s(ipv6adrr, "%x", pkt->ipv6_srcaddr.byte8);  ipv6s = ipv6s + ipv6adrr;

		sprintf_s(ipv6adrr, "%x", pkt->ipv6_dstaddr.byte1);  ipv6d = ipv6d + ipv6adrr;
		sprintf_s(ipv6adrr, "%x:", pkt->ipv6_dstaddr.byte2); ipv6d = ipv6d + ipv6adrr;
		sprintf_s(ipv6adrr, "%x:", pkt->ipv6_dstaddr.byte3); ipv6d = ipv6d + ipv6adrr;
		sprintf_s(ipv6adrr, "%x:", pkt->ipv6_dstaddr.byte4); ipv6d = ipv6d + ipv6adrr;
		sprintf_s(ipv6adrr, "%x:", pkt->ipv6_dstaddr.byte5); ipv6d = ipv6d + ipv6adrr;
		sprintf_s(ipv6adrr, "%x:", pkt->ipv6_dstaddr.byte6); ipv6d = ipv6d + ipv6adrr;
		sprintf_s(ipv6adrr, "%x:", pkt->ipv6_dstaddr.byte7); ipv6d = ipv6d + ipv6adrr;
		sprintf_s(ipv6adrr, "%x", pkt->ipv6_dstaddr.byte8);  ipv6d = ipv6d + ipv6adrr;
					
		jpkt["_source"]["layers"]["ipv6"]["ipv6.version"] = JsonBox::Value(pkt->ip6_version);
		sprintf_s(ipv6tc, "0x%08x", pkt->ipv6_tclass);
		jpkt["_source"]["layers"]["ipv6"]["ipv6.tclass"] = JsonBox::Value(ipv6tc);
		sprintf_s(ipv6fw, "0x%08x", pkt->ipv6_flow);
		jpkt["_source"]["layers"]["ipv6"]["ipv6.flow"] = JsonBox::Value(ipv6fw);
		jpkt["_source"]["layers"]["ipv6"]["ipv6.plen"] = JsonBox::Value(pkt->ipv6_plen);
		jpkt["_source"]["layers"]["ipv6"]["ipv6.nеxt"] = JsonBox::Value(pkt->ipv6_next);
		jpkt["_source"]["layers"]["ipv6"]["ipv6.hlim"] = JsonBox::Value(pkt->ipv6_hlim);
		jpkt["_source"]["layers"]["ipv6"]["ipv6.src_addr"] = JsonBox::Value(ipv6s);
		jpkt["_source"]["layers"]["ipv6"]["ipv6.dst_addr"] = JsonBox::Value(ipv6d);
	}
		
	if (pkt->udp == 1) {
			jpkt["_source"]["layers"]["upd"]["upd.srcport"] = JsonBox::Value(pkt->upd_srcport);
			jpkt["_source"]["layers"]["upd"]["upd.dstport"] = JsonBox::Value(pkt->upd_dstport);
			jpkt["_source"]["layers"]["upd"]["upd.lenght"] = JsonBox::Value(pkt->upd_len);
			sprintf_s(updcrc, "0x%08x", pkt->upd_crc);
			jpkt["_source"]["layers"]["upd"]["upd.checksum"] = JsonBox::Value(updcrc);

			if (pkt->dns == 1)
			{
				sprintf_s(dnsid, "0x%08x", pkt->dns_id);
				jpkt["_source"]["layers"]["dns"]["dns.id"] = JsonBox::Value(dnsid);
				sprintf_s(dnsflags, "0x%08x", pkt->dns_flags);
				jpkt["_source"]["layers"]["dns"]["dns.flags"] = JsonBox::Value(dnsflags);

				jpkt["_source"]["layers"]["dns"]["dns.flags_three"]["dns.flags.response"] = JsonBox::Value(pkt->dns_ftree.response);
				jpkt["_source"]["layers"]["dns"]["dns.flags_three"]["dns.flags.opcode"] = JsonBox::Value(pkt->dns_ftree.opcode);
				jpkt["_source"]["layers"]["dns"]["dns.flags_three"]["dns.flags.truncated"] = JsonBox::Value(pkt->dns_ftree.truncated);
				jpkt["_source"]["layers"]["dns"]["dns.flags_three"]["dns.flags.recdesired"] = JsonBox::Value(pkt->dns_ftree.recdesired);
				jpkt["_source"]["layers"]["dns"]["dns.flags_three"]["dns.flags.z"] = JsonBox::Value(pkt->dns_ftree.z);
				jpkt["_source"]["layers"]["dns"]["dns.flags_three"]["dns.flags.checkdisable"] = JsonBox::Value(pkt->dns_ftree.ckdsbl);

				jpkt["_source"]["layers"]["dns"]["dns.count.queries"] = JsonBox::Value(pkt->dns_qdcount);
				jpkt["_source"]["layers"]["dns"]["dns.count.answers"] = JsonBox::Value(pkt->dns_ancount);
				jpkt["_source"]["layers"]["dns"]["dns.count.auth_rr"] = JsonBox::Value(pkt->dns_nscount);
				jpkt["_source"]["layers"]["dns"]["dns.count.add_rr"] = JsonBox::Value(pkt->dns_arcount);
			}

		}

	if (pkt->tcp ==1) {
			jpkt["_source"]["layers"]["tcp"]["tcp.srcport"] = JsonBox::Value(pkt->tcp_srcport);
			jpkt["_source"]["layers"]["tcp"]["tcp.dstport"] = JsonBox::Value(pkt->tcp_dstport);
			jpkt["_source"]["layers"]["tcp"]["tcp.len"] = JsonBox::Value(pkt->tcp_len);
			sprintf_s(tcpseq, "%08x", pkt->tcp_seq);
			jpkt["_source"]["layers"]["tcp"]["tcp.seq"] = JsonBox::Value(tcpseq);
			sprintf_s(tcpack, "%08x", pkt->tcp_ack);
			jpkt["_source"]["layers"]["tcp"]["tcp.ack"] = JsonBox::Value(tcpack);
			jpkt["_source"]["layers"]["tcp"]["tcp.hdr_len"] = JsonBox::Value(pkt->tcp_hdr_len);
			sprintf_s(tcpflags, "0x%08x", pkt->tcp_flags);
			jpkt["_source"]["layers"]["tcp"]["tcp.flags"] = JsonBox::Value(tcpflags);

			jpkt["_source"]["layers"]["tcp"]["tcp.flags_three"]["tcp.flags.res"] = JsonBox::Value(pkt->tcp_ftree.res);
			jpkt["_source"]["layers"]["tcp"]["tcp.flags_three"]["tcp.flags.ns"] = JsonBox::Value(pkt->tcp_ftree.ns);
			jpkt["_source"]["layers"]["tcp"]["tcp.flags_three"]["tcp.flags.cwr"] = JsonBox::Value(pkt->tcp_ftree.cwr);
			jpkt["_source"]["layers"]["tcp"]["tcp.flags_three"]["tcp.flags.ecn"] = JsonBox::Value(pkt->tcp_ftree.ecn);
			jpkt["_source"]["layers"]["tcp"]["tcp.flags_three"]["tcp.flags.urg"] = JsonBox::Value(pkt->tcp_ftree.urg);
			jpkt["_source"]["layers"]["tcp"]["tcp.flags_three"]["tcp.flags.ack"] = JsonBox::Value(pkt->tcp_ftree.ack);
			jpkt["_source"]["layers"]["tcp"]["tcp.flags_three"]["tcp.flags.push"] = JsonBox::Value(pkt->tcp_ftree.push);
			jpkt["_source"]["layers"]["tcp"]["tcp.flags_three"]["tcp.flags.reset"] = JsonBox::Value(pkt->tcp_ftree.reset);
			jpkt["_source"]["layers"]["tcp"]["tcp.flags_three"]["tcp.flags.syn"] = JsonBox::Value(pkt->tcp_ftree.syn);
			jpkt["_source"]["layers"]["tcp"]["tcp.flags_three"]["tcp.flags.fin"] = JsonBox::Value(pkt->tcp_ftree.fin);

			jpkt["_source"]["layers"]["tcp"]["tcp.window_size"] = JsonBox::Value(pkt->tcp_win);
			sprintf_s(tcpcrc, "0x%08x", pkt->tcp_sum);
			jpkt["_source"]["layers"]["tcp"]["tcp.checksum"] = JsonBox::Value(tcpcrc);
			jpkt["_source"]["layers"]["tcp"]["tcp.urgent_pointer"] = JsonBox::Value(pkt->tcp_urp);

			if (pkt->smtp == 1)	jpkt["_source"]["layers"]["smtp.response"] = JsonBox::Value(pkt->tcp_odata);
			if (pkt->http == 1)	jpkt["_source"]["layers"]["http"] = JsonBox::Value(pkt->tcp_odata);

		}

	
	//std::cout << jpkt << "\n";
	//JsonBox::Value v(jpkt);
	//v.writeToFile(jsonfile);
	jpkt.writeToFile(jsonfile);
	
}

