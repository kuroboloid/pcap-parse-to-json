#pragma once


#include "pcap.h"
#include "prtcl_hdr.h"
#include <string.h>


typedef struct _packet_t
	{
		int frame_number;             // ����� ������
	    time_t frame_sec;         // ����� ������� sec 
		time_t frame_usec;        // ����� ������� usec 
		u_int32_t	frame_len;

		u_int8_t eth;
		mac_address  eth_dhost;		// ���� ���������
		mac_address  eth_shost;		// ���� ����������
		u_int16_t eth_type;			// ���

		u_int8_t arp;
		u_int16_t arp_hw_type;
		u_int16_t arp_proto;
		u_int8_t arp_hw_size;
		u_int8_t arp_proto_size;
		u_int16_t arp_opcode;
		mac_address arp_shost;
		ip_address arp_saddr;  // ����� ���������
		mac_address  arp_dhost;
		ip_address arp_daddr;  // ����� ����������	

		u_int8_t ipv6;
		u_int8_t ip6_version;
		u_int8_t ipv6_tclass;
		u_int16_t ipv6_flow;
		u_int16_t ipv6_plen;
		u_int8_t ipv6_next;
		u_int8_t ipv6_hlim;
		ipv6_address 	ipv6_srcaddr;		// 0x: �������� IP-����� 
		ipv6_address 	ipv6_dstaddr;		// 0x: IP-����� ����������
		
		u_int8_t ipv4;
		u_int8_t ip_version;
		u_int8_t 	ip_hdr_len;		// �����: ����� IP-��������� 
		u_char ip_tos;  // ��� ������������
		u_int16_t 	ip_len;		// ����: ����� ����� IP
		u_short ip_id;  // �������������
		u_short ip_flags;  // ����� (3 ����) + �������� ��������� (13 ���)
		ip_flags_tree ip_ftree;
		u_char ip_ttl;  // ����� �����
		u_char ip_proto;  // ��������
		u_short ip_crc;  // ����������� ����� ���������
		ip_address 	ip_srcaddr;		// 0x: �������� IP-����� 
		ip_address 	ip_dstaddr;		// 0x: IP-����� ����������

		u_int8_t icmp;
		u_int8_t igmp;
		u_int8_t tcp;
		u_int16_t 	tcp_srcport;		// ���� ��������� TCP
		u_int16_t 	tcp_dstport;		// ���� ���������� TCP 
		u_int16_t	tcp_len;		// �����: ����� �������� �������� TCP 
		u_int8_t 	tcp_hdr_len;		// �����: ����� ��������� TCP
		u_int32_t 	tcp_seq;	// ���������� ����� TCP
		u_int32_t 	tcp_ack;	// ����� ������������� TCP 
		u_int8_t 	tcp_flags;	// TCP ����� 
		tcp_flags_tree tcp_ftree;
		u_int16_t 	tcp_win;	// TCP ������ ����
		u_int16_t	tcp_sum;		// ����������� �����
		u_int16_t	tcp_urp;		// ������� ���������
		
#define HTTP_REQ	0x01
#define HTTP_RSP	0x10
		u_int8_t	http;		// is_http ��� is_request ��� is_response 
		u_int8_t	smtp;		
		char		*tcp_odata;	// �������� �������� �������� TCP
		char		*tcp_data;	// �������� �������� ������
		//packet_t	*next;		// ��������� ����� � ������� �������
		
		u_int8_t udp;
		u_short upd_srcport;  // �������� ����
		u_short upd_dstport;  // ���� ����������
		u_short upd_len;  // ����� 
		u_short upd_crc;  // ����������� �����

		u_int8_t dns;
		u_int16_t dns_id;	//�������������
		u_int16_t dns_flags;	//�����
		dns_flags_tree dns_ftree;
		u_int16_t dns_qdcount;	//���������� ��������
		u_int16_t dns_ancount;	//���������� �������
		u_int16_t dns_nscount;	//���-�� ���� �������
		u_int16_t dns_arcount;	//���-�� �������������� ���.

		u_int8_t ntp; //ntp
	} packet_t;

/* ������� */
	packet_t * packet_new(void);						/* Produce a new packet object */
	void packet_preprocess(const struct pcap_pkthdr *, const u_char *, int pnum);
    void print_packet (packet_t *pkt);
	void packet_to_json (packet_t *pkt);
	void to_json();
	void load_from_json();
	
