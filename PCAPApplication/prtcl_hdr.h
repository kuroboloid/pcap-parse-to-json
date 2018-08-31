#pragma once
#include "pcap.h"


#if BYTE_ORDER == BIG_ENDIAN
#define ETHER_TYPE_IP	0x0008
#endif
#if BYTE_ORDER == LITTLE_ENDIAN
#define ETHER_TYPE_IP	0x0800
#endif

#define IP_TYPE_ICMP 0x01
#define IP_TYPE_IGMP 0x02

#define IP_TYPE_TCP	0x06
#define IP_TYPE_UDP	0x11



/* MAC �����*/
typedef struct mac_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}mac_address;


/*4 ����� IP-�����*/
typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/*6 IPv6-�����*/

typedef struct ipv6_address {
	u_int16_t byte1;
	u_int16_t byte2;
	u_int16_t byte3;
	u_int16_t byte4;
	u_int16_t byte5;
	u_int16_t byte6;
	u_int16_t byte7;
	u_int16_t byte8;
}ipv6_address;

/* ��������� Ethernet */
typedef struct ethernet_header
{
	//u_int8_t  ether_dhost[6];		/* Destination addr	*/
	//u_int8_t  ether_shost[6];		/* Source addr */
	mac_address  ether_dhost;		/* Destination addr	*/
	mac_address  ether_shost;		/* Source addr */
	u_int16_t ether_type;			/* Packet type */
} eth_header;

/* ��������� ARP */
typedef struct arp_header
{
    u_int16_t hw_type;	
	u_int16_t proto;
	u_int8_t hw_size;
	u_int8_t proto_size;
	u_int16_t opcode;
	mac_address arp_shost;	
	ip_address saddr;  // ����� ���������
	mac_address  arp_dhost;		
	ip_address daddr;  // ����� ����������	
	
} arp_header;

typedef struct ip_flags_tree
	{	u_char rb;
		u_char df;
		u_char mf;
	} ip_flags_tree;

/*��������� IPv4 */
typedef struct ip_header {
	u_int8_t ihl:4;
	u_int8_t version : 4;
	u_char tos;  // ��� ������������
	u_short tlen;  // ����� �����
	u_short id;  // �������������
	u_short flags;  // ����� (3 ����) + �������� ��������� (13 ���)

	u_char ttl;  // ����� �����
	u_char proto;  // ��������
	u_short crc;  // ����������� ����� ���������
	ip_address saddr;  // ����� ���������
	ip_address daddr;  // ����� ����������
	u_int op_pad;  // Option + Padding
}ip_header;

/*��������� IPv6 */
typedef struct ipv6_header
{	
	u_int32_t ver_tcl_flow;
	u_int16_t plen ;
	u_int8_t next;
	u_int8_t hlim;
	ipv6_address srcaddr;
	ipv6_address dstaddr;
}ipv6_header;

typedef struct tcp_flags_tree
{
	u_char res;
	u_char ns;
	u_char cwr;
	u_char ecn;
	u_char urg;
	u_char ack;
	u_char push;
	u_char reset;
	u_char syn;
	u_char fin;
} tcp_flags_tree;


/* ��������� TCP */
typedef struct tcp_header
{
	u_int16_t th_sport;		// �������� ���� 
	u_int16_t th_dport;		// ���� ����������
	u_int32_t th_seq;		// ������������������ �����
	u_int32_t th_ack;		// ����� �������������
	u_int8_t th_x2 : 4;		// �������� ������
	u_int8_t th_off : 4;		
	u_int8_t th_flags;
#  define TH_FIN	0x01
#  define TH_SYN	0x02
#  define TH_RST	0x04
#  define TH_PUSH	0x08
#  define TH_ACK	0x10
#  define TH_URG	0x20
	u_int16_t th_win;		// ����
	u_int16_t th_sum;		// ����������� �����
	u_int16_t th_urp;		// ������� ���������
}tcp_header;

/* ��������� HTTP (�� ������������) */
typedef struct http_header
{
	char	*startchr;
	char	*endchr;
}http_header;

/*UDP - ��������� */
typedef struct udp_header {
	u_short uh_sport;  // �������� ����
	u_short uh_dport;  // ���� ����������
	u_short len;  // ����� 
	u_short crc;  // ����������� �����
}udp_header;


typedef struct dns_question {
	char * name;
	u_int16_t type;
	u_int16_t cls;
	struct dns_question * next;
} dns_question;

// Holds the information for a dns resource record.
typedef struct dns_rr {
	char * name;
	u_int16_t type;
	u_int16_t cls;
	const char * rr_name;
	u_int16_t ttl;
	u_int16_t rdlength;
	u_int16_t data_len;
	char * data;
	struct dns_rr * next;
} dns_rr;

typedef struct dns_flags_tree
{
	u_char response;
	u_char opcode;
	u_char truncated;
	u_char recdesired;
	u_char z;
	u_char ckdsbl;
} dns_flags_tree;

/*DNS - ��������� */
typedef struct dns_header {
	/*u_int16_t id;	//�������������
	char qr;		// ��� ��������� (������/�����)
	char AA;		//������������ �����
	char TC;		//������������
	u_int8_t rcode;		//��� ��������
	u_int8_t opcode;		//��� ��������
	u_int16_t qdcount;	//���������� ��������
	dns_question * queries;
	u_int16_t ancount;	//���������� �������
	dns_rr * answers;
	u_int16_t nscount;	//���-�� ���� �������
	dns_rr * name_servers;
	u_int16_t arcount;	//���-�� �������������� ���.
	dns_rr * additional;*/
	u_int16_t id;	//�������������
	u_int16_t flags;	//�����
	u_int16_t qdcount;	//���������� ��������
	u_int16_t ancount;	//���������� �������
	u_int16_t nscount;	//���-�� ���� �������
	u_int16_t arcount;	//���-�� �������������� ���.

}dns_header;



eth_header *packet_parse_ethhdr(const char *cp); /*������� Ethernet-��������� */
arp_header *packet_parse_arphdr(const char *cp); /*������� ARP-��������� */
ip_header *packet_parse_iphdr(const char *cp); /* ������� IPv4-��������� */
ipv6_header *packet_parse_ipv6hdr(const char *cp); /* ������� IPv6-��������� */
udp_header *packet_parse_updhdr(const char *cp); /* ������� UDP-��������� */
tcp_header *packet_parse_tcphdr(const char *cp); /* ������� TCP-��������� */
dns_header *packet_parse_dnshdr(const char *cp); /* ������� DNS-��������� */