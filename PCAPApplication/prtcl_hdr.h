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



/* MAC АДРЕС*/
typedef struct mac_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}mac_address;


/*4 БАЙТА IP-АДРЕС*/
typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/*6 IPv6-АДРЕС*/

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

/* ЗАГОЛОВОК Ethernet */
typedef struct ethernet_header
{
	//u_int8_t  ether_dhost[6];		/* Destination addr	*/
	//u_int8_t  ether_shost[6];		/* Source addr */
	mac_address  ether_dhost;		/* Destination addr	*/
	mac_address  ether_shost;		/* Source addr */
	u_int16_t ether_type;			/* Packet type */
} eth_header;

/* ЗАГОЛОВОК ARP */
typedef struct arp_header
{
    u_int16_t hw_type;	
	u_int16_t proto;
	u_int8_t hw_size;
	u_int8_t proto_size;
	u_int16_t opcode;
	mac_address arp_shost;	
	ip_address saddr;  // Адрес источника
	mac_address  arp_dhost;		
	ip_address daddr;  // Адрес назначения	
	
} arp_header;

typedef struct ip_flags_tree
	{	u_char rb;
		u_char df;
		u_char mf;
	} ip_flags_tree;

/*ЗАГОЛОВОК IPv4 */
typedef struct ip_header {
	u_int8_t ihl:4;
	u_int8_t version : 4;
	u_char tos;  // Тип обслуживания
	u_short tlen;  // Общая длина
	u_short id;  // Идентификация
	u_short flags;  // Флаги (3 бита) + смещение фрагмента (13 бит)

	u_char ttl;  // Время жизни
	u_char proto;  // Протокол
	u_short crc;  // Контрольная сумма заголовка
	ip_address saddr;  // Адрес источника
	ip_address daddr;  // Адрес назначения
	u_int op_pad;  // Option + Padding
}ip_header;

/*ЗАГОЛОВОК IPv6 */
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


/* ЗАГОЛОВОК TCP */
typedef struct tcp_header
{
	u_int16_t th_sport;		// Исходный порт 
	u_int16_t th_dport;		// Порт назначения
	u_int32_t th_seq;		// Последовательность чисел
	u_int32_t th_ack;		// Номер подтверждения
	u_int8_t th_x2 : 4;		// Смещение данных
	u_int8_t th_off : 4;		
	u_int8_t th_flags;
#  define TH_FIN	0x01
#  define TH_SYN	0x02
#  define TH_RST	0x04
#  define TH_PUSH	0x08
#  define TH_ACK	0x10
#  define TH_URG	0x20
	u_int16_t th_win;		// окно
	u_int16_t th_sum;		// контрольная сумма
	u_int16_t th_urp;		// срочный указатель
}tcp_header;

/* ЗАГОЛОВОК HTTP (не используется) */
typedef struct http_header
{
	char	*startchr;
	char	*endchr;
}http_header;

/*UDP - заголовок */
typedef struct udp_header {
	u_short uh_sport;  // Исходный порт
	u_short uh_dport;  // Порт назначения
	u_short len;  // Длина 
	u_short crc;  // Контрольная сумма
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

/*DNS - заголовок */
typedef struct dns_header {
	/*u_int16_t id;	//Идентификация
	char qr;		// Тип сообщения (запрос/ответ)
	char AA;		//Авторитетный ответ
	char TC;		//Фрагментация
	u_int8_t rcode;		//Код возврата
	u_int8_t opcode;		//Код операции
	u_int16_t qdcount;	//Количество вопросов
	dns_question * queries;
	u_int16_t ancount;	//Количество ответов
	dns_rr * answers;
	u_int16_t nscount;	//Кол-во прав доступа
	dns_rr * name_servers;
	u_int16_t arcount;	//Кол-во дополнительной инф.
	dns_rr * additional;*/
	u_int16_t id;	//Идентификация
	u_int16_t flags;	//Флаги
	u_int16_t qdcount;	//Количество вопросов
	u_int16_t ancount;	//Количество ответов
	u_int16_t nscount;	//Кол-во прав доступа
	u_int16_t arcount;	//Кол-во дополнительной инф.

}dns_header;



eth_header *packet_parse_ethhdr(const char *cp); /*Парсинг Ethernet-заголовка */
arp_header *packet_parse_arphdr(const char *cp); /*Парсинг ARP-заголовка */
ip_header *packet_parse_iphdr(const char *cp); /* Парсинг IPv4-заголовка */
ipv6_header *packet_parse_ipv6hdr(const char *cp); /* Парсинг IPv6-заголовка */
udp_header *packet_parse_updhdr(const char *cp); /* Парсинг UDP-заголовка */
tcp_header *packet_parse_tcphdr(const char *cp); /* Парсинг TCP-заголовка */
dns_header *packet_parse_dnshdr(const char *cp); /* Парсинг DNS-заголовка */