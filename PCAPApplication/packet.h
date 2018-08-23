#pragma once


#include "pcap.h"
#include "prtcl_hdr.h"
#include <string.h>


typedef struct _packet_t
	{
		int frame_number;             // номер пакета
	    time_t frame_sec;         // Время захвата sec 
		time_t frame_usec;        // Время захвата usec 
		u_int32_t	frame_len;

		u_int8_t eth;
		mac_address  eth_dhost;		// Порт источника
		mac_address  eth_shost;		// Порт назначения
		u_int16_t eth_type;			// Тип

		u_int8_t arp;
		u_int16_t arp_hw_type;
		u_int16_t arp_proto;
		u_int8_t arp_hw_size;
		u_int8_t arp_proto_size;
		u_int16_t arp_opcode;
		mac_address arp_shost;
		ip_address arp_saddr;  // Адрес источника
		mac_address  arp_dhost;
		ip_address arp_daddr;  // Адрес назначения	

		u_int8_t ipv6;
		u_int8_t ip6_version;
		u_int8_t ipv6_tclass;
		u_int16_t ipv6_flow;
		u_int16_t ipv6_plen;
		u_int8_t ipv6_next;
		u_int8_t ipv6_hlim;
		ipv6_address 	ipv6_srcaddr;		// 0x: исходный IP-адрес 
		ipv6_address 	ipv6_dstaddr;		// 0x: IP-адрес получателя
		
		u_int8_t ipv4;
		u_int8_t ip_version;
		u_int8_t 	ip_hdr_len;		// Байты: длина IP-заголовка 
		u_char ip_tos;  // Тип обслуживания
		u_int16_t 	ip_len;		// Байт: общая длина IP
		u_short ip_id;  // Идентификация
		u_short ip_flags;  // Флаги (3 бита) + смещение фрагмента (13 бит)
		ip_flags_tree ip_ftree;
		u_char ip_ttl;  // Время жизни
		u_char ip_proto;  // Протокол
		u_short ip_crc;  // Контрольная сумма заголовка
		ip_address 	ip_srcaddr;		// 0x: исходный IP-адрес 
		ip_address 	ip_dstaddr;		// 0x: IP-адрес получателя

		u_int8_t icmp;
		u_int8_t igmp;
		u_int8_t tcp;
		u_int16_t 	tcp_srcport;		// Порт источника TCP
		u_int16_t 	tcp_dstport;		// Порт назначения TCP 
		u_int16_t	tcp_len;		// Байты: длина полезной нагрузки TCP 
		u_int8_t 	tcp_hdr_len;		// Байты: длина заголовка TCP
		u_int32_t 	tcp_seq;	// Порядковый номер TCP
		u_int32_t 	tcp_ack;	// Номер подтверждения TCP 
		u_int8_t 	tcp_flags;	// TCP флаги 
		tcp_flags_tree tcp_ftree;
		u_int16_t 	tcp_win;	// TCP размер окна
		u_int16_t	tcp_sum;		// контрольная сумма
		u_int16_t	tcp_urp;		// срочный указатель
		
#define HTTP_REQ	0x01
#define HTTP_RSP	0x10
		u_int8_t	http;		// is_http или is_request или is_response 
		u_int8_t	smtp;		
		char		*tcp_odata;	// Исходная полезная нагрузка TCP
		char		*tcp_data;	// Реальные полезные данные
		//packet_t	*next;		// Следующий пакет в очереди пакетов
		
		u_int8_t udp;
		u_short upd_srcport;  // Исходный порт
		u_short upd_dstport;  // Порт назначения
		u_short upd_len;  // Длина 
		u_short upd_crc;  // Контрольная сумма

		u_int8_t dns;
		u_int16_t dns_id;	//Идентификация
		u_int16_t dns_flags;	//Флаги
		dns_flags_tree dns_ftree;
		u_int16_t dns_qdcount;	//Количество вопросов
		u_int16_t dns_ancount;	//Количество ответов
		u_int16_t dns_nscount;	//Кол-во прав доступа
		u_int16_t dns_arcount;	//Кол-во дополнительной инф.

		u_int8_t ntp; //ntp
	} packet_t;

/* ФУНКЦИИ */
	packet_t * packet_new(void);						/* Produce a new packet object */
	void packet_preprocess(const struct pcap_pkthdr *, const u_char *, int pnum);
    void print_packet (packet_t *pkt);
	void packet_to_json (packet_t *pkt);
	void to_json();
	void load_from_json();
	
