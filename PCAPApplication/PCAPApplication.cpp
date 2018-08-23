// PCAPApplication.cpp: определяет точку входа для консольного приложения.
//

#include "stdafx.h"
#include <iostream>
#include <string>
#include "pcap.h"
#include <winsock2.h>
#include "packet.h"


using namespace std;
#pragma comment (lib, "ws2_32.lib")

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#define LINE_LEN 16

void package_handler(u_char * dumpfile, const struct pcap_pkthdr * header, const u_char * pkt_data);
//void packet_preprocess(const struct pcap_pkthdr *, const u_char *);

int savedump();
int readdump();
int pnum;

int main(int argc, char **argv)
{	int opr=0;
//to_json();
	printf("Enter the opeation (1 - saving, 2 - reading json, 3 - pcap to json): ");   
	//scanf_s("%d", &opr);
	cin >> opr;

	switch (opr)
	{ case 1: savedump();
			  break;
	case 2:   load_from_json(); //readdump();
		system("pause");
		break;
	case 3: readdump();
			system("pause");
			break;
	default:
		break;
	}
	return 0;
}

void package_handler(u_char * dumpfile, const struct pcap_pkthdr * header, const u_char * pkt_data)
{
	pnum++;
	packet_preprocess( header, pkt_data, pnum);
	/*сохранить пакет в файле дампа */
	//pcap_dump(dumpfile, header, pkt_data);
	return;
}


int savedump()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0, col;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	pnum = 0;
    u_int netmask;
	
	
	/*------ИЗВЛЕЧЬ СПИСОК УСТРОЙСТВ С ЛОКАЛЬНОЙ МАШИНЫ--------*/
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed*/, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		exit(1);
	}
	/*---- ВЫВОД СПИСКА----- */
	for (d = alldevs; d != NULL; d = d->next)
		{
			printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else printf(" (No description available)\n");
		}
	if (i == 0)
	{
		printf("\n No interfaces found! Make sure WinPcap is installed.\n");
		system("pause");
		return 0;
	}

	printf("Enter the interface number (1-%d):", i);    //ввести номер интерфейса
	scanf_s("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\n Interface number out of range.\n");
		pcap_freealldevs(alldevs);  /* ОСВОБОДИТЬ СПИСОК УСТРОЙСТВ*/
		system("pause");
		return -1;
	}

	/* ---ПЕРЕХОД К ВЫБРАННОМУ АДАПТЕРУ--- */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);
	
	/* ОТКРЫТЬ УСТРОЙСТВО */
		if ((adhandle = pcap_open(d->name,          // ИМЯ УСТРОЙСТВА
									65536,            // ЧАСТЬ ПАКЕТА ДЛЯ ЗАХВАТА
									// 65536 гарантирует, что весь пакет будет захвачен на всех уровнях ссылок
								PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
								1000,             // ВРЕМЯ ОЖИДАНИЯ
								NULL,             // АУТЕНТИФИКАЦИЯ НА УДАЛЕННОЙ МАШИНЕ
								errbuf            // БУФФЕР ОШИБКИ
								)) == NULL)
			{
			fprintf(stderr, "\n Unable to open the adapter. %s is not supported by WinPcap\n", d->name); //Невозможно открыть адаптер.% s не поддерживается WinPcap
			pcap_freealldevs(alldevs);
			system("pause");
			return -1;
			}

		/*ПРОВЕРИТЬ УРОВЕНЬ МАС для Ethernet.*/
			if (pcap_datalink(adhandle)!= DLT_EN10MB)
		{
		fprintf(stderr, "\n This program works only on Ethernet networks.\n");
		pcap_freealldevs(alldevs);
		system("pause");
		return -1;
		}

		if (d->addresses != NULL) 			/*Извлечь маску первого адреса интерфейса */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
			else 	netmask = 0xffffff;  	/*Если интерфейс без адресов, мы предположим, что он находится в сети класса С*/

		/*СКОМПИЛИРОВАТЬ ФИЛЬТР
		if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0)
			{
				fprintf(stderr, "\n Unable to compile the packet filter. Check the syntax.\n");
				pcap_freealldevs(alldevs);
				system("pause");
				return -1;
			}

		/*УСТАНОВИТЬ ФИЛЬТР
			if (pcap_setfilter(adhandle, &fcode)<0)
			{
				fprintf(stderr, "\n Error setting the filter.\n");
				pcap_freealldevs(alldevs);
				system("pause");
				return -1;
			}

		/*Открыть файл дампа 
		pcap_dumper_t *dumpfile;
		char fname[128] = "C://1//dump001.pcap"; // имя дампа 
		dumpfile = pcap_dump_open(adhandle, fname);
		if (dumpfile == NULL)
		{	fprintf(stderr, "\n Error opening output file \n");
			system("pause");
			return -1;
		}*/
		

		printf("\n Enter the number of packets (no limits - 0):");    //ввести номер интерфейса
		scanf_s("%d", &col);

        printf("\n Listening on% s ...", d->description);
		printf("\n Press Ctrl+C to stop \n");

		/*ЗАХВАТ ПАКЕТОВ */
		//pcap_loop(adhandle, col, package_handler, (unsigned char *)dumpfile);
		pcap_loop(adhandle, col, package_handler, NULL);
		pcap_freealldevs(alldevs);
		printf("\n Complete! \n");
		system("pause");
		return 0;
}

int readdump()
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	char source[PCAP_BUF_SIZE];
	pnum = 0;
	char *fname = ""; //имя дампа
	fname = "C://1//ip6.pcap";
	/*printf("Enter the opeation: (1-%*c):", fname);
	if (fname == "")
	{
		fprintf(stderr, "\n Name is C://1//dump001.dmp  \n");
		fname = "C://1//dump001.dmp";
	}*/

	if (pcap_createsrcstr(source, // переменная, которая будет содержать исходную строку
						PCAP_SRC_FILE, // мы хотим открыть файл
						NULL, // удаленный хост
						NULL, // порт на удаленном хосте
						fname, // имя файла, который мы хотим открыть
						errbuf // буфер ошибок
						) != 0)
	{
		fprintf(stderr, "\n Error creating a source string \n");
		return -1;
	}

	if ((fp = pcap_open(source,         // name of the device
						65536,          // portion of the packet to capture
						// 65536 guarantees that the whole packet will be captured on all the link layers
						PCAP_OPENFLAG_PROMISCUOUS,     // promiscuous mode
						1000,              // read timeout
						NULL,              // authentication on the remote machine
						errbuf         // error buffer
						)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the file %s.\n", source);
		return -1;
	}

	pcap_loop(fp, 0, package_handler, NULL);

	return 0;
}