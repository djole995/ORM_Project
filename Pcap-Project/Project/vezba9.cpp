// ================================================================
// Katedra: Katedra za racunarsku tehniku i racunarske komunikacije
// Predmet: Osnovi racunarskih mreza 2
// Godina studija: III godina
// Semestar: Letnji (VI)
// Skolska godina: 2016/2017
// Datoteka: vezba9.c
// ================================================================

// Include libraries
// We do not want the warnings about the old deprecated and unsecure CRT functions since these examples can be compiled under *nix as well
#ifdef _MSC_VER
	#define _CRT_SECURE_NO_WARNINGS
#else
#include <netinet/in.h>
#include <time.h>
#endif

#include <thread>
#include <condition_variable>
#include <mutex>
#include <pcap.h>
#include "protocol_headers.h"
#include <vector>
#include <Windows.h>
#include <windef.h>

using namespace std;

/* Packet handlers for captured packets on ethernet and wifi adapters. */
void wifi_packet_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data);
void eth_packet_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data);

/* Read recorded udp datagram. */
void initiallize(struct pcap_pkthdr** packet_header, unsigned char** packet_data);

/* Capture packets on device which are processed with given packet handler. */
void cap_thread(pcap_t *device, pcap_handler handler);

void send_thread(pcap_t *device, unsigned char* send_data);

/* Calculates IPv4 header checksum. */
uint16_t ip_checksum(const void *buf, size_t hdr_len);

/* device_handle_in - recorded pcap file, opened in offline mode. */
/* device_handle_out - output device (wi-fi or ethernet adapter). */
pcap_t* device_handle_in, *device_handle_wifi, *device_handle_eth;

unsigned char source_eth_addr[6] = {0x78, 0x0c, 0xb8, 0xf7, 0x71, 0xa0 };
unsigned char dest_eth_addr[6] = {0x2c, 0xd0, 0x5a, 0x90, 0xba, 0x9a };

//unsigned char source_ip_addr[4] = {192, 168, 0, 20};
unsigned char source_ip_addr[4] = { 10, 81, 2, 44 };
//unsigned char dest_ip_addr[4] = { 192, 168, 0, 10 };
unsigned char dest_ip_addr[4] = { 10, 81, 2, 52 };

const int BLOCK_SIZE = 10;
const int DATAGRAM_DATA_SIZE = 10;

bool ack_buffer[BLOCK_SIZE];
bool wrong_ack_err = false;

/* Parallel output stream threads. */
thread *wifi_send_thread;
thread *eth_send_thread;
/* Parallel input stream threads. */
thread *wifi_cap_thread;
thread *eth_cap_thread;
condition_variable wifi_cap_wait;
condition_variable eth_cap_wait;
mutex mx;
mutex stdout_mutex;

/* Global pointer to data read from file and its lenght, initialized in initialize function.*/
unsigned char *file_buff;
long file_length;


struct pcap_pkthdr* packet_header;
unsigned char* packet_data;

ex_udp_datagram* ex_udp_d;

/* Data sent via wifi and ethernet. */
unsigned char *wifi_send_data;
unsigned char *eth_send_data;

int main()
{
	//eth_cap_thread = new thread(cap_thread);
	//eth_cap_thread->detach();
    int i=0;
    int wifi_device_number;
	int eth_device_number;
    int sentBytes;
	pcap_if_t* devices;
	pcap_if_t* device;
	char error_buffer [PCAP_ERRBUF_SIZE];
	unsigned int netmask;
	int send_option;

	char filter_exp[] = "ip dst 192.168.0.20 and udp port 27015";
	struct bpf_program fcode;
	
	/**************************************************************/
	//Retrieve the device list on the local machine 
	if (pcap_findalldevs(&devices, error_buffer) == -1)
	{
		printf("Error in pcap_findalldevs: %s\n", error_buffer);
		return -1;
	}
	// Count devices and provide jumping to the selected device 
	// Print the list
	for(device=devices; device; device=device->next)
	{
		printf("%d. %s", ++i, device->name);
		if (device->description)
			printf(" (%s)\n", device->description);
		else
			printf(" (No description available)\n");
	}

	// Check if list is empty
	if (i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter send option (1 - Serial, 2 - Parallel):\n");
	scanf("%d", &send_option);
	// Pick one device from the list
	printf("Enter the output interface(s) number (1-%d):",i);
	if (send_option == 1)
	{
		scanf("%d", &wifi_device_number);
	}
	else
	{
		scanf("%d", &wifi_device_number);
		scanf("%d", &eth_device_number);
	}


	if(wifi_device_number < 1 || wifi_device_number > i || eth_device_number < 1 || eth_device_number > i)
	{
		printf("\nInterfaces number out of range.\n");
		return -1;
	}

	// Select the first device...
	device=devices;
	// ...and then jump to chosen devices
	for (i=0; i<wifi_device_number-1; i++)
	{
		device=device->next;
	}

	// Open the output adapter 
	if ((device_handle_wifi = pcap_open_live(device->name, 65536, 1, 1000, error_buffer)) == NULL)
	{
		printf("\n Unable to open adapter %s.\n", device->name);
		return -1;
	}

	// Select the first device...
	device = devices;
	// ...and then jump to chosen devices
	for (i = 0; i<eth_device_number - 1; i++)
	{
		device = device->next;
	}

	// Open the output adapter 
	if ((device_handle_eth = pcap_open_live(device->name, 65536, 1, 1000, error_buffer)) == NULL)
	{
		printf("\n Unable to open adapter %s.\n", device->name);
		return -1;
	}
	
	// Check the link layer. We support only Ethernet for simplicity.
	if(pcap_datalink(device_handle_wifi) != DLT_EN10MB)
	{
		printf("\nThis program works only on Ethernet networks.\n");
		return -1;
	}

	if (pcap_datalink(device_handle_eth) != DLT_EN10MB)
	{
		printf("\nThis program works only on Ethernet networks.\n");
		return -1;
	}

	if (!device->addresses->netmask)
		netmask = 0;
	else
		netmask = ((struct sockaddr_in *)(device->addresses->netmask))->sin_addr.s_addr;

	// Compile the filter    
	if (pcap_compile(device_handle_wifi, &fcode, filter_exp, 1, netmask) < 0)
	{
		printf("\n Unable to compile the packet filter. Check the syntax.\n");
		return -1;
	}

	// Set the filter
	if (pcap_setfilter(device_handle_wifi, &fcode) < 0)
	{
		printf("\n Error setting the filter.\n");
		return -1;
	}

	initiallize(&packet_header, &packet_data);

	//packet_data = new unsigned char[DATAGRAM_DATA_SIZE];

	ex_udp_d = new ex_udp_datagram(packet_header, packet_data);
	/* Setting source and dest eth address.*/
	for (int i = 0; i < 6; i++)
	{
		ex_udp_d->eh->src_address[i] = source_eth_addr[i];
		ex_udp_d->eh->dest_address[i] = dest_eth_addr[i];
	}

	for (int i = 0; i < 4; i++)
	{
		ex_udp_d->iph->src_addr[i] = source_ip_addr[i];
		ex_udp_d->iph->dst_addr[i] = dest_ip_addr[i];
	}

	ex_udp_d->uh->dest_port = htons(27015);
	ex_udp_d->uh->src_port = htons(27015);

	int tmp = ntohs(ex_udp_d->uh->datagram_length) - sizeof(udp_header);
	*(ex_udp_d->seq_number) = 0;

	wifi_cap_thread = new thread(cap_thread, device_handle_wifi, wifi_packet_handler);
	//eth_cap_thread = new thread(cap_thread, device_handle_eth, eth_packet_handler);
	wifi_cap_thread->detach();
	//eth_cap_thread->detach();

	/* Split packets on two halfs, one is sent via wifi, second via ethernet. */
	wifi_send_data = file_buff;
	eth_send_data = file_buff + file_length / 2;
	wifi_send_thread = new thread(send_thread, device_handle_wifi, wifi_send_data);
	eth_send_thread = new thread(send_thread, device_handle_wifi, eth_send_data);

	/* Sending block of packets */
/*	bool block_sent = false;
	while (!block_sent)
	{
		static int backoff = 100;
		block_sent = true;
		for (int i = 0; i < BLOCK_SIZE; i++)
			if (ack_buffer[i] == false)
			{
				block_sent = false;
				backoff += 100;
				stdout_mutex.lock();
				printf("Packet : %d not sent.\n", i);
				stdout_mutex.unlock();
				*(ex_udp_d->seq_number) = i;
				pcap_sendpacket(device_handle_wifi, packet_data, packet_header->len);
			}
		Sleep(backoff);
	}*/

	wifi_send_thread->join();
	eth_send_thread->join();
	
	pcap_close(device_handle_wifi);
	pcap_close(device_handle_eth);

	
	return 0;
}

// Callback function invoked by libpcap/WinPcap for every incoming packet
void wifi_packet_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{
	ex_udp_datagram* rec_packet;
	rec_packet = new ex_udp_datagram(packet_header, packet_data);
	u_long* ack_num = rec_packet->seq_number;

	if (*ack_num < BLOCK_SIZE)
		ack_buffer[*ack_num] = true;

	stdout_mutex.lock();
	printf("ACK number %d \n", *ack_num);
	stdout_mutex.unlock();
}

void eth_packet_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{
	ex_udp_datagram* rec_packet;
	rec_packet = new ex_udp_datagram(packet_header, packet_data);
	u_long* ack_num = rec_packet->seq_number;

	if (*ack_num < BLOCK_SIZE)
		ack_buffer[*ack_num] = true;

	stdout_mutex.lock();
	printf("ACK number %d \n", *ack_num);
	stdout_mutex.unlock();
}

void initiallize(struct pcap_pkthdr** packet_header, unsigned char** packet_data) 
{
	pcap_t* device_handle_i;
	FILE *data_file;
	char error_buffer[PCAP_ERRBUF_SIZE];

	data_file = fopen("data.txt", "ab+");

	if (data_file == NULL)
	{
		printf("Failed to open file!\n");
		return;
	}

	fseek(data_file, 0, SEEK_END);
	file_length = ftell(data_file);

	fseek(data_file, 0, SEEK_SET);

	file_buff = new unsigned char[file_length];

	fread(file_buff, sizeof(unsigned char), file_length, data_file);


	for (int i = 0; i < BLOCK_SIZE; i++)
	{
		ack_buffer[i] = false;
	}
	
	if ((device_handle_i = pcap_open_offline("udp.pcap",	// File name 
		error_buffer					// Error buffer
	)) == NULL)
	{
		printf("\n Unable to open the file %s.\n", "udp.pcap");
		return;
	}


	pcap_next_ex(device_handle_i, packet_header, (const u_char**)packet_data);
}

void cap_thread(pcap_t *device, pcap_handler handler)
{
	/* Waiting ACK for every packet */
	pcap_loop(device, 0, handler, NULL);
}

void send_thread(pcap_t * device, unsigned char *send_data)
{
	/* Sending block of packets */
	bool block_sent = false;
	while (!block_sent)
	{
		static int backoff = 100;
		block_sent = true;
		for (int i = 0; i < BLOCK_SIZE; i++)
			if (ack_buffer[i] == false)
			{
				block_sent = false;
				backoff += 100;
				stdout_mutex.lock();
				printf("Packet : %d not sent.\n", i);
				stdout_mutex.unlock();

				packet_header->len = sizeof(udp_header) + ex_udp_d->iph->header_length * 4 + sizeof(ethernet_header);

				/* Last datagram in file is smaller than others? */
				if ((i + 1)*DATAGRAM_DATA_SIZE <= file_length/2)
				{
					memcpy(ex_udp_d->data, send_data + i*DATAGRAM_DATA_SIZE, DATAGRAM_DATA_SIZE);
					ex_udp_d->iph->length = htons(ex_udp_d->iph->header_length*4 + sizeof(udp_header) + DATAGRAM_DATA_SIZE + 4);
					ex_udp_d->uh->datagram_length = htons(sizeof(udp_header) + DATAGRAM_DATA_SIZE + 4);
					packet_header->len += DATAGRAM_DATA_SIZE + 4;
				}
				else
				{
					memcpy(ex_udp_d->data, send_data + i*DATAGRAM_DATA_SIZE, file_length/2 - i*DATAGRAM_DATA_SIZE);
					ex_udp_d->iph->length = htons(ex_udp_d->iph->header_length*4 + sizeof(udp_header) + file_length/2 - i*DATAGRAM_DATA_SIZE + 4);
					ex_udp_d->uh->datagram_length = htons(sizeof(udp_header) + file_length/2 - i*DATAGRAM_DATA_SIZE + 4);
					packet_header->len += file_length/2 - i*DATAGRAM_DATA_SIZE + 4;
				}
				*(ex_udp_d->seq_number) = htonl(i);
				pcap_sendpacket(device, packet_data, packet_header->len);

				/* All packets sent */
				if ((i + 1)*DATAGRAM_DATA_SIZE >= file_length/2)
					break;
			}
		Sleep(backoff);
	}
}


//! \brief Calculate the IP header checksum.
//! \param buf The IP header content.
//! \param hdr_len The IP header length.
//! \return The result of the checksum.
uint16_t ip_checksum(const void *buf, size_t hdr_len)
{
	unsigned long sum = 0;
	const uint16_t *ip1;
	
	ip1 = (const uint16_t *) buf;
	while (hdr_len > 1)
	{
		sum += *ip1++;
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
	}
	
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	
	return(~sum);
}
