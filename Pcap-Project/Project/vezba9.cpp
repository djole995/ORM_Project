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

void send_thread(pcap_t *device, unsigned char* send_data, unsigned int data_size, unsigned int id);

unsigned int make_packets(unsigned char *input_data, unsigned char ***packets, unsigned char *udp_packet_data, 
	struct pcap_pkthdr *udp_packet_header, unsigned int data_size, unsigned int packet_data_size);

/* Calculates IPv4 header checksum. */
uint16_t ip_checksum(const void *buf, size_t hdr_len);

/* device_handle_in - recorded pcap file, opened in offline mode. */
/* device_handle_out - output device (wi-fi or ethernet adapter). */
pcap_t* device_handle_in, *device_handle_wifi, *device_handle_eth;

unsigned char source_eth_addr[6] = {0x78, 0x0c, 0xb8, 0xf7, 0x71, 0xa0 };
unsigned char dest_eth_addr[6] = {0x2c, 0xd0, 0x5a, 0x90, 0xba, 0x9a };

unsigned char source_ip_addr[4] = {192, 168, 0, 20};
//unsigned char source_ip_addr[4] = { 10, 81, 2, 44 };
unsigned char dest_ip_addr[4] = { 192, 168, 0, 10 };
//unsigned char dest_ip_addr[4] = { 10, 81, 2, 52 };

const int BLOCK_SIZE = 10;
const int DATAGRAM_DATA_SIZE = 10;
const int BUFFER_SIZE_ACK_NUM = 10000;

bool ack_buffer[BLOCK_SIZE*100];
bool ack_buffer_size[2];
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

/* Generic udp packet read from wireshark file. */
struct pcap_pkthdr* packet_header;
unsigned char* packet_data;

/* Packets created from read file data. */
unsigned char **packets;

ex_udp_datagram* ex_udp_d;

/* Data sent via wifi and ethernet. */
unsigned char *wifi_send_data;
unsigned int wifi_data_size;
unsigned char *wifi_packets;
unsigned char *eth_send_data;
unsigned int eth_data_size;
unsigned char *eth_packets;

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

	// Check the link layer. We support only Ethernet for simplicity.
	if (pcap_datalink(device_handle_wifi) != DLT_EN10MB)
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
	
	if (pcap_datalink(device_handle_eth) != DLT_EN10MB)
	{
		printf("\nThis program works only on Ethernet networks.\n");
		return -1;
	}

	if (!device->addresses->netmask)
		netmask = 0;
	else
		netmask = ((struct sockaddr_in *)(device->addresses->netmask))->sin_addr.s_addr;
  
	if (pcap_compile(device_handle_eth, &fcode, filter_exp, 1, netmask) < 0)
	{
		printf("\n Unable to compile the packet filter. Check the syntax.\n");
		return -1;
	}

	if (pcap_setfilter(device_handle_eth, &fcode) < 0)
	{
		printf("\n Error setting the filter.\n");
		return -1;
	}


	/* Read generic udp packet and read raw data file. */
	initiallize(&packet_header, &packet_data);
	/* Split file data into packes of DATAGRAM_DATA_SIZE size. */
	unsigned int packets_number = make_packets(file_buff, &packets, packet_data, packet_header, file_length, DATAGRAM_DATA_SIZE);

	for (int i = 0; i < packets_number; i++)
	{
			ex_udp_d = new ex_udp_datagram(packets[i]);
			for (int j = 0; j < DATAGRAM_DATA_SIZE; j++)
				printf("%c", ex_udp_d->data[j]);
		printf("\n");
	}

	/*ex_udp_d = new ex_udp_datagram(packets[2]);
	for (int j = 0; j < 3; j++)
		printf("%c", ex_udp_d->data[j]);*/

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
	eth_cap_thread = new thread(cap_thread, device_handle_eth, eth_packet_handler);
	wifi_cap_thread->detach();
	eth_cap_thread->detach();

	/* Split packets on two halfs, one is sent via wifi, second via ethernet. */
	wifi_send_data = file_buff;
	wifi_data_size = file_length/2;
	eth_send_data = file_buff + file_length / 2;
	eth_data_size = (file_length % 2 == 0) ? file_length / 2 : file_length / 2 + 1;
	wifi_send_thread = new thread(send_thread, device_handle_wifi, wifi_send_data, wifi_data_size, 0);
	eth_send_thread = new thread(send_thread, device_handle_eth, eth_send_data, eth_data_size, 1);

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

	int i = 0;
	if (ntohl(*ack_num) < BLOCK_SIZE*100)
		ack_buffer[ntohl(*ack_num)] = true;
	else if (ntohl(*ack_num) == BUFFER_SIZE_ACK_NUM)
		ack_buffer_size[i++] = true;

	stdout_mutex.lock();
	printf("ACK number %d \n", ntohl(*ack_num));
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

/* Split data to packets. Return number of packets created. */
unsigned int make_packets(unsigned char *input_data, unsigned char ***packets, unsigned char *udp_packet_data, struct pcap_pkthdr *udp_packet_header, unsigned int input_data_size, unsigned int packet_data_size)
{
	int packets_num = ceil(double(input_data_size) / packet_data_size);
	*packets = new unsigned char*[packets_num];

	ex_udp_datagram *udp_d = new ex_udp_datagram(udp_packet_header, udp_packet_data);

	int header_size = sizeof(ethernet_header) + udp_d->iph->header_length * 4 + sizeof(udp_header) + 4; //4 bytes for ACK num
	/* Total packet len = header size + raw data size. */
	int total_packet_size = header_size + packet_data_size;
	int last_packet_size = header_size + input_data_size - (packets_num - 1)*packet_data_size;

	for (int i = 0; i < packets_num-1; i++)
	{
		(*packets)[i] = new unsigned char[total_packet_size];
		/* Copy header from generic packet. */
		memcpy((*packets)[i], udp_packet_data, header_size);
		/* Copy raw data. */
		memcpy((*packets)[i] + header_size, input_data + i*packet_data_size, packet_data_size);

	}

	/* Last packet is smaller than others. */
	(*packets)[packets_num-1] = new unsigned char[last_packet_size];
	/* Copy header from generic packet. */
	memcpy((*packets)[packets_num-1], udp_packet_data, header_size);
	/* Copy raw data. */
	memcpy((*packets)[packets_num-1] + header_size, input_data + (packets_num-1)*packet_data_size, last_packet_size - header_size);

	delete udp_d;

	return packets_num;
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



void send_thread(pcap_t * device, unsigned char *send_data, unsigned int data_size, unsigned int id)
{
	ex_udp_d->change_data_size(sizeof(unsigned int));

	/* Set raw packet data to output buffer size. */
	unsigned int *d_size = (unsigned int*) ex_udp_d->data;
	*d_size = htons(data_size);

	/* Send data size. */
	int ret = -1;
	ack_buffer_size[id] = true;
	while(ret != 0 && ack_buffer_size == false)
		ret = pcap_sendpacket(device, packet_data, sizeof(udp_header) + ex_udp_d->iph->header_length * 4 + sizeof(ethernet_header) + 8);

	int block_num = 0;
	/* Sending block of packets. */
	
	for (int j = 0; j <= data_size / DATAGRAM_DATA_SIZE / BLOCK_SIZE; j++)
	{
		bool block_sent = false;
		while (!block_sent)
		{
			static int backoff = 100;
			block_sent = true;
			for (int i = /*block_num*/0; i < /*block_num + */BLOCK_SIZE; i++)
			{
				if (ack_buffer[i] == false)
				{
					block_sent = false;
					backoff += 100;
					stdout_mutex.lock();
					printf("Packet : %d not sent.\n", i);
					stdout_mutex.unlock();

					packet_header->len = sizeof(udp_header) + ex_udp_d->iph->header_length * 4 + sizeof(ethernet_header);

					/* Last datagram in file is smaller than others? */
					if ((i + 1)*DATAGRAM_DATA_SIZE <= data_size)
					{
						memcpy(ex_udp_d->data, send_data + i*DATAGRAM_DATA_SIZE, DATAGRAM_DATA_SIZE);
						ex_udp_d->change_data_size(DATAGRAM_DATA_SIZE);
						packet_header->len += DATAGRAM_DATA_SIZE + 4;
					}
					else
					{
						memcpy(ex_udp_d->data, send_data + i*DATAGRAM_DATA_SIZE, data_size - i*DATAGRAM_DATA_SIZE);
						ex_udp_d->change_data_size(data_size - i*DATAGRAM_DATA_SIZE);
						packet_header->len += data_size - i*DATAGRAM_DATA_SIZE + 4;
					}
					*(ex_udp_d->seq_number) = htonl(i);
					pcap_sendpacket(device, packet_data, packet_header->len);
				}

				/* All packets sent */
				if ((i + 1)*DATAGRAM_DATA_SIZE >= data_size)
					break;
			}
			Sleep(backoff);
		}
		block_num++;
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
