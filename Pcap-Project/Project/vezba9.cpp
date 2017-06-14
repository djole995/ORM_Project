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

void send_thread(pcap_t *device, unsigned char** send_data, unsigned int data_size, unsigned int id);

void make_packets(unsigned char *input_data, unsigned char ***packets, unsigned char *udp_packet_data, 
	struct pcap_pkthdr *udp_packet_header, unsigned int data_size, unsigned int packet_data_size);

/* Sets packets source and destination addresses. */
void set_addresses(unsigned char **packets, unsigned int packets_num, unsigned char eth_src_addr[], unsigned char eth_dst_addr[],
	unsigned char ip_src_addr[], unsigned char ip_dst_addr[]);

void calculate_checksum(unsigned char **packets, unsigned int packets_num);

/* Calculates IPv4 header checksum. */
uint16_t ip_checksum(const void *buf, size_t hdr_len);

const int BLOCK_SIZE = 10;
const int DATAGRAM_DATA_SIZE = 10;
const int BUFFER_SIZE_ACK_NUM = 10000;
const int INTERFACES_NUMBER = 2;
const int PORT_NUMBER = 27015;

/* device_handle_in - recorded pcap file, opened in offline mode. */
/* device_handle_out - output device (wi-fi or ethernet adapter). */
pcap_t* device_handle[INTERFACES_NUMBER];

unsigned char eth_source_mac_addr[6] = { 0x78, 0x0c, 0xb8, 0xf7, 0x71, 0xa0 };
//unsigned char source_wifi_addr[6] = {}
//unsigned char wifi_source_mac_addr[6] = { 0x00, 0xe0, 0x4c, 0x36, 0x33, 0xf6 };
unsigned char server_mac_addr[INTERFACES_NUMBER][6] = { { 0x78, 0x0c, 0xb8, 0xf7, 0x71, 0xa0 }, { 0x00, 0xe0, 0x4c, 0x36, 0x33, 0xf6 } };
//unsigned char dest_eth_addr[6] = { 0x2c, 0xd0, 0x5a, 0x90, 0xba, 0x9a };
unsigned char client_mac_addr/*[INTERFACES_NUMBER]*/[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
//unsigned char dest_eth_addr[6] = { 0x7c, 0x05, 0x07, 0x24, 0xf8, 0x04 };

unsigned char server_ip_addr[INTERFACES_NUMBER][4] = { {192, 168, 0, 1}, { 169, 254, 176, 100 } };
unsigned char client_ip_addr[INTERFACES_NUMBER][4] = { { 192, 168, 0, 16 },{ 169, 254, 176, 102 } };
//unsigned char source_ip_addr[4] = { 10, 81, 35, 45 };
//unsigned char dest_ip_addr[4] = { 10, 81, 35, 43 };
/*unsigned char eth_source_ip_addr[4] = { 169, 254, 176, 100 };
unsigned char eth_dest_ip_addr[4] = { 169, 254, 176, 101 };*/
//unsigned char dest_ip_addr[4] = { 192, 168, 0, 9 };
/*unsigned char wifi_dest_ip_addr[4] = { 192, 168, 0, 14 };*/

/* ACK buffer. First element represent ACK for sent data size, others are ACKs for user datagrams. */
bool ack_buffer[2000];

/* Parallel output stream threads. */
thread *send_threads[INTERFACES_NUMBER];
/* Parallel input stream threads. */
thread *cap_threads[INTERFACES_NUMBER];

mutex mx;
mutex stdout_mutex;
mutex ack_buff_mutex;

/* Global pointer to data read from file and its lenght, initialized in initialize function.*/
unsigned char *file_buff;
long file_length;

/* Generic udp packet read from wireshark file. */
struct pcap_pkthdr* packet_header;
unsigned char* packet_data;

/* Packets created from read file data. */
unsigned char *data_size_packet[INTERFACES_NUMBER];
unsigned char **packets[INTERFACES_NUMBER];
mutex *packet_mutex;
/* packet status (received or not received). */
bool *packet_sent;

/* Size of packet including headers, size of extended header itself and number of created packets
, all initialized in make_packets function. */
unsigned int total_packet_size;
/* Last packet may be smaller than others. */
unsigned int last_packet_total_size;
unsigned int packets_num;
unsigned int header_size;

ex_udp_datagram* ex_udp_d;

/* Data sent via wifi and ethernet. */
unsigned char **send_data[INTERFACES_NUMBER];
/* Number of packets sent on every network interfaces. */
unsigned int data_size[INTERFACES_NUMBER];

int main()
{
    int i=0;
    int device_number[INTERFACES_NUMBER];
    int sentBytes;
	pcap_if_t* devices;
	pcap_if_t* device;
	char error_buffer [PCAP_ERRBUF_SIZE];
	unsigned int netmask;
	int send_option;
	/* Server ethernet interface filter exp and  Server wifi interface ip filter exp.  */
	char *filter_exp[INTERFACES_NUMBER] = {"udp port 27015 and ip dst 192.168.0.20", "udp port 27015 and ip dst 169.254.176.100" };
	struct bpf_program fcode[INTERFACES_NUMBER];
	
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
		scanf("%d", &device_number[0]);
	}
	else
	{
		scanf("%d", &device_number[0]);
		scanf("%d", &device_number[1]);
	}

	/* Checking valid user input. */
	for(int j = 0; j < INTERFACES_NUMBER; j++)
	{
		if (device_number[j] < 1 || device_number[j] > i)
		{
			printf("\nInterfaces number out of range.\n");
			return -1;
		}
	}

	/* Opening devices and setting capture filter. */
	for (int j = 0; j < INTERFACES_NUMBER; j++)
	{
		// Select the first device...
		device = devices;
		// ...and then jump to chosen devices
		for (i = 0; i < device_number[j]-1; i++)
		{
			device = device->next;
		}

		// Open the output adapter 
		if ((device_handle[j] = pcap_open_live(device->name, 65536, 1, 1, error_buffer)) == NULL)
		{
			printf("\n Unable to open adapter %s.\n", device->name);
			return -1;
		}

		// Check the link layer. We support only Ethernet for simplicity.
		if (pcap_datalink(device_handle[j]) != DLT_EN10MB)
		{
			printf("\nThis program works only on Ethernet networks.\n");
			return -1;
		}

		if (!device->addresses->netmask)
			netmask = 0;
		else
			netmask = ((struct sockaddr_in *)(device->addresses->netmask))->sin_addr.s_addr;



		// Compile the filter    
		if (pcap_compile(device_handle[j], &fcode[j], filter_exp[j], 1, netmask) < 0)
		{
			printf("\n Unable to compile the packet filter. Check the syntax.\n");
			return -1;
		}

		// Set the filter
		if (pcap_setfilter(device_handle[j], &fcode[j]) < 0)
		{
			printf("\n Error setting the filter.\n");
			return -1;
		}
	}

	/* Read generic udp packet and read raw data file. */
	initiallize(&packet_header, &packet_data);

	for (int i = 0; i < INTERFACES_NUMBER; i++)
	{
		/* Split file data into packes of DATAGRAM_DATA_SIZE size. */
		make_packets(file_buff, &packets[i], packet_data, packet_header, file_length, DATAGRAM_DATA_SIZE);
		set_addresses(packets[i], packets_num, server_mac_addr[i], client_mac_addr, server_ip_addr[i], client_ip_addr[i]);
		set_addresses(&data_size_packet[i], 1, server_mac_addr[i], client_mac_addr, server_ip_addr[i], client_ip_addr[i]);
		calculate_checksum(packets[i], packets_num);
		calculate_checksum(&data_size_packet[i], 1);
	}

	for (int i = 0; i < INTERFACES_NUMBER; i++)
	{
		/* Set addresses and calculate checksum for data size packet. */
		set_addresses(&data_size_packet[i], 1, server_mac_addr[i], client_mac_addr, server_ip_addr[i], client_ip_addr[i]);
		calculate_checksum(&data_size_packet[i], 1);
	}

	ex_udp_datagram ex_udp_d2(packets[0][0]);

	ex_udp_d2 = ex_udp_datagram(packets[1][0]);

	/* Creating caputure thread for every interface. */
	for (int i = 0; i < INTERFACES_NUMBER; i++)
	{
		cap_threads[i] = new thread(cap_thread, device_handle[i], wifi_packet_handler);
		cap_threads[i]->detach();
	}

	/* Split send data on INTERFACES_NUMBER parts and start send threads. */
	for (int i = 0; i < INTERFACES_NUMBER; i++)
	{
		send_threads[i] = new thread(send_thread, device_handle[i], packets[i], packets_num, i);
	}

	/* Waiting untill all packets are sent. */
	for (int i = 0; i < INTERFACES_NUMBER; i++)
	{
		send_threads[i]->join();
	}
	
	for (int i = 0; i < INTERFACES_NUMBER; i++)
	{
		pcap_close(device_handle[i]);
	}

	
	return 0;
}

// Callback function invoked by libpcap/WinPcap for every incoming packet
void wifi_packet_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{
	ex_udp_datagram* rec_packet;
	rec_packet = new ex_udp_datagram(packet_header, packet_data);
	u_long ack_num = ntohl(*(rec_packet->seq_number));

	packet_mutex[ack_num].lock();
	packet_sent[ack_num] = true;
	packet_mutex[ack_num].unlock();

	/*stdout_mutex.lock();
	printf("WiFi: ACK number %d \n", ack_num);
	stdout_mutex.unlock();*/
}

void eth_packet_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{
	ex_udp_datagram* rec_packet;
	rec_packet = new ex_udp_datagram(packet_header, packet_data);
	u_long* ack_num = rec_packet->seq_number;

	ack_buffer[ntohl(*ack_num)] = true;

	stdout_mutex.lock();
	printf("Eth : ACK number %d \n", ntohl(*ack_num));
	stdout_mutex.unlock();
}

/* Split data to packets. Return number of packets created. */
void make_packets(unsigned char *input_data, unsigned char ***packets, unsigned char *udp_packet_data, struct pcap_pkthdr *udp_packet_header, unsigned int input_data_size, unsigned int packet_data_size)
{
	packets_num = ceil(double(input_data_size) / packet_data_size);
	*packets = new unsigned char*[packets_num];

	/* Help structures. */
	ex_udp_datagram *udp_d = new ex_udp_datagram(udp_packet_header, udp_packet_data);
	ip_header *iph;
	udp_header *uh;

	header_size = sizeof(ethernet_header) + udp_d->iph->header_length * 4 + sizeof(udp_header) + 4; //4 bytes for ACK num
	/* Total packet len = header size + raw data size. */
	total_packet_size = header_size + packet_data_size;
	last_packet_total_size = header_size + input_data_size - (packets_num - 1)*packet_data_size;

	for (int i = 0; i < packets_num-1; i++)
	{
		(*packets)[i] = new unsigned char[total_packet_size];
		/* Copy header from generic packet. */
		memcpy((*packets)[i], udp_packet_data, header_size);
		/* Copy raw data. */
		memcpy((*packets)[i] + header_size, input_data + i*packet_data_size, packet_data_size);
		/* Setting header fields which indicates packet size. */
		iph = (ip_header*)((*packets)[i] + sizeof(ethernet_header));
		uh = (udp_header*)((*packets)[i] + iph->header_length * 4 + sizeof(ethernet_header));
		iph->length = htons(total_packet_size - sizeof(ethernet_header));
		uh->datagram_length = htons(total_packet_size - iph->header_length * 4 - sizeof(ethernet_header));
		uh->src_port = htons(PORT_NUMBER);
		uh->dest_port = htons(PORT_NUMBER);
	}

	/* Last packet is smaller than others. */
	(*packets)[packets_num - 1] = new unsigned char[last_packet_total_size];
	/* Copy header from generic packet. */
	memcpy((*packets)[packets_num-1], udp_packet_data, header_size);
	/* Copy raw data. */
	memcpy((*packets)[packets_num-1] + header_size, input_data + (packets_num-1)*packet_data_size, last_packet_total_size - header_size);
	/* Setting header fields which indicates packet size. */
	iph = (ip_header*)((*packets)[packets_num - 1] + sizeof(ethernet_header));
	uh = (udp_header*)((*packets)[packets_num - 1] + iph->header_length * 4 + sizeof(ethernet_header));
	iph->length = htons(last_packet_total_size - sizeof(ethernet_header));
	uh->datagram_length = htons(last_packet_total_size - iph->header_length * 4 - sizeof(ethernet_header));
	uh->src_port = htons(PORT_NUMBER);
	uh->dest_port = htons(PORT_NUMBER);

	/* Creating data size packet for every interface. */
	for (int i = 0; i < INTERFACES_NUMBER; i++)
	{
		data_size_packet[i] = new unsigned char[header_size + sizeof(unsigned int)];
		/* Copy header from generic packet. */
		memcpy(data_size_packet[i], udp_packet_data, header_size);
		/* Copy raw data. */
		unsigned int *data_size = (unsigned int*)(data_size_packet[i] + header_size);
		*data_size = htonl(packets_num);
		/* Setting header fields which indicates packet size. */
		iph = (ip_header*)(data_size_packet[i] + sizeof(ethernet_header));
		uh = (udp_header*)(data_size_packet[i] + iph->header_length * 4 + sizeof(ethernet_header));
		iph->length = htons(header_size + sizeof(unsigned int) - sizeof(ethernet_header));
		uh->datagram_length = htons(header_size + sizeof(unsigned int) - iph->header_length * 4 - sizeof(ethernet_header));
		uh->src_port = htons(PORT_NUMBER);
		uh->dest_port = htons(PORT_NUMBER);

		/* Set data size packet ack number (0). */
		u_long *ack = (u_long *)(data_size_packet[i] + header_size - 4);
		*ack = htonl(0);
	}

	/* Enumerating packets (setting ACK nums in extended udp header). */
	u_long *ack;
	for (int i = 0; i < packets_num; i++)
	{
		ack = (u_long *) ((*packets)[i] + header_size - 4);
		*ack = htonl(i+1);
	}

	/* initialiting packets state (ACK received) buffer and its locks. 
	Size is packets_num+1 (one additional element for data_size packet. */
	packet_mutex = new mutex[packets_num+1];
	packet_sent = new bool[packets_num+1];

	for (int i = 0; i < packets_num; i++)
	{
		packet_sent[i] = false;
	}

	delete udp_d;
}

void set_addresses(unsigned char ** packets, unsigned int packets_num, unsigned char eth_src_addr[], unsigned char eth_dst_addr[], unsigned char ip_src_addr[], unsigned char ip_dst_addr[])
{
	ip_header *iph;
	ethernet_header *eh;
	for (int i = 0; i < packets_num; i++)
	{
		eh = (ethernet_header*)packets[i];
		iph = (ip_header*) (packets[i] + sizeof(ethernet_header));
		for (int i = 0; i < 6; i++)
		{
			eh->dest_address[i] = eth_dst_addr[i];
			eh->src_address[i] = eth_src_addr[i];
		}

		for (int i = 0; i < 4; i++)
		{
			iph->dst_addr[i] = ip_dst_addr[i];
			iph->src_addr[i] = ip_src_addr[i];
		}
	}
}

void calculate_checksum(unsigned char **packets, unsigned int packets_num)
{
	ip_header *iph;
	for (int i = 0; i < packets_num; i++)
	{
		iph = (ip_header*)(packets[i] + sizeof(ethernet_header));
		iph->checksum = 0;
		iph->checksum = ip_checksum(iph, iph->header_length * 4);
	}
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


void send_thread(pcap_t * device, unsigned char **send_data, unsigned int data_size, unsigned int id)
{
	ex_udp_datagram watch(data_size_packet[id]);
	
	pcap_pkthdr *recv_packet_header;
	unsigned char *recv_packet_data;

	int ret = -1;
	int backoff = 1000;
	//Sleep((id - 1) * 2000);
	/* Send data size. Send until ACK is received from client. */
	packet_mutex[0].lock();
	while (ret != 0 || packet_sent[0] == false)
	{
		packet_mutex[0].unlock();
		ret = pcap_sendpacket(device, data_size_packet[id], header_size + sizeof(unsigned int));
		Sleep(backoff);
		packet_mutex[0].lock();
		backoff += 100;
	}
	packet_mutex[0].unlock();



	for (int j = 0; j < data_size; j++)
	{
		/* Packet already sent. */
		packet_mutex[j + 1].lock();
		if (packet_sent[j + 1] == true)
		{
			packet_mutex[j + 1].unlock();
			continue;
		}
		packet_mutex[j+1].unlock();
		backoff = 1000;
		bool packet_ack = false;

		/* Sending packet. */
		while (true)
		{
			/* Last packet inside packet buffer. */
			if (j == packets_num - 1)
				ret = pcap_sendpacket(device, send_data[j], last_packet_total_size);
			else
				ret = pcap_sendpacket(device, send_data[j], total_packet_size);

			if (ret == -1)
			{
				stdout_mutex.lock();
				printf("Sending packet failed, interface has been disconnected!\n");
				stdout_mutex.unlock();
				Sleep(5000);
			}

			Sleep(backoff);
			backoff += 100;
			/* Retransmisson */
			/* Check packet state, it could be already sent by other interfaces. */
			packet_mutex[j + 1].lock();
			/* Lock packet again. */
			if (packet_sent[j + 1] == true)
			{
				packet_mutex[j + 1].unlock();
				break;
			}
			/* Send next packet. */
			else
			{
				packet_mutex[j + 1].unlock();
				continue;
			}
		}
	}

}


void send_thread2(pcap_t * device, unsigned char **send_data, unsigned int data_size, unsigned int id)
{
	ex_udp_datagram watch(send_data[0]);
	ex_udp_d->change_data_size(sizeof(unsigned int));

	/* Set raw packet data to output buffer size. */
	unsigned int *d_size = (unsigned int*) ex_udp_d->data;
	*d_size = htonl(data_size);

	/* Send data size. Send until ACK is received from client. */
	int ret = -1;
	ack_buff_mutex.lock();
	while (ret != 0 && ack_buffer[0] == false)
	{
		ack_buff_mutex.unlock();
		ret = pcap_sendpacket(device, packet_data, sizeof(udp_header) + ex_udp_d->iph->header_length * 4 + sizeof(ethernet_header) + 8);
		Sleep(100);
		ack_buff_mutex.lock();
	}
	ack_buff_mutex.unlock();

	int block_num = 0;
	int backoff;
	int window_pos = id* (packets_num / 2);

	for (int j = 0; j < ceil(float(data_size) / DATAGRAM_DATA_SIZE / BLOCK_SIZE); j++)
	{
		backoff = 100;
		/* Sending block of packets. */
		bool block_sent = false;
		while (!block_sent)
		{
			block_sent = true;
			for (int i = window_pos; i < window_pos + BLOCK_SIZE; i++)
			{
				/* Last block of packets may not be full. */
				if (i == id* (packets_num / 2) + data_size)
					break;

				ack_buff_mutex.lock();
				if (ack_buffer[i] == false)
				{
					ack_buff_mutex.unlock();
					block_sent = false;
					backoff += 100;
					stdout_mutex.lock();
					printf("Packet : %d not sent.\n", i);
					stdout_mutex.unlock();

					/* Last packet inside packet buffer. */
					/* window_pos*(id+1) - real position inside packet buffer. */
					if(i == packets_num-1)
						pcap_sendpacket(device, send_data[i-id*packets_num/2], last_packet_total_size);
					else
						pcap_sendpacket(device, send_data[i - id*packets_num / 2], total_packet_size);
				}
			}
			Sleep(backoff);
		}
		window_pos += BLOCK_SIZE;
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
		hdr_len -= 2;
	}
	
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	
	return(~sum);
}
