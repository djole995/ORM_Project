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

//unsigned char source_eth_addr[6] = { 0x78, 0x0c, 0xb8, 0xf7, 0x71, 0xa0 };
unsigned char source_eth_addr[6] = { 0x00, 0xe0, 0x4c, 0x36, 0x33, 0xf6 };
unsigned char dest_eth_addr[6] = { 0x2c, 0xd0, 0x5a, 0x90, 0xba, 0x9a };

//unsigned char source_ip_addr[4] = {192, 168, 0, 20};
unsigned char source_ip_addr[4] = { 10, 81, 2, 48 };
//unsigned char dest_ip_addr[4] = { 192, 168, 0, 10 };
unsigned char dest_ip_addr[4] = { 10, 81, 2, 59 };

/* ACK buffer. First element represent ACK for sent data size, others are ACKs for user datagrams. */
bool ack_buffer[2000];

/* Parallel output stream threads. */
thread *send_threads[INTERFACES_NUMBER];
/* Parallel input stream threads. */
thread *cap_threads[INTERFACES_NUMBER];

mutex mx;
mutex stdout_mutex;
mutex ack_buff_mutex;

mutex packet_mutex[2000];
bool packet_sent[2000];

/* Global pointer to data read from file and its lenght, initialized in initialize function.*/
unsigned char *file_buff;
long file_length;

/* Generic udp packet read from wireshark file. */
struct pcap_pkthdr* packet_header;
unsigned char* packet_data;

/* Packets created from read file data. */
unsigned char **packets;
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
	for (int i = 0; i < 2000; i++)
		packet_sent[i] = false;
	//eth_cap_thread = new thread(cap_thread);
	//eth_cap_thread->detach();
    int i=0;
    int device_number[INTERFACES_NUMBER];
    int sentBytes;
	pcap_if_t* devices;
	pcap_if_t* device;
	char error_buffer [PCAP_ERRBUF_SIZE];
	unsigned int netmask;
	int send_option;

	char filter_exp[] = "ip dst 10.81.2.48 and udp port 27015";
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
		if ((device_handle[j] = pcap_open_live(device->name, 65536, 1, 1000, error_buffer)) == NULL)
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
		if (pcap_compile(device_handle[j], &fcode, filter_exp, 1, netmask) < 0)
		{
			printf("\n Unable to compile the packet filter. Check the syntax.\n");
			return -1;
		}

		// Set the filter
		if (pcap_setfilter(device_handle[j], &fcode) < 0)
		{
			printf("\n Error setting the filter.\n");
			return -1;
		}
	}

	/* Read generic udp packet and read raw data file. */
	initiallize(&packet_header, &packet_data);
	/* Split file data into packes of DATAGRAM_DATA_SIZE size. */
	make_packets(file_buff, &packets, packet_data, packet_header, file_length, DATAGRAM_DATA_SIZE);

	ex_udp_datagram ex_udp_d2(packets[0]);

	ex_udp_d2 = ex_udp_datagram(packets[1]);

	for (int i = 0; i < packets_num; i++)
	{
			ex_udp_d2 = ex_udp_datagram(packets[i]);
			for (int j = 0; j < DATAGRAM_DATA_SIZE; j++)
			{
				printf("%c", ex_udp_d2.data[j]);
				
			}
			printf("\n%d", *ex_udp_d2.seq_number);
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

	/* Creating caputure thread for every interface. */
	/*for (int i = 0; i < INTERFACES_NUMBER; i++)
	{
		cap_threads[i] = new thread(cap_thread, device_handle[i], wifi_packet_handler);
		//eth_cap_thread = new thread(cap_thread, device_handle_eth, eth_packet_handler);
		cap_threads[i]->detach();
		//eth_cap_thread->detach();
	}*/

	/* Split send data on INTERFACES_NUMBER parts and start send threads. */
	for (int i = 0; i < INTERFACES_NUMBER; i++)
	{
		/*send_data[i] = packets + packets_num/2*i;
		data_size[i] = packets_num / 2 + i*(packets_num % 2);*/
		send_threads[i] = new thread(send_thread, device_handle[i], packets, packets_num, i);
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
	u_long* ack_num = rec_packet->seq_number;

	ack_buff_mutex.lock();
	ack_buffer[ntohl(*ack_num)] = true;
	ack_buff_mutex.unlock();

	stdout_mutex.lock();
	printf("WiFi: ACK number %d \n", ntohl(*ack_num));
	stdout_mutex.unlock();
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
	(*packets)[packets_num-1] = new unsigned char[last_packet_total_size];
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

	/* Enumerating packets (setting ACK nums in extended udp header). */
	u_long *ack;
	for (int i = 0; i < packets_num; i++)
	{
		ack = (u_long *) ((*packets)[i] + header_size - 4);
		*ack = i+1;
	}

	delete udp_d;
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
	ex_udp_datagram watch(send_data[0]);
	ex_udp_d->change_data_size(sizeof(unsigned int));
	
	pcap_pkthdr *recv_packet_header;
	unsigned char *recv_packet_data;

	int ret = -1;
	int backoff;

	for (int j = 0; j < data_size-id; j++)
	{
		packet_mutex[j+id].lock();
		/* Packet already sent. */
		if (packet_sent[j+id] == true)
		{
			packet_mutex[j+id].unlock();
			continue;
		}
		packet_sent[j+id] = true;
		packet_mutex[j+id].unlock();
			
		backoff = 0;
		bool packet_ack = false;

		while (!packet_ack)
		{
			/* Last packet inside packet buffer. */
			if (j+id == packets_num - 1)
				ret = pcap_sendpacket(device, send_data[j+id], last_packet_total_size);
			else
				ret = pcap_sendpacket(device, send_data[j+id], total_packet_size);

			if (ret == -1)
			{
				stdout_mutex.lock();
				printf("Sending packet failed, interface has been disconnected!\n");
				stdout_mutex.unlock();
				Sleep(1000);
			}
			else
			{
				/* Debug */
				packet_ack = true;
				/* ACK was not received. */
				if (pcap_next_ex(device, &recv_packet_header, (const u_char**) &recv_packet_data) != 1)
				{
					stdout_mutex.lock();
					printf("Receiving packet failed, interface has been disconnected!\n"); 
					stdout_mutex.unlock();
				}
				else
				{
					watch = ex_udp_datagram(recv_packet_data);
					/* Check ACK number. */
					if (*(watch.seq_number) == j+id)
					{
						/*packet_mutex[j].lock();
						packet_sent[j] = true;
						packet_mutex[j].unlock();*/
						stdout_mutex.lock();
						printf("ACK for packet %d received", *(watch.seq_number));
						stdout_mutex.unlock();
					}
					else
					{
						stdout_mutex.lock();
						printf("Wrong ACK received, packet : %d not sent.\n", j+id);
						stdout_mutex.unlock();
					}
				}
			}

			Sleep(backoff);
			backoff += 10;
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
	}
	
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	
	return(~sum);
}
