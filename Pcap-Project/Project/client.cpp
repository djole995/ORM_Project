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
#include "Functions.h"


using namespace std;
using namespace chrono;

/* Packet handlers for captured packets on ethernet and wifi adapters. */
void packet_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data);

/* Read recorded udp datagram. */
void initiallize(struct pcap_pkthdr** packet_header, unsigned char** packet_data);

/* Capture packets on device which are processed with given packet handler. */
void cap_thread(pcap_t *device, pcap_handler handler);

/* Send data throught given device. */
void send_thread(pcap_t *device, unsigned char** send_data, unsigned int data_size, unsigned int id);

/* Split data into packets of choosen size and initiallize some global variables. */
void make_packets(unsigned char *input_data, unsigned char ***packets, unsigned char *udp_packet_data, 
	struct pcap_pkthdr *udp_packet_header, unsigned int data_size, unsigned int packet_data_size);
/* Free dynamically allocated memory. */
void free_resources();

const int DATAGRAM_DATA_SIZE = 1465;
const int INTERFACES_NUMBER = 2;
const int PORT_NUMBER = 27015;

/* device_handle_in - recorded pcap file, opened in offline mode. */
/* device_handle_out - output device (wi-fi or ethernet adapter). */
pcap_t* device_handle[INTERFACES_NUMBER];

/* Server and client mac and ip addresses. */
unsigned char server_mac_addr[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
/* Client and server ip addresses and client mac addresses, user sets when program starts. */
unsigned char client_mac_addr[INTERFACES_NUMBER][6] = { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };
unsigned char server_ip_addr[INTERFACES_NUMBER][4] = { { 0, 0, 0, 0 },{ 0, 0, 0, 0 } };
unsigned char client_ip_addr[INTERFACES_NUMBER][4] = { {0, 0, 0, 0}, { 0, 0, 0, 0 } };


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
mutex *packet_send_lock;
/* packet status (received or not received). */
bool *packet_sent;

/* Size of packet including headers, size of extended header itself and number of created packets
, all initialized in make_packets function. */
unsigned int total_packet_size;
/* Last packet may be smaller than others. */
unsigned int last_packet_total_size;
/* Number of packets created, initiallized in make packets functions. */
unsigned int packets_num;
unsigned int header_size;

ex_udp_datagram* ex_udp_d;

/* Data sent via wifi and ethernet. */
unsigned char **send_data[INTERFACES_NUMBER];

/* Number of packets sent by every network interface, used for statistics. */
unsigned int eth_packet_cnt = 0;
unsigned int wifi_packet_cnt = 0;

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
	char *filter_exp[INTERFACES_NUMBER] = {"udp port 27015 and ip dst 10.81.2.93", "udp port 27015 and ip dst 169.254.176.100" };
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

	// Pick one device from the list
	printf("\t\tEnter the output interfaces number (1-%d):\n",i);
	
	printf("Enter WiFi interface number: ");
	scanf("%d", &device_number[0]);
	printf("Enter Ethernet interface number: ");
	scanf("%d", &device_number[1]);

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

		
		get_addresses(device, client_ip_addr, client_mac_addr, server_ip_addr, j);
		set_filter_exp(&filter_exp[j], device, PORT_NUMBER);

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
		set_addresses(packets[i], packets_num, client_mac_addr[i], server_mac_addr, client_ip_addr[i], server_ip_addr[i]);
		set_addresses(&data_size_packet[i], 1, client_mac_addr[i], server_mac_addr, client_ip_addr[i], server_ip_addr[i]);
		calculate_checksum(packets[i], packets_num);
		calculate_checksum(&data_size_packet[i], 1);
	}

	for (int i = 0; i < INTERFACES_NUMBER; i++)
	{
		/* Set addresses and calculate checksum for data size packet. */
		set_addresses(&data_size_packet[i], 1, client_mac_addr[i], server_mac_addr, client_ip_addr[i], server_ip_addr[i]);
		calculate_checksum(&data_size_packet[i], 1);
	}

	/* Creating caputure thread for every interface. */
	for (int i = 0; i < INTERFACES_NUMBER; i++)
	{
		cap_threads[i] = new thread(cap_thread, device_handle[i], packet_handler);
		cap_threads[i]->detach();
	}

	system_clock::time_point start = system_clock::now();
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

	system_clock::time_point stop = system_clock::now();

	/* Mesaure send time. */
	duration<double> send_time = stop - start;

	printf("All packets sent in %lf seconds.\n", send_time.count());

	printf("Number of packets sent via ethernet : %d\n", eth_packet_cnt);
	printf("Number of packets sent via wifi : %d\n", wifi_packet_cnt);
	
	for (int i = 0; i < INTERFACES_NUMBER; i++)
	{
		pcap_close(device_handle[i]);
	}

	free_resources();

	return 0;
}

// Callback function invoked by libpcap/WinPcap for every incoming packet
void packet_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{
	ex_udp_datagram* rec_packet;
	rec_packet = new ex_udp_datagram(packet_header, packet_data);
	u_long ack_num = ntohl(*(rec_packet->seq_number));

	unsigned short checksum = rec_packet->iph->checksum;
	rec_packet->iph->checksum = 0;
	if (ip_checksum(rec_packet->iph, rec_packet->iph->header_length*4) != checksum)
	{
		return;
	}

	packet_mutex[ack_num].lock();
	if (packet_sent[ack_num] == false)
	{
		if (rec_packet->iph->dst_addr[0] == 169)
			eth_packet_cnt++;
		else
			wifi_packet_cnt++;
	}
	packet_sent[ack_num] = true;
	packet_mutex[ack_num].unlock();

	
}

/* Split data to packets. */
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
	packet_send_lock = new mutex[packets_num];
	packet_sent = new bool[packets_num+1];

	/* initiallize packets ACK buffer (all unconfirmed). */
	for (int i = 0; i < packets_num; i++)
	{
		packet_sent[i] = false;
	}

	delete udp_d;
}

void free_resources()
{
	delete packet_sent;

	for (int i = 0; i < INTERFACES_NUMBER; i++)
	{
		for (int j = 0; j < packets_num; j++)
			delete packets[i][j];
		delete[] packets[i];

		delete cap_threads[i];
		delete send_threads[i];
		delete data_size_packet[i];
	}

	delete file_buff;
}

void initiallize(struct pcap_pkthdr** packet_header, unsigned char** packet_data) 
{
	pcap_t* device_handle_i;
	FILE *data_file;
	char error_buffer[PCAP_ERRBUF_SIZE];

	data_file = fopen("sample_and_hold_4x4.png", "rb+");

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
	fclose(data_file);
	
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
	ex_udp_datagram ex_udp_d(send_data[0]);
	int ret = -1;
	int backoff = 100;
	int speed_test = 100;
	/* Send data size. Send until ACK is received from client. */
	packet_mutex[0].lock();
	while (ret != 0 || packet_sent[0] == false)
	{
		packet_mutex[0].unlock();
		ret = pcap_sendpacket(device, data_size_packet[id], header_size + sizeof(unsigned int));
		this_thread::sleep_for(milliseconds(speed_test));
		speed_test += 400;
		/* Interface is disconnected. */
		if (speed_test > 20000)
		{
			stdout_mutex.lock();
			printf("Send via interface with id %d failed.\n", id);
			stdout_mutex.unlock();
			return;
		}
		packet_mutex[0].lock();	
	}
	packet_mutex[0].unlock();

	for (int j = id; j < data_size; j++)
	{
		/* Check whether packet is already being sent by other network interface. */
		if (!packet_send_lock[j].try_lock())
			continue;
		/* Packet already sent. */
		packet_mutex[j + 1].lock();
		if (packet_sent[j + 1] == true)
		{
			packet_mutex[j + 1].unlock();
			packet_send_lock[j].unlock();
			continue;
		}
		packet_mutex[j+1].unlock();
		backoff = speed_test;

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
				packet_send_lock[j].unlock();
				stdout_mutex.lock();
				printf("Sending packet failed, interface has been disconnected!\n");
				stdout_mutex.unlock();
				this_thread::sleep_for(milliseconds(4000));
				packet_send_lock[j].lock();
			}

			/* Interface slow -> allow other interfaces to send same packet. */
			if(backoff > 1000)
				packet_send_lock[j].unlock();

			this_thread::sleep_for(milliseconds(backoff));
			backoff += 400;

			if (backoff > 1400)
				packet_send_lock[j].lock();

			/* Client or interface is probably disconnected. */
			if (backoff > 3000 && ret == 0)
			{
				packet_send_lock[j].unlock();
				break;
			}
			/* Retransmisson */
			/* Check packet state, it could be already sent by other interfaces. */
			packet_mutex[j + 1].lock();
			/* Lock packet again. */
			if (packet_sent[j + 1] == true)
			{
				/* Try sending next packet. */
				packet_send_lock[j].unlock();
				packet_mutex[j + 1].unlock();
				break;
			}
			/* Continue sending packet. */
			else
			{
				packet_mutex[j + 1].unlock();
				continue;
			}
		}
	}
		
	/* Checking whether other interface was in sending packet procedure when disconnected. */
	for (int j = 0; j < data_size; j++)
	{
		backoff = speed_test;

		/* Packet already sent. */
		packet_mutex[j + 1].lock();
		if (packet_sent[j + 1] == true)
		{
			packet_mutex[j + 1].unlock();
			continue;
		}
		packet_mutex[j + 1].unlock();

		packet_send_lock[j].lock();

		backoff = speed_test;

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
				packet_send_lock[j].unlock();
				stdout_mutex.lock();
				printf("Sending packet failed, interface has been disconnected\n");
				stdout_mutex.unlock();
				this_thread::sleep_for(milliseconds(4000));
				packet_send_lock[j].lock();
			}

			/* Interface slow -> allow other interfaces to send same packet. */
			if (backoff > 2000)
				packet_send_lock[j].unlock();

			this_thread::sleep_for(milliseconds(backoff));
			backoff += 400;

			if (backoff > 2400)
				packet_send_lock[j].lock();

			/* Client is probably disconnected. */
			if (backoff > 3000 && ret == 0)
			{
				packet_send_lock[j].unlock();
				break;
			}
			/* Retransmisson */
			/* Check packet state, it could be already sent by other interfaces. */
			packet_mutex[j + 1].lock();
			/* Lock packet again. */
			if (packet_sent[j + 1] == true)
			{
				/* Try sending next packet. */
				packet_send_lock[j].unlock();
				packet_mutex[j + 1].unlock();
				break;
			}
			/* Continue sending packet. */
			else
			{
				packet_mutex[j + 1].unlock();
				continue;
			}
		}
	}
}



