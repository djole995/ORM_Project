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

void packet_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data);
void eth_packet_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data);
/* Read recorded udp datagram. */
void initiallize(struct pcap_pkthdr** packet_header, unsigned char** packet_data);
void cap_thread(pcap_t *device, pcap_handler handler);

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

bool ack_buffer[BLOCK_SIZE];
bool wrong_ack_err = false;

//HANDLE hPcapLoopThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)PcapLoopThread, NULL, 0, 0);
HANDLE start_pcap_loop_event = CreateEvent(NULL, TRUE, FALSE, NULL);

thread *wifi_cap_thread;
thread *eth_cap_thread;
condition_variable wifi_cap_wait;
condition_variable eth_cap_wait;
mutex mx;
mutex stdout_mutex;

//DJOKARA VOLI BILJU 
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
	struct pcap_pkthdr* packet_header;
	unsigned char* packet_data;
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

	ex_udp_datagram *ex_udp_d = new ex_udp_datagram(packet_header, packet_data);
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

	unsigned int sum = 0;
	int tmp2 = 0;
	int offset = 2;
	unsigned short *addr;
	for (int i = 0; i < 9; i++) 
	{
		addr =(unsigned short*) ex_udp_d->iph + i*offset;
		sum += *addr;
	}

	int first_short = 0xf000 & sum;
	int last_short = 0x0fff & sum;

	tmp2 = first_short + last_short;
	sum = ~tmp2;

	int tmp = ntohs(ex_udp_d->uh->datagram_length) - sizeof(udp_header);
	*(ex_udp_d->seq_number) = 0;

	wifi_cap_thread = new thread(cap_thread, device_handle_wifi, packet_handler);
	//eth_cap_thread = new thread(cap_thread, device_handle_eth, eth_packet_handler);
	wifi_cap_thread->detach();
	//eth_cap_thread->detach();

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
				*(ex_udp_d->seq_number) = i;
				pcap_sendpacket(device_handle_wifi, packet_data, packet_header->len);
			}
		Sleep(backoff);
	}

	
	pcap_close(device_handle_wifi);
	pcap_close(device_handle_eth);

	
	return 0;
}

// Callback function invoked by libpcap/WinPcap for every incoming packet
void packet_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
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
	char error_buffer[PCAP_ERRBUF_SIZE];

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
