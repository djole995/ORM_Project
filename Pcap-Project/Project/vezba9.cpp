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

#include <pcap.h>
#include "protocol_headers.h"

void packet_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data);
/* Read recorded udp datagram. */
void initiallize(struct pcap_pkthdr** packet_header, unsigned char** packet_data);

/* device_handle_in - recorded pcap file, opened in offline mode. */
/* device_handle_out - output device (wi-fi or ethernet adapter). */
pcap_t* device_handle_in, *device_handle_out;

int main()
{
    int i=0;
    int device_number;
    int sentBytes;
	pcap_if_t* devices;
	pcap_if_t* device;
	char error_buffer [PCAP_ERRBUF_SIZE];
	unsigned char packet[256];
	struct pcap_pkthdr* packet_header;
	unsigned char* packet_data;



	/*//Destination MAC address
	pack.eh.dest_address[0] = 0x2c;
	pack.eh.dest_address[1] = 0xd0;
	pack.eh.dest_address[2] = 0x5a;
	pack.eh.dest_address[3] = 0x90;
	pack.eh.dest_address[4] = 0xba;
	pack.eh.dest_address[5] = 0x9a;*/

	//Source MAC address
/*	pack.eh.src_address[0] = 0x78;
	pack.eh.src_address[1] = 0x0c;
	pack.eh.src_address[2] = 0xb8;
	pack.eh.src_address[3] = 0xf7;
	pack.eh.src_address[4] = 0x71;
	pack.eh.src_address[5] = 0xa0;

	pack.eh.dest_address[0] = 0x78;
	pack.eh.dest_address[1] = 0x0c;
	pack.eh.dest_address[2] = 0xb8;
	pack.eh.dest_address[3] = 0xf7;
	pack.eh.dest_address[4] = 0x71;
	pack.eh.dest_address[5] = 0xa0;

	pack.eh.type = 0x0800;

	pack.iph.dst_addr[0] = 192;
	pack.iph.dst_addr[1] = 168;
	pack.iph.dst_addr[2] = 0;
	pack.iph.dst_addr[3] = 20;

	pack.iph.src_addr[0] = 192;
	pack.iph.src_addr[1] = 168;
	pack.iph.src_addr[2] = 0;
	pack.iph.src_addr[3] = 20;

	pack.iph.header_length = 5;
	pack.iph.length = sizeof(ip_header) + sizeof(ethernet_header)+100;
	pack.iph.fragm_flags = 0;
	pack.iph.fragm_offset = 0;
	pack.iph.tos = 0;
	pack.iph.next_protocol = 17;
	pack.iph.version = 4;
	pack.iph.ttl = 30;

	for (int i = 0; i < 100; i++)
		pack.data[i] = 0;
		*/

/*	//Header length
	packet[12] = 5;
	//Version
	packet[13] = 4;
	//Type of service
	packet[14] = 0;
	//Total length
	packet[15] = 41;
	packet[16] = 0;
	//Identification
	packet[17] = 0;
	packet[18] = 0;
	//Fragments
	packet[19] = 0;
	packet[20] = 0;
	//TTL
	packet[21] = 30;
	// Next Protocol - UDP
	packet[22] = 17;
	//Checksum
	packet[23] = 0;
	packet[24] = 0;
	// Source IP address*/

	
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
	printf("Enter the output interface number (1-%d):",i);
	scanf("%d", &device_number);

	if(device_number < 1 || device_number > i)
	{
		printf("\nInterface number out of range.\n");
		return -1;
	}

	// Select the first device...
	device=devices;
	// ...and then jump to chosen devices
	for (i=0; i<device_number-1; i++)
	{
		device=device->next;
	}

	/**************************************************************/
	// Open the capture file 
	/*if ((device_handle_in = pcap_open_offline("example.pcap",	// File name 
								error_buffer					// Error buffer
	   )) == NULL)
	{
		printf("\n Unable to open the file %s.\n", "example.pcap");
		return -1;
	}*/
	/**************************************************************/

	/**************************************************************/
	// Open the output adapter 
	if ((device_handle_out = pcap_open_live(device->name, 65536, 1, 1000, error_buffer)) == NULL)
	{
		printf("\n Unable to open adapter %s.\n", device->name);
		return -1;
	}
	
	// Check the link layer. We support only Ethernet for simplicity.
	if(pcap_datalink(device_handle_out) != DLT_EN10MB)
	{
		printf("\nThis program works only on Ethernet networks.\n");
		return -1;
	}

	initiallize(&packet_header, &packet_data);

	ex_udp_datagram *ex_udp_d = new ex_udp_datagram(packet_header, packet_data);

	ex_udp_d->eh->src_address[0] = 0x78;
	ex_udp_d->eh->src_address[1] = 0x0c;
	ex_udp_d->eh->src_address[2] = 0xb8;
	ex_udp_d->eh->src_address[3] = 0xf7;
	ex_udp_d->eh->src_address[4] = 0x71;
	ex_udp_d->eh->src_address[5] = 0xa0;

	ex_udp_d->eh->dest_address[0] = 0x2c;
	ex_udp_d->eh->dest_address[1] = 0xd0;
	ex_udp_d->eh->dest_address[2] = 0x5a;
	ex_udp_d->eh->dest_address[3] = 0x90;
	ex_udp_d->eh->dest_address[4] = 0xba;
	ex_udp_d->eh->dest_address[5] = 0x9a;

	ex_udp_d->iph->dst_addr[0] = 192;
	ex_udp_d->iph->dst_addr[1] = 168;
	ex_udp_d->iph->dst_addr[2] = 0;
	ex_udp_d->iph->dst_addr[3] = 10;

	ex_udp_d->iph->src_addr[0] = 192;
	ex_udp_d->iph->src_addr[1] = 168;
	ex_udp_d->iph->src_addr[2] = 0;
	ex_udp_d->iph->src_addr[3] = 20;

	ex_udp_d->seq_number = 0;

	for(int i = 0; i < 100; i++)
		pcap_sendpacket(device_handle_out, packet_data, packet_header->len);


	/*while (1)
	{
		pcap_sendpacket(device_handle_out, &pack, sizeof(ex_udp_datagram));
		Sleep(100);
	}*/
	
	pcap_close(device_handle_out);

	return 0;
}

// Callback function invoked by libpcap/WinPcap for every incoming packet
void packet_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{
	// Retrieve position of ethernet_header
	ethernet_header* eh;
    eh = (ethernet_header*)packet_data;

	eh->src_address[0] = 0x78;
	eh->src_address[1] = 0x0c;
	eh->src_address[2] = 0xb8;
	eh->src_address[3] = 0xf7;
	eh->src_address[4] = 0x71;
	eh->src_address[5] = 0xa0;

	eh->dest_address[0] = 0x2c;
	eh->dest_address[1] = 0xd0;
	eh->dest_address[2] = 0x5a;
	eh->dest_address[3] = 0x90;
	eh->dest_address[4] = 0xba;
	eh->dest_address[5] = 0x9a;

	//pack.eh.type = 0x0800;

	// Check the type of next protocol in packet
	if (ntohs(eh->type) == 0x800)	// Ipv4
	{
		ip_header* ih;
        ih = (ip_header*)(packet_data + sizeof(ethernet_header));

		ih->dst_addr[0] = 192;
		ih->dst_addr[1] = 168;
		ih->dst_addr[2] = 0;
		ih->dst_addr[3] = 10;

		ih->src_addr[0] = 192;
		ih->src_addr[1] = 168;
		ih->src_addr[2] = 0;
		ih->src_addr[3] = 20;

		if(ih->next_protocol == 17) // UDP
		{
			/**************************************************************/
			// Add packet in the queue
			for(int i = 0; i < 100; i++)
				pcap_sendpacket(device_handle_out, packet_data, packet_header->len);
			/**************************************************************/
		}
	}
}

void initiallize(struct pcap_pkthdr** packet_header, unsigned char** packet_data) 
{
	pcap_t* device_handle_i;
	char error_buffer[PCAP_ERRBUF_SIZE];
	
	if ((device_handle_i = pcap_open_offline("example.pcap",	// File name 
		error_buffer					// Error buffer
	)) == NULL)
	{
		printf("\n Unable to open the file %s.\n", "udp_packets.pcap");
		return;
	}


	pcap_next_ex(device_handle_i, packet_header, (const u_char**)packet_data);

	/*ethernet_header* eh;
	eh = (ethernet_header*)packet_data;*/

	/*eh->src_address[0] = 0x78;
	eh->src_address[1] = 0x0c;
	eh->src_address[2] = 0xb8;
	eh->src_address[3] = 0xf7;
	eh->src_address[4] = 0x71;
	eh->src_address[5] = 0xa0;

	eh->dest_address[0] = 0x2c;
	eh->dest_address[1] = 0xd0;
	eh->dest_address[2] = 0x5a;
	eh->dest_address[3] = 0x90;
	eh->dest_address[4] = 0xba;
	eh->dest_address[5] = 0x9a;*/

	/*if (ntohs(eh->type) == 0x800)	// Ipv4
	{
		ip_header* ih;
		ih = (ip_header*)(packet_data + sizeof(ethernet_header));*/

		/*ih->dst_addr[0] = 192;
		ih->dst_addr[1] = 168;
		ih->dst_addr[2] = 0;
		ih->dst_addr[3] = 10;

		ih->src_addr[0] = 192;
		ih->src_addr[1] = 168;
		ih->src_addr[2] = 0;
		ih->src_addr[3] = 20;*/

		/*if (ih->next_protocol == 17) // UDP
			// Add packet in the queue
			for (int i = 0; i < 100; i++)
				pcap_sendpacket(device_handle_out, *packet_data, (*packet_header)->len);*/
	//}

	
}