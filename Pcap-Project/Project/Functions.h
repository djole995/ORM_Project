#pragma once
#include "protocol_headers.h"

using namespace std;

char* convert_sockaddr_to_string(struct sockaddr* address)
{
	return (char *)inet_ntoa(((struct sockaddr_in *) address)->sin_addr);
}

char *get_interface_addr(pcap_if_t *dev)
{
	pcap_addr_t *addr;

	// IP addresses
	for (addr = dev->addresses; addr; addr = addr->next)
	{
		if (addr->addr->sa_family == AF_INET)
		{
			if (addr->addr != NULL)
			{
				return convert_sockaddr_to_string(addr->addr);
			}
		}
	}
}

void get_addresses(pcap_if_t *device, unsigned char ip_addr[][4], unsigned char eth_addr[][6], 
	unsigned char server_ip_addr[][4],  int id)
{
	char input[19];
	char server_addr[16];
	unsigned int eth_tmp[6];
	if (id == 0)
	{
		printf("Enter client WiFi mac address (format : xx:xx:xx:xx:xx:xx) : \n");
		scanf("%s", input);
		printf("Enter server WiFi IP address (format : xxx.xxx.xxx.xxx) : \n");
		scanf("%s", server_addr);
	}
	else
	{
		printf("Enter client ethernet mac address (format : xx:xx:xx:xx:xx:xx) : \n");
		scanf("%s", input);
		printf("Enter server ethernet IP address (format : xxx.xxx.xxx.xxx) : \n");
		scanf("%s", server_addr);
	}

	sscanf(input, "%02x:%02x:%02x:%02x:%02x:%02x", &eth_tmp[0], &eth_tmp[1], &eth_tmp[2], &eth_tmp[3], 
		&eth_tmp[4], &eth_tmp[5]);

	for (int i = 0; i < 6; i++)
		eth_addr[id][i] = (unsigned char)eth_tmp[i];

	char *ip_addr_str = get_interface_addr(device);
	sscanf(ip_addr_str, "%hhu.%hhu.%hhu.%hhu", &ip_addr[id][0], &ip_addr[id][1], &ip_addr[id][2], &ip_addr[id][3]);
	sscanf(server_addr, "%hhu.%hhu.%hhu.%hhu", &server_ip_addr[id][0], &server_ip_addr[id][1], 
		&server_ip_addr[id][2], &server_ip_addr[id][3]);
}

void set_filter_exp(char **filter_exp, pcap_if_t *device, unsigned int portNumber)
{
	char portNumStr[] = "00000";
	sprintf(portNumStr, "%u", portNumber);
	string filter_exp_tmp("udp dst port ");

	filter_exp_tmp += string(portNumStr);
	filter_exp_tmp += " and ip dst ";
	filter_exp_tmp += string(get_interface_addr(device));
	
	*filter_exp = new char[filter_exp_tmp.size()];
	strcpy(*filter_exp, filter_exp_tmp.data());

	//printf("%s\n", *filter_exp);
}

//! \brief Calculate the IP header checksum.
//! \param buf The IP header content.
//! \param hdr_len The IP header length.
//! \return The result of the checksum.
uint16_t ip_checksum(const void *buf, size_t hdr_len)
{
	unsigned long sum = 0;
	const uint16_t *ip1;

	ip1 = (const uint16_t *)buf;
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


/* Calculates IPv4 checksum for packets_num packets. */
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

/* Sets packets source and destination addresses. */
void set_addresses(unsigned char ** packets, unsigned int packets_num, unsigned char eth_src_addr[], unsigned char eth_dst_addr[], unsigned char ip_src_addr[], unsigned char ip_dst_addr[])
{
	ip_header *iph;
	ethernet_header *eh;
	for (int i = 0; i < packets_num; i++)
	{
		eh = (ethernet_header*)packets[i];
		iph = (ip_header*)(packets[i] + sizeof(ethernet_header));
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

