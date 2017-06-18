#pragma once

#include "protocol_headers.h"

char* convert_sockaddr_to_string(struct sockaddr* address)
{
	return (char *)inet_ntoa(((struct sockaddr_in *) address)->sin_addr);
}

/*void set_filter_exp(unsigned char **filter_exp, pacp_if_t *device)
{
	//26
	char tmp[] = "udp port 27015 and ip dst ";

	*filter_exp = new unsigned char[]
}*/

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

