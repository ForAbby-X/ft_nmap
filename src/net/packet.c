/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   packet.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: alde-fre <alde-fre@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/08/07 11:08:10 by alde-fre          #+#    #+#             */
/*   Updated: 2024/09/04 12:31:15 by alde-fre         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "net.h"

#include <arpa/inet.h>


uint32_t	randseed = 0x42424242;

void	net_srand_u32(uint32_t a)
{
	randseed = a;
}

uint32_t	net_rand_u32(uint32_t a)
{
	a = (a ^ 61) ^ (a >> 16);
	a = a + (a << 3);
	a = a ^ (a >> 4);
	a = a * 0x27d4eb2d;
	a = a ^ (a >> 15);
	return (a);
}

uint16_t	data_checksum(uint16_t *addr, uint32_t count)
{
	register uint32_t sum = 0;

	while (count >= 2)
	{
		sum += *addr;
		++addr;
		count -= 2;
	}

	if (count > 0)
		sum += htons(*addr) & 0xff;

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return (~sum);
}

/*
*	@brief Create an IP header with the given parameters
*	@note Does not calculate the total length
*/
t_ip_header		ip_header_create(uint32_t source_ip_address, uint32_t destination_ip_address, uint8_t protocol)
{
	t_ip_header	ip_header;

	ip_header = (t_ip_header){0};
	ip_header.ihl = 5;													// the header length is 5 times 32 bits (20 bytes) because we don't use any options
	ip_header.version = 4;
	ip_header.tos = 0;
	ip_header.tot_len = htons(sizeof(t_ip_header) + sizeof(t_tcp_header));		// the total length of the full packets in bytes, the value here is pre calculated for the TCP header
	ip_header.id = htons(0);													// the identification number, arbitrary in our case mostly because it is used for fragmentation
	ip_header.frag_off = htons(0);												// the fragmentation offset, 0 here because we don't fragment the packet
	ip_header.ttl = 255;												// the number of time the packet can travers a network node before being dropped
	ip_header.protocol = protocol;										// the protocol is used to define the type of the data part of the packet
	ip_header.check = htons(0);
	ip_header.saddr = htonl(source_ip_address);
	ip_header.daddr = htonl(destination_ip_address);
	
	ip_header.check = htons(data_checksum((uint16_t *)&ip_header, ip_header.ihl << 2));

	return (ip_header);
}

struct s_pseudo_header
{
	uint32_t	saddr;
	uint32_t	daddr;
	uint8_t		zero;
	uint8_t		protocol;
	uint16_t	tcp_len;
};

/*
*	@brief Create a TCP header with the given parameters
*	@note The full net socket is needed here to calculate the checksum
*/
t_tcp_header	tcp_header_create(t_net_flags const flags, t_net_socket source_net_socket, t_net_socket destination_net_socket)
{
	/*
	*	This buffer exist for the sole purpose of calculating the checksum of the TCP header
	*	The TCP evolved and now for unnecessary security resons the checksum is calculated
	*	 by adding a pseudo header to the TCP header
	*/
	uint8_t tcp_header_buffer[sizeof(struct s_pseudo_header) + sizeof(t_tcp_header)] = {0};

	struct s_pseudo_header *pseudo_header = (struct s_pseudo_header *)(tcp_header_buffer);

	pseudo_header->saddr = htonl(source_net_socket.address);
	pseudo_header->daddr = htonl(destination_net_socket.address);
	pseudo_header->zero = 0;
	pseudo_header->protocol = IPPROTO_TCP;
	pseudo_header->tcp_len = htons(sizeof(t_tcp_header));

	t_tcp_header	*tcp_header = (t_tcp_header *)(tcp_header_buffer + sizeof(struct s_pseudo_header));

	tcp_header->source = htons(source_net_socket.port);
	tcp_header->dest = htons(destination_net_socket.port);
	tcp_header->seq = htons(0);
	tcp_header->ack_seq = htonl(0);
	tcp_header->doff = htons(5);									// the header length is 5 times 32 bits (20 bytes) because we don't use any options nor data
	tcp_header->fin = htons(TCP_GET_FLAGS(flags, TCP_FLAG_FIN));	// the FIN flag is set if the connection is closed
	tcp_header->syn = htons(TCP_GET_FLAGS(flags, TCP_FLAG_SYN));	// the SYN flag is set if the connection is initiated
	tcp_header->rst = htons(TCP_GET_FLAGS(flags, TCP_FLAG_RST));	// the RST flag is set if the connection is reset
	tcp_header->psh = htons(TCP_GET_FLAGS(flags, TCP_FLAG_PSH));	// the PSH flag is set if the data is pushed to the application
	tcp_header->ack = htons(TCP_GET_FLAGS(flags, TCP_FLAG_ACK));	// the ACK flag is set if the packet is an acknowledgment
	tcp_header->urg = htons(TCP_GET_FLAGS(flags, TCP_FLAG_URG));	// the URG flag is set if the packet is urgent
	tcp_header->window = htons(5840);
	tcp_header->check = htons(0);
	tcp_header->urg_ptr = htons(0);

	tcp_header->check = htons(data_checksum((uint16_t *)tcp_header_buffer, sizeof(tcp_header_buffer)));

	return (*tcp_header);
}

t_tcp_packet		tcp_packet_create(t_net_socket source_net_socket, t_net_socket destination_net_socket, uint8_t protocol, t_net_flags flags)
{
	t_tcp_packet	tcp_packet;

	tcp_packet.ip_header = ip_header_create(source_net_socket.address, destination_net_socket.address, protocol);
	tcp_packet.tcp_header = tcp_header_create(flags, source_net_socket, destination_net_socket);

	return (tcp_packet);
}

void	tcp_packet_display(t_tcp_packet *const packet)
{
	char 	char_buffer[512] = {0};
	size_t	char_len = 0;

	char_len += sprintf(char_buffer + char_len, "IP HEADER\n");
	char_len += sprintf(char_buffer + char_len, "	ihl = %d\n", packet->ip_header.ihl);
	char_len += sprintf(char_buffer + char_len, "	version = %d\n", packet->ip_header.version);
	char_len += sprintf(char_buffer + char_len, "	tos = %d\n", packet->ip_header.tos);
	char_len += sprintf(char_buffer + char_len, "	tot_len = %d\n", packet->ip_header.tot_len);
	char_len += sprintf(char_buffer + char_len, "	id = %d\n", packet->ip_header.id);
	char_len += sprintf(char_buffer + char_len, "	frag_off = %d\n", packet->ip_header.frag_off);

	char_len += sprintf(char_buffer + char_len, "	ttl = %d\n", packet->ip_header.ttl);
	char_len += sprintf(char_buffer + char_len, "	protocol = %d\n", packet->ip_header.protocol);
	char_len += sprintf(char_buffer + char_len, "	check = %d\n", packet->ip_header.check);
	// char_len += sprintf(char_buffer + char_len, "	saddr = %s\n", inet_ntoa(*(struct in_addr *)&packet->ip_header.saddr));
	// char_len += sprintf(char_buffer + char_len, "	daddr = %s\n", inet_ntoa(*(struct in_addr *)&packet->ip_header.daddr));
	
	char_len += sprintf(char_buffer + char_len, "	TCP HEADER\n");
	char_len += sprintf(char_buffer + char_len, "		source = %d\n", packet->tcp_header.source);
	char_len += sprintf(char_buffer + char_len, "		dest = %d\n", packet->tcp_header.dest);
	char_len += sprintf(char_buffer + char_len, "		seq = %d\n", packet->tcp_header.seq);
	char_len += sprintf(char_buffer + char_len, "		ack_seq = %d\n", packet->tcp_header.ack_seq);
	char_len += sprintf(char_buffer + char_len, "		doff = %d\n", packet->tcp_header.doff);
	char_len += sprintf(char_buffer + char_len, "		fin = %d\n", packet->tcp_header.fin);
	char_len += sprintf(char_buffer + char_len, "		syn = %d\n", packet->tcp_header.syn);
	char_len += sprintf(char_buffer + char_len, "		rst = %d\n", packet->tcp_header.rst);
	char_len += sprintf(char_buffer + char_len, "		psh = %d\n", packet->tcp_header.psh);
	char_len += sprintf(char_buffer + char_len, "		ack = %d\n", packet->tcp_header.ack);
	char_len += sprintf(char_buffer + char_len, "		urg = %d\n", packet->tcp_header.urg);
	char_len += sprintf(char_buffer + char_len, "		window = %d\n", packet->tcp_header.window);
	char_len += sprintf(char_buffer + char_len, "		check = %d\n", packet->tcp_header.check);
	char_len += sprintf(char_buffer + char_len, "		urg_ptr = %d\n", packet->tcp_header.urg_ptr);

	fwrite(char_buffer, 1, char_len, stdout);
	printf("charlen: %zu\n", char_len);
}

