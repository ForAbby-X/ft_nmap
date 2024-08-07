/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: alde-fre <alde-fre@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/08/04 16:19:12 by alde-fre          #+#    #+#             */
/*   Updated: 2024/08/07 18:11:40 by alde-fre         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <pthread.h>
#include <errno.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#include "ft_nmap/ft_nmap.h"
#include "vector.h"

/// MANAGER FUNCTIONS ///

static inline int	__nmap_scan_create(t_nmap *const nmap, t_nmap_options const *const options)
{
	*nmap = (t_nmap){0};

	// threads array
	nmap->threads = vector_create_s(sizeof(t_nmap_thread), options->number_of_thread);
	if (nmap->threads.data == NULL)
		return (1);

	vector_resize(&nmap->threads, options->number_of_thread);

	// file descriptor set
	// FD_ZERO(&nmap->open_fd);
	
	return (0);
}

static inline void	__nmap_scan_free(t_nmap *const nmap)
{
	if (nmap->threads.data != NULL)
		vector_destroy(&nmap->threads);
}


static inline int	_nmap_scan_port(t_nmap *const nmap, t_nmap_options const *const options, int port)
{
	(void)nmap;

	printf("Scanning port %d\n", port);

	int socket_fd = socket(PF_INET, SOCK_RAW, options->sock_protocol);
	if (socket_fd < 0)
	{
		perror("socket() error");
		return (1);
	}

	if (setsockopt(socket_fd, IPPROTO_IP, IP_HDRINCL, &(int){1}, sizeof(int)) == -1)
	{
		perror("setsockopt() error");
		return (2);
	}

	/*
	*  Now that the socket is setup we prepare the packet that will be sent.
	*/

	t_net_socket source_net_socket = (t_net_socket){options->send_ip_address, 0};
	t_net_socket dest_net_socket = (t_net_socket){options->dest_ip_address, port};

	t_tcp_packet packet = tcp_packet_create(source_net_socket, dest_net_socket, IPPROTO_TCP, TCP_SET_FLAGS(0, TCP_FLAG_SYN));

	/*
	*
	*	The packet is setup to simple tcp for now but we will need to change it to handle the different user input flags. 
	*	This can be easily done by modifying <tcp_packet_create>.
	*	Now i send the packet to the corresponding address and port.
	*
	*	edit: i will do a better more functional function later to not have to change the function call depending on a big conditional tree here...
	*
	*/

	t_sockaddr	dest_addr = (t_sockaddr){0};
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(port);
	dest_addr.sin_addr.s_addr = options->dest_ip_address;

	if (sendto(socket_fd, &packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0)
	{
		perror("sendto() error");
		return (3);
	}

	/*
	*
	*	Now that the packet is surfing on the internet we wait for a response,
	*	if no one respond after a certain time we can easily deduce that the port is not used by the system.
	*	In that case: we stop it and register its state.
	*
	*/

	// t_sockaddr recv_addr = (t_sockaddr){0};
	// socklen_t recv_addr_len = sizeof(recv_addr);

	t_tcp_packet	recv_packet = {0};

	printf("Waiting for response on thread %lu\n", pthread_self());

	if (recvfrom(socket_fd, &recv_packet, sizeof(recv_packet), 0, NULL, NULL) < 0)
	{
		perror("recvfrom() error");
		return (4);
	}

	/*
	*	
	*	Once the packet is received we need to check wich response we got:
	*	If the response is a packet with flag TCP_FLAG_SYN and TCP_FLAG_ACK
	*	 it means the port is open and have a service that is ready to connect !
	*
	*	Else it means the server is closed.
	*
	*	But if we have a no response in some times, it means that the port probably
	*	 have a service that is handling the packet and so it is filtered...
	*
	*/

	tcp_packet_display(&recv_packet);

	// // start of print packet
	// char char_buffer[1024] = {0};
	// sprintf(char_buffer + strlen(char_buffer), "SYN = %d\n", recv_packet.tcp_header.syn);
	// sprintf(char_buffer + strlen(char_buffer), "ACK = %d\n", recv_packet.tcp_header.ack);
	// sprintf(char_buffer + strlen(char_buffer), "RST = %d\n", recv_packet.tcp_header.rst);
	// sprintf(char_buffer + strlen(char_buffer), "PSH = %d\n", recv_packet.tcp_header.psh);
	// sprintf(char_buffer + strlen(char_buffer), "FIN = %d\n", recv_packet.tcp_header.fin);
	// sprintf(char_buffer + strlen(char_buffer), "URG = %d\n", recv_packet.tcp_header.urg);	
	// printf("For port %d on thread:%lu\n%s\n", port, pthread_self(), char_buffer);
	// // end of print packet

	if (close(socket_fd))
	{
		perror("close() error");
		return (4);
	}
	
	return (0);
}

static void	*_nmap_thread_wrapper(void *arg)
{
	t_nmap_thread *const nmap_thread = arg;

	for (t_length i = 0; i < nmap_thread->port_size; ++i)
	{
		int ret = _nmap_scan_port(nmap_thread->nmap, nmap_thread->options, nmap_thread->port_array[i]);
		if (ret)
		{
			printf("%s%d%s%lu\n", "ERROR[", ret, "]: on thread n*", pthread_self());
			break;
		}
	}

	return (arg);
}

static inline int	__nmap_scan_content(t_nmap *const nmap, t_nmap_options const *const options)
{
	t_length 		size_of_array = options->ports_to_scan.size / options->number_of_thread;
	int				total_remain = options->ports_to_scan.size % options->number_of_thread;

	int				*port_array = (int *)options->ports_to_scan.data;
	t_nmap_thread	*threads_list = (t_nmap_thread *)nmap->threads.data;
	for (t_length i = 0; i < nmap->threads.size; ++i)
	{
		t_length current_array_size = size_of_array + (total_remain-- > 0);

		threads_list[i].nmap = nmap;
		threads_list[i].options = (t_nmap_options *)options;
		threads_list[i].port_array = port_array;
		threads_list[i].port_size = current_array_size;

		printf("Launching thread %u: at %p with %u\n", i, threads_list[i].port_array, threads_list[i].port_size);

		port_array += current_array_size;

		pthread_create(&threads_list[i].thread_ptr, NULL, _nmap_thread_wrapper, threads_list + i);
	}

	// wait for all threads to finish
	for (t_length i = 0; i < nmap->threads.size; ++i)
		pthread_join(threads_list[i].thread_ptr, NULL);

	return (0);
}

int	nmap_scan(t_nmap_options *const options)
{
	t_nmap	nmap;

	if (options->number_of_thread > options->ports_to_scan.size)
	{
		printf("WARNING: Number of thread is greater than number of ports to scan\n");
		printf("WARNING: Number of thread lowered to %u\n", options->ports_to_scan.size);
		options->number_of_thread = options->ports_to_scan.size;
	}

	if (__nmap_scan_create(&nmap, options))
	{
		__nmap_scan_free(&nmap);
		return (1);
	}

	__nmap_scan_content(&nmap, options);

	__nmap_scan_free(&nmap);
	return (0);
}
