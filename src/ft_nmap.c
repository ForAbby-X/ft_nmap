/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: alde-fre <alde-fre@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/08/04 16:19:12 by alde-fre          #+#    #+#             */
/*   Updated: 2024/09/02 16:14:03 by alde-fre         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <pthread.h>
#include <errno.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#include "ft_nmap.h"
#include "vector.h"

/// MANAGER FUNCTIONS ///

static inline int	__nmap_scan_create(t_nmap *const nmap, t_nmap_options const *const options)
{
	memset(nmap, 0, sizeof(t_nmap));

	// threads array
	nmap->threads = vector_create_s(sizeof(t_nmap_thread), options->number_of_thread);
	if (nmap->threads.data == NULL)
		return (1);
	
	vector_resize(&nmap->threads, options->number_of_thread);

	return (0);
}

static inline void	__nmap_scan_free(t_nmap *const nmap)
{
	if (nmap->threads.data != NULL)
		vector_destroy(&nmap->threads);

}

static inline int	__nmap_scan_port(t_nmap *const nmap, t_nmap_options const *const options, t_port_action *const port_action)
{
	(void)nmap;

	printf("Scanning port %d\n", port_action->port);

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
	*  Now that the socket is ready we prepare the packet that will be sent.
	*/

	t_net_socket source_net_socket = (t_net_socket){options->send_ip_address, 0};
	t_net_socket dest_net_socket = (t_net_socket){options->dest_ip_address, port_action->port};

	t_tcp_packet packet = tcp_packet_create(source_net_socket, dest_net_socket, IPPROTO_TCP, TCP_SET_FLAGS(0, TCP_FLAG_SYN));

	/*
	*	The packet is arranged to simple tcp for now but we will need to change it to handle the different user input flags. 
	*	This can be easily done by modifying <tcp_packet_create>.
	*	Now i send the packet to the corresponding address and port.
	*
	*	edit: i will do a better more functional function later to not have to change the function call depending on a big conditional tree here...
	*/

	t_sockaddr	dest_addr = (t_sockaddr){0};
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(port_action->port);
	dest_addr.sin_addr.s_addr = options->dest_ip_address;

	ssize_t ret_sendto = sendto(socket_fd, &packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
	if (ret_sendto < 0)
	{
		perror("sendto() error");
		return (3);
	}
	printf("	Packet sent to %s:%d\n", inet_ntoa(*(struct in_addr *)&options->dest_ip_address), port_action->port);
	printf("	Packet size: %ld\n", ret_sendto);

	/*
	*	Now that the packet is surfing on the internet we wait for a response,
	*	if no one respond after a certain time we can easily deduce that the port is not used by the system.
	*	In that case: we stop it and register its state.
	*/

	port_action->actions |= 1; // lets say that it is tcp first action !

	/*
	*	Once the packet is received we need to check wich response we got:
	*	If the response is a packet with flag TCP_FLAG_SYN and TCP_FLAG_ACK
	*	 it means the port is open and have a service that is ready to connect !
	*
	*	If the response is a packet with flag TCP_FLAG_RST
	*	 it means the port is closed and no service is listening on it.
	*
	*	Else it means the server is closed.
	*
	*	But if we have a no response in some times, it means that the port probably
	*	 have a service that is handling the packet and so it is filtered...
	*/

	// tcp_packet_display(&recv_packet);	// debug only

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
	t_port_action *current_port;
	int ret = 0;
	
	while (1)
	{
		for (t_length i = 0; i < nmap_thread->port_size; ++i)
		{
			current_port = nmap_thread->port_array + i;
			
			if (current_port->actions == 0)
			{
				ret = __nmap_scan_port(nmap_thread->nmap, nmap_thread->options, current_port);
				if (ret)
				{
					printf("ERROR[%d]: on thread n*%lu\n", ret, pthread_self());
					break;
				}
			}
		}
	}
	return (arg);
}

static inline int	__nmap_scan_content(t_nmap *const nmap, t_nmap_options const *const options)
{
	t_length 		size_of_array = options->ports_to_scan.size / options->number_of_thread;
	int				total_remain = options->ports_to_scan.size % options->number_of_thread;

	int				*port_array = (int *)options->ports_to_scan.data;
	t_port_action	*port_actions = malloc(sizeof(t_port_action) * options->ports_to_scan.size);
	if (port_actions == NULL)
	{
		fprintf(stderr, "malloc() error\n");
		fprintf(stderr, "Can't malloc port actions array\n");
		return (1);
	}

	/*
	*	setup the array of ports associated with their actions.
	*/
	for (t_length i = 0; i < options->ports_to_scan.size; ++i)
	{
		port_actions[i].port = port_array[i];
		port_actions[i].actions = 0;				// no actions to do for now
	}

	t_nmap_thread	*threads_array = (t_nmap_thread *)nmap->threads.data;
	for (t_length i = 0; i < nmap->threads.size; ++i)
	{
		t_length current_array_size = size_of_array + (total_remain-- > 0);

		threads_array[i].nmap = nmap;
		threads_array[i].options = (t_nmap_options *)options;
		threads_array[i].port_array = port_actions;
		threads_array[i].port_size = current_array_size;

		printf("Launching thread %u: at %p with %u\n", i, threads_array[i].port_array, threads_array[i].port_size);

		port_actions += current_array_size;

		pthread_create(&threads_array[i].thread_ptr, NULL, _nmap_thread_wrapper, threads_array + i);
	}

	// wait for all threads to finish
	for (t_length i = 0; i < nmap->threads.size; ++i)
		pthread_join(threads_array[i].thread_ptr, NULL);

	free(port_actions);

	return (0);
}

int	nmap_scan(t_nmap_options *const options)
{
	t_nmap			nmap;
	t_port_listener	port_listener;

	/*
	*	Start of port listener config.
	*/
	if (port_listener_init(&port_listener, options->dest_ip_address, &options->ports_to_scan))
	{
		fprintf(stderr, "port_listener_init() error\n");
		fprintf(stderr, "Can't init port listener\n");
		port_listener_destroy(&port_listener);					// forcing myself to do that to respect the engineer guide: "fast and ugly"
		return (1);
	}

	/*
	*	Here starts the port listener thread.
	*	At this point every packets comming from the desired ip are stored.
	*/
	if (port_listener_start(&port_listener))
	{
		fprintf(stderr, "port_listener_start() error\n");
		fprintf(stderr, "Can't start port listener\n");
		port_listener_destroy(&port_listener);
		return (1);
	}
	
	if (options->number_of_thread > options->ports_to_scan.size)
	{
		printf("WARNING: Number of thread is greater than number of ports to scan\n");
		printf("WARNING: Number of thread lowered to %u\n", options->ports_to_scan.size);
		options->number_of_thread = options->ports_to_scan.size;
	}

	if (__nmap_scan_create(&nmap, options)) // __nmap_scan_init(&nmap, options)
	{
		__nmap_scan_free(&nmap);
		port_listener_stop(&port_listener);
		port_listener_destroy(&port_listener);
		return (1);
	}


	__nmap_scan_content(&nmap, options);

	port_listener_stop(&port_listener);
	__nmap_scan_free(&nmap);
	port_listener_destroy(&port_listener);
	return (0);
}
