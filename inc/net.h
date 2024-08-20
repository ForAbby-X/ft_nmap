/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   net.h                                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: alde-fre <alde-fre@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/08/07 11:06:16 by alde-fre          #+#    #+#             */
/*   Updated: 2024/08/20 17:26:58 by alde-fre         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef NET_H
# define NET_H

// # include <linux/in.h>
# include <linux/if_ether.h>
# include <linux/tcp.h>
# include <linux/ip.h>
# include <net/ethernet.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <stdint.h>
# include <string.h>
# include <stdio.h>
# include <pcap.h>
# include <pthread.h>

# include "vector.h" 

/*
*	Just changed this macro, to let it handle multiple flags at once
*
*	The old version is this:
*	'# define TCP_GET_FLAGS(FLAGS, KEY)	(((FLAGS) & ((KEY) >> 4)) != 0)'
*
*	Alan De Freitas - 08/08/2024
*/
# define TCP_GET_FLAGS(FLAGS, KEY)	(((FLAGS) & ((KEY) >> 4)) == ((KEY) >> 4))
# define TCP_SET_FLAGS(FLAGS, KEY)	(((FLAGS) | ((KEY) >> 4)))

// TYPEDEFS //

typedef struct s_net_socket		t_net_socket;
typedef struct sockaddr_in		t_sockaddr;

typedef uint32_t				t_net_flags;

typedef struct ethhdr			t_eth_header;
typedef struct iphdr			t_ip_header;
typedef struct tcphdr			t_tcp_header;
typedef struct s_tcp_packet		t_tcp_packet;

typedef struct s_port_packet	t_port_packet;

typedef struct s_port_listener	t_port_listener;

// FUNCTIONS //

void			net_srand_u32(uint32_t a);
uint32_t		net_rand_u32(uint32_t a);

uint16_t		data_checksum(uint16_t *addr, uint32_t count);

t_ip_header		ip_header_create(uint32_t source_ip_address, uint32_t destination_ip_address, uint8_t protocol);
t_tcp_header	tcp_header_create(t_net_flags const flags, t_net_socket source_net_socket, t_net_socket destination_net_socket);
t_tcp_packet	tcp_packet_create(t_net_socket source_net_socket, t_net_socket destination_net_socket, uint8_t protocol, t_net_flags flags);

void			tcp_packet_display(t_tcp_packet *const packet);


int				port_listener_init(t_port_listener *const listener, uint32_t ip_address, t_vector *const port);
void			port_listener_destroy(t_port_listener *const listener);

int				port_listener_start(t_port_listener	*const listener);
void			port_listener_stop(t_port_listener	*const listener);

t_port_packet	*port_listener_get(unsigned short port);
t_port_packet	*port_listener_add(unsigned short port, uint8_t *packet_addr);


// STRUCTURES //
struct s_net_socket
{
	uint32_t		address;
	uint16_t		port;
};

struct s_tcp_packet
{
	t_ip_header		ip_header;
	t_tcp_header	tcp_header;
};

struct s_net_map
{
	t_vector	vector;
	
};

struct s_port_packet
{
	unsigned short	port;
	t_vector		packets;
};

struct s_port_listener
{
	uint32_t			targeted_address;

	pthread_t			thread;

	pcap_t				*handle;
	char				error_buff[PCAP_ERRBUF_SIZE];
	char				*device_name;
	bpf_u_int32			address;
	bpf_u_int32			mask;

	struct bpf_program	compiled_expression;	// might end up being individual to each threads (maybe even each port !).
};

#endif
