/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: alde-fre <alde-fre@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/08/04 16:15:31 by alde-fre          #+#    #+#             */
/*   Updated: 2024/09/04 16:05:13 by alde-fre         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_NMAP_H
# define FT_NMAP_H

# include <pcap.h>

# include "vector.h"

# include "net.h"

typedef struct s_nmap			t_nmap;
typedef struct s_nmap_thread	t_nmap_thread;
typedef struct s_nmap_options	t_nmap_options;

typedef struct s_port_action	t_port_action;

typedef enum e_net_flag_e		e_net_flag_e;

/// FUNCTION PROTOTYPE ///

int				nmap_scan(t_nmap_options *const options);

/// STRUCTURE ///


struct s_nmap_options
{
	t_length		number_of_thread;
	t_vector		ports_to_scan;

	int				send_ip_address;
	int				dest_ip_address;
	int				sock_protocol;
	t_net_flags		flags;

	/*
	*	This is the device that libcap will *sniff* on, if NULL, libcap will use the default device.
	*	It is probably not necessary in our case, but it is here in case we need to allow the user to change it...
	*/
	char const		*libcap_device_name;
	
};

struct s_nmap
{
	t_vector		threads;		// vector of all the working threads

};

struct s_port_action
{
	uint16_t	port;
	uint16_t	actions;
};

struct s_nmap_thread
{
	// thread related
	pthread_t		thread_ptr;		// pointer to the thread
	t_length		port_size;		// number of ports to scan
	t_port_action	*port_array;	// port array pointing to nmap global port vector

	// nmap related
	t_nmap			*nmap;			// handle to nmap structure
	t_nmap_options	*options;		// handle to options structure
};

struct s_nmap_port
{
	int				port;
	t_net_flags		last_rcv_flags;

	uint32_t		protocols;
};

enum	e_net_flag_e
{
	NMAP_SEND		= 0b00000011,
	NMAP_SEND_TCP	= 0b00000001,
	NMAP_SEND_UDP	= 0b00000010,

	NMAP_RECV		= 0b00110000,
	NMAP_RECV_TCP	= 0b00010000,
	NMAP_RECV_UDP	= 0b00100000,
};

#endif
