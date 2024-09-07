/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   struct.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: alde-fre <alde-fre@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/06 12:21:10 by alde-fre          #+#    #+#             */
/*   Updated: 2024/09/06 18:23:11 by alde-fre         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef STRUCT_H
# define STRUCT_H

# include "vector.h"
# include "port_listener/port_listener.h"

typedef struct s_nmap	t_nmap;

/*
 *	NMAP:
 *		source_ip: uint32					# ipv4 only is mandatory for the project
 *		destination_ip: uint32				# ipv4 only is mandatory for the project
 *		destination_ports: vector(uint16)	# should probably store ports and actions related to them in NMAP
 *		listener: port_listener
 *		worker_pool: vector(worker)
 */
struct s_nmap
{
	uint32_t			source_ip;
	uint32_t			destination_ip;
	t_vector			destination_ports; // : uint16_t
	t_vector			worker_pool; // : t_worker
};

#endif