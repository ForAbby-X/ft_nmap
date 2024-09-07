/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   nmap.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: alde-fre <alde-fre@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/06 12:16:03 by alde-fre          #+#    #+#             */
/*   Updated: 2024/09/06 19:50:27 by alde-fre         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <pthread.h>
#include "port_listener/port_listener.h"
#include "nmap/nmap.h"

/* todo:
- implement t_worker struct
- implement [port, action] struct
- implement t_port_listener
- implement source ip logic
*/

static t_nmap_error	nmap_init(t_nmap *nmap, uint32_t target_address, t_vector *ports, uint32_t worker_number)
{
	nmap->destination_ip = target_address;
	nmap->source_ip = 0; // todo: depending on the flag gather the real source ip or hide it !
	
	nmap->destination_ports = vector_subvec(ports, 0, ports->size); // ! warning ! implement [port, action] struct
	if (nmap->destination_ports.data == NULL)
		return (NMAP_MEMORY_FAILURE);
	
	nmap->worker_pool = vector_create_s(sizeof(pthread_t), worker_number); // todo: implement t_worker
	if (nmap->worker_pool.data == NULL)
		return (NMAP_MEMORY_FAILURE);
	
	return (NMAP_SUCCESS);
}

static void	nmap_destroy(t_nmap *nmap)
{
	vector_destroy(&nmap->worker_pool);
	vector_destroy(&nmap->destination_ports);
}


t_nmap_error	nmap_scan(uint32_t target_address, t_vector *ports)
{
	t_nmap nmap = {0};
	t_nmap_error error = 0;

	error = nmap_init(&nmap, target_address, ports, 1); // number of worker is last parameter
	if (error)
		return (error);

	// scan happens here !
	port_listener_start(target_address, ports);

	nmap_destroy(&nmap);
	return (NMAP_SUCCESS);
}
