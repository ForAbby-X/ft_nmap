/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: alde-fre <alde-fre@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/08/04 14:23:39 by alde-fre          #+#    #+#             */
/*   Updated: 2024/12/06 13:04:45 by alde-fre         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ft_nmap.h"
#include "vector.h"

int	main(int argc, char **argv)
{
	if (getuid() != 0)
	{
		printf("You must have root privilege to run this program\n");
		return (1);
	}

	if (argc != 2)
	{
		printf("Usage: %s <ip_address>\n", argv[0]);
		return (1);
	}

	t_nmap_options	options = {
		.number_of_thread = 1,
		.ports_to_scan = vector_create(sizeof(int)),

		.send_ip_address = *(int *)(char [4]){216, 58, 214, 78},
		.dest_ip_address = *(int *)(char [4]){216, 58, 214, 78},
		.sock_protocol = IPPROTO_TCP,
		.flags = 0,

		.libcap_device_name = "wlp82s0",
	};

	for (int i = 0; i < 1024; ++i)
		vector_addback(&options.ports_to_scan, &(int){i});

	// vector_addback(&options.ports_to_scan, &(int){20});
	// vector_addback(&options.ports_to_scan, &(int){80});
	// vector_addback(&options.ports_to_scan, &(int){430});
	// vector_addback(&options.ports_to_scan, &(int){8080});
	// vector_addback(&options.ports_to_scan, &(int){8081});
	// vector_addback(&options.ports_to_scan, &(int){8082});
	// vector_addback(&options.ports_to_scan, &(int){8083});
	// vector_addback(&options.ports_to_scan, &(int){8084});
	// vector_addback(&options.ports_to_scan, &(int){8085});
	// vector_addback(&options.ports_to_scan, &(int){8086});

	nmap_scan(&options);

	vector_destroy(&options.ports_to_scan);

	return (0);
}
