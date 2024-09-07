/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: alde-fre <alde-fre@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/06 11:08:47 by alde-fre          #+#    #+#             */
/*   Updated: 2024/09/06 23:03:35 by alde-fre         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap/nmap.h"

// laptop ip: 10.18.191.24/16

int main(void)
{
	uint32_t target_address = *(uint32_t *)(uint8_t [4]){10, 18, 191, 24};
	t_vector ports = vector_create(sizeof(uint16_t));
	t_nmap_error error = 0;
	
	if (ports.data == NULL)
	{
		printf("error: vector creation in main...\n");
		return (1);
	}

	vector_addback(&ports, &(uint16_t){200 + 10});
	vector_addback(&ports, &(uint16_t){200 + 243});
	vector_addback(&ports, &(uint16_t){10});
	vector_addback(&ports, &(uint16_t){200 + 38});
	vector_addback(&ports, &(uint16_t){35});
	vector_addback(&ports, &(uint16_t){200 + 37});
	vector_addback(&ports, &(uint16_t){200 + 35});
	vector_addback(&ports, &(uint16_t){36});
	vector_addback(&ports, &(uint16_t){37});
	vector_addback(&ports, &(uint16_t){200 + 36});
	vector_addback(&ports, &(uint16_t){38});
	vector_addback(&ports, &(uint16_t){243});
	vector_addback(&ports, &(uint16_t){300 + 10});
	vector_addback(&ports, &(uint16_t){300 + 200 + 38});
	vector_addback(&ports, &(uint16_t){300 + 35});
	vector_addback(&ports, &(uint16_t){300 + 200 + 37});
	vector_addback(&ports, &(uint16_t){300 + 200 + 35});
	vector_addback(&ports, &(uint16_t){300 + 36});
	vector_addback(&ports, &(uint16_t){300 + 37});
	vector_addback(&ports, &(uint16_t){300 + 200 + 36});
	vector_addback(&ports, &(uint16_t){300 + 38});
	vector_addback(&ports, &(uint16_t){300 + 243});

	error = nmap_scan(target_address, &ports);
	if (error)
	{
		printf("error: nmap error n°%d in main...\n", error);
		return (1);
	}

	vector_destroy(&ports);
	return (0);
}