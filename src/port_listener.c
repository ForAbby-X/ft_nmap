/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   port_listener.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: alde-fre <alde-fre@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/06 12:54:26 by alde-fre          #+#    #+#             */
/*   Updated: 2024/09/07 09:54:36 by alde-fre         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "port_listener/error.h"
#include "port_listener/struct.h"
#include <string.h>

static inline t_port_listener_error	port_listener_init_expression(t_port_listener *port_listener, t_vector *ports, uint32_t address)
{
	/*
	 *	Here generate the uncompiled expression.
	 *
	 *		Soo ... a list of all the ports with a mix the prefixes 'port' and 'portrange'.
	 *		Optimisation of the number of chars could be good.
	 *		That means grouping the adjacent ports together to use their range,
	 *		 and the rest will be disposed individually as usual.
	 *
	 *		ex: "port 5,8,10,20-85,90"
	 */

	// simple bubble sort
	uint16_t *it = ports->data;
	while (it - (uint16_t *)ports->data + 1 < ports->size)
	{
		if (*it > *(it + 1))
		{
			uint16_t copy_it_val = *it;
			*it = *(it + 1);
			*(it + 1) = copy_it_val;
			it = ports->data;
		}
		else
			++it;
	}

	/*
	 *	dst port xXxXx
	 *	dst portrange xXxX1-xXxXx2 
	 *	and
	 *
	 *
	 *		max len of port: "65535" -> 5
	 *		max len of phrase: "dst port xXxXx " -> 15
	 *		max length of junction: "or " -> 3
	 *
	 *		Worst length for uncompiled string:  (15 + 43) x 1024 - 1 - 5 = 18426
	 */

	// grouping of similar ports
	
	/*
	 *	Too fatigued pour continuer ce soir - Alan De Freitas Sep 6 2024 - 23:05
	 *
	 *		edit: Too fatigued mais a tout de meme fini... mais mal,
	 *		 il faut remplacer l'iterateur par un index pour
	 *		 simplifier les conditions et la lecture du code...
	 *
	 *	Tommorow i should implement the sorting for small numbers to be
	 *	 first and range to be last so i can use the sequence shortener.
	 *	After thinking for a bit i realised i can do it dynamically
	 *	 with a bit of memory play.
	 *	 Like moving the ranges at the end of the array and register
	 *	 them only once we reach the ''range'' side of the array.
	 *
	 * 		exemple of old vs new display:
	 *		 "dst port 12 or dst port 35 or dst port 56 or dst port 576 or dst port 784 or dst port 2345 or ..."
	 *		 "dst port 12 or 35 or 56 or 576 or 784 or 2345 or dst port range 45-55 or 580-760"
	 *
	 *	- Alan De Freitas Sep 6 2024 - 23:17
	 */
	
	char raw_expression[32768] = {0};	// should be 18426 max
	uint16_t raw_expression_length = 0;
	uint16_t range_start = 0;
	uint16_t old_it_val = 0;
	it = ports->data;
	while (it - (uint16_t *)ports->data <= ports->size)
	{
		if (old_it_val == 0)			// start of range
		{
			range_start = *it;
		}
		else if (it - (uint16_t *)ports->data == ports->size || *it != old_it_val + 1)	// end of range
		{
			if (range_start == old_it_val)	// unique port
				raw_expression_length += sprintf(raw_expression + raw_expression_length, "dst port %d or ", old_it_val);
			else							// range is -> (range_start - old_it_val)
				raw_expression_length += sprintf(raw_expression + raw_expression_length, "dst portrange %d-%d or ", range_start, old_it_val);
			if (it - (uint16_t *)ports->data < ports->size)
				range_start = *it;
		}
		if (it - (uint16_t *)ports->data < ports->size)
			old_it_val = *it;
		++it;
	}
	if (raw_expression_length > 4) // if expression is not empty remove trailling "or "
		raw_expression[raw_expression_length - 4] = '\0';

	printf("Final uncompiled expression for ports filtering:\n	'%s'\n", raw_expression);


	if(pcap_compile(port_listener->handle, &port_listener->compiled_expression, raw_expression, 1, address) == -1) // the 1 means optimisation enabled
		return (PORT_LISTENER_FAILURE);

	return (PORT_LISTENER_SUCCESS);
}

t_port_listener_error	port_listener_init(t_port_listener *port_listener, uint32_t target_address, t_vector *ports)
{
	char error_buff[PCAP_ERRBUF_SIZE] = {0}; // ! warning ! if keeping here remove in struct
	
	port_listener->address = target_address;

	(void)ports;

	/*
	 *	Gather all the network devices on this machine.
	 */
	pcap_if_t *device_list = NULL;
	if (pcap_findalldevs(&device_list, error_buff))
	{
		fprintf(stderr, "Error: Looking for network devices.\n%s\n", error_buff);
		return (PORT_LISTENER_FIND_DEVICE_ERROR);
	}

	printf("Network devices found:\n");
	uint8_t device_id = 0;
	for (pcap_if_t *it = device_list; it != NULL; it = it->next)
		printf("	%d - %s: %s\n", device_id++, it->name, it->description);		

	if (device_list == NULL || device_list->name == NULL) // if no device available or first device does not have name
	{
		fprintf(stderr, "Error: No device found for listening.\n");
		pcap_freealldevs(device_list);
		return (PORT_LISTENER_FAILURE);
	}
	port_listener->device_name = device_list->name; // take the first device
	printf("Choosed network device: '%s'\n", port_listener->device_name);

	uint32_t machine_address = 0;
	uint32_t machine_mask = 0;
	if (pcap_lookupnet(port_listener->device_name, &machine_address, &machine_mask, error_buff) == -1)
	{
		fprintf(stderr, "Error: Looking for network info on device '%s'.\n%s\n", port_listener->device_name, error_buff);
		pcap_freealldevs(device_list);
		return (PORT_LISTENER_FAILURE);
	}

	struct in_addr device_address = {.s_addr = machine_address}, device_mask = {.s_addr = machine_mask};
	printf("This device network address: %s/", inet_ntoa(device_address));	// display address ...
	printf("%s\n", inet_ntoa(device_mask));									// then mask.


	port_listener->handle = pcap_open_live(port_listener->device_name, PCAP_ERRBUF_SIZE, 0, -1, error_buff); // no promiscious: can cause problems
	if (port_listener->handle == NULL)
	{
		fprintf(stderr, "Error: Creating listening handle on network device '%s'.\n%s\n", port_listener->device_name, error_buff);
		pcap_freealldevs(device_list);
		return (PORT_LISTENER_FAILURE);
	}

	// gen expr
	if (port_listener_init_expression(port_listener, ports, machine_address))
	{
		fprintf(stderr,"Error: Compiling network packet filter.\n");
		pcap_close(port_listener->handle);
		pcap_freealldevs(device_list);
	}

	if(pcap_setfilter(port_listener->handle, &port_listener->compiled_expression) == -1)
	{
		fprintf(stderr,"Error: Applying compiled packet filter to listener handle.\n");
		pcap_freecode(&port_listener->compiled_expression);
		pcap_close(port_listener->handle);
		pcap_freealldevs(device_list);
		return (PORT_LISTENER_FAILURE);
	}
	

	pcap_freecode(&port_listener->compiled_expression);
	pcap_close(port_listener->handle);
	pcap_freealldevs(device_list);
	return (PORT_LISTENER_SUCCESS);
}


t_port_listener_error	port_listener_start(uint32_t target_address, t_vector *ports)
{
	t_port_listener port_listener = {0};
	t_port_listener_error error = 0;

	error = port_listener_init(&port_listener, target_address, ports);
	if (error)
		return (error);
	
	// listening starts here ...

	return (0);
}
