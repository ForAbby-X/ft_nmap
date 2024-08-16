/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   listener.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: alde-fre <alde-fre@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/08/09 08:20:10 by alde-fre          #+#    #+#             */
/*   Updated: 2024/08/16 18:12:34 by alde-fre         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "net.h"

/*
*	This global store a map of the packets stored for each port.
*/
t_vector	g_packet_lists;

// def dicho2bis(t, v):
//     a = 0
//     b = len(t)
//     if b == 0:
//       return False
//     while True:
//         m = (a + b) // 2
//         if a == m:
//           return t[a] == v
//         if t[m] > v:
//             b = m
//         else:
//             a = m

// template <class ForwardIterator, class T>
//   ForwardIterator lower_bound (ForwardIterator first, ForwardIterator last, const T& val)
// {
//   ForwardIterator it;
//   iterator_traits<ForwardIterator>::difference_type count, step;
//   count = distance(first,last);
//   while (count>0)
//   {
//     it = first; step=count/2; advance (it,step);
//     if (*it<val) {                 // or: if (comp(*it,val)), for version (2)
//       first=++it;
//       count-=step+1;
//     }
//     else count=step;
//   }
//   return first;
// }

static t_length	_lower_bound(unsigned short port)
{
	t_length first = 0;
	t_length count = g_packet_lists.size;
	t_length it;
	t_length step;
	
	t_port_packet *packets = g_packet_lists.data;

	if (count == 0)
		return (0);

	while (count > 0)
	{
		step = count >> 1;
		it = first + step;
		
		if (packets[it].port < port)
		{
			first = ++it;
			count -= step + 1;
		}
		else
			count = step;
	}
	return (first);
}

/*
*	@return the pointer to the key-pair if the key exist else NULL
*/
t_port_packet	*port_listener_get(unsigned short port)
{
	if (g_packet_lists.size == 0)
		return (NULL);

	t_port_packet *sel = vector_get(&g_packet_lists, _lower_bound(port));	// @todo remove function call
	
	if (sel->port == port)
		return (sel);
	return (NULL);
}

/*
*	@return the pointer to the key-pair added to the map
*/
t_port_packet	*port_listener_add(unsigned short port, uint8_t *packet_addr)
{
	t_length	sel_index = _lower_bound(port);
	t_port_packet *sel = vector_get(&g_packet_lists, sel_index);			// @todo remove function call
	
	if (sel->port == port)
		return (vector_addback(&sel->packets, packet_addr));
	
	t_port_packet	prt_pckt;

	prt_pckt.packets = vector_create(sizeof(uint8_t *));
	if (prt_pckt.packets.data == NULL)
		return (NULL);
	prt_pckt.port = port;

	return (vector_insert(&sel->packets, &prt_pckt, sel_index));
}

/*
*	This function will create a pcap handle initialise it, configure it to listen
*	 to everything coming from an ip and register every packets in a container.
*
*	As for the container to use; i still dont know...
*	 probably a map with the port as the key, and a vector as the value,
*	 or a sorted vector with ports and a pointer to the data in a large buffer. 
*
*
*	My thought is that with a global listener like that we end up with alot of
*	 memory used for a simple task as *watching* tcp flags...
*	Not to mention the overhead of storing, sorting and freeing all these memory...
*
*	I should probably do a simple listener that gather only the flags related to
*	 each protocol that i will use (TCP, UDP, ICMP...)
*
*	But the drawback will be that if i want to identify the system running on the
*	 port i need to send an http request and so gather it.
*	And so store the whole packets...
*
*	Alan De Freitas - 09/08/2024
*/
static void	_individual_net_packet_handler(uint8_t *args, const struct pcap_pkthdr *packet_info, const uint8_t *packet)
{
	(void)args; // should always be NULL
	(void)packet;

	printf("Recevied a packet on at %lu:%lu\n", packet_info->ts.tv_sec, packet_info->ts.tv_usec);
	printf("Packet received: length %d\n", packet_info->len);
}

int	port_listener_init(t_port_listener *const listener, uint32_t ip_address, t_vector *const port)
{
	memset(listener, 0, sizeof(t_port_listener));

	listener->targeted_address = ip_address;

	//listener->device_name = "enp0s3"; // @warning may be the cause of crash later !!! @todo change this for user input !!!
	pcap_if_t *device_list = NULL;		// @warning need to free this list !
	pcap_findalldevs(&device_list, listener->error_buff);
	listener->device_name = device_list->name;


	printf("listening to: %s\n", inet_ntoa((struct in_addr){listener->targeted_address}));
	printf("libpcap_device_name: %s\n", listener->device_name);

	/*
	*	The packet lists must be preallocated so the pointers to the port will not changed after get.
	*/
	g_packet_lists = vector_create_s(sizeof(t_port_packet), port->size);
	if (g_packet_lists.data == NULL)
	{
		fprintf(stderr, "vector_create_s() error\n");
		fprintf(stderr, "Can't create the main packet buffer\n");
		return (2);
	}
	
	/*
	*	This part where i allocate the whole memory is not necessary,
	*	 i do this to limit the number of malloc during the execution
	*	 and then make it faster and easier to handle errors.
	*/
	vector_resize(&g_packet_lists, port->size);
	t_port_packet *prt_pcks = g_packet_lists.data;
	int *ports = port->data;
	for (t_length i = 0; i < g_packet_lists.size; ++i)
	{
		prt_pcks[i].port = ports[i];
		prt_pcks[i].packets = vector_create(sizeof(uint8_t *));
		if (prt_pcks[i].packets.data == NULL)
		{
			fprintf(stderr, "vector_create() error\n");
			fprintf(stderr, "Can't create the packet buffer for port n'%d\n", ports[i]);
			return (2);		// @todo change error number
		}
	}

	/*
	*	This function gather an address and a mask related to the network.
	*
	*	It is essential because we need to have the network mask to apply
	*	 filters to the packet listener.
	*/
	if (pcap_lookupnet(listener->device_name, &listener->address, &listener->mask, listener->error_buff) == -1)
	{
		fprintf(stderr, "pcap_lookupnet() error\n");
		fprintf(stderr, "Can't get netmask for device %s\n", listener->device_name);
		return (3);
	}

	/*
	*	This function open the device for sniffing.
	*
	*	1. An array:	the name of the device to *sniff* on.
	*	2. An integer:	defines the maximum number of bytes to capture.
	*	3. An integer:	set the interface into promiscuous mode.
	*	4. An integer:	is the time it wait for a response before timeout.
	*	5. An array:	the buffer that will hold any error message.
	*/
	listener->handle = pcap_open_live(listener->device_name, BUFSIZ, 1, 0001, listener->error_buff);
	if (listener->handle == NULL)
	{
		fprintf(stderr, "pcap_open_live() error\n");
		fprintf(stderr, "Couldn't open device %s: %s\n", listener->device_name, listener->error_buff);
		return (4);
	}

	/*
	*	This function allocate 16777215 bytes to store the packets,
	*	 it should be enough to store every packets necessary for
	*	 the nmap execution.
	*/
	// if (pcap_set_buffer_size(listener->handle, 0xFFFF))
	// {
	// 	fprintf(stderr, "pcap_set_buffer_size() error\n");
	// 	fprintf(stderr, "Can't change buffer size\n");
	// 	return (1);
	// }

	/*
	*	This function verifies that the selected device provides the necessary link-layer header.
	*
	*	In our case it is the 'Ethernet (10Mb)' layer equivalent to the flag 'DLT_EN10MB'.
	*/
	if (pcap_datalink(listener->handle) != DLT_EN10MB)
	{
		fprintf(stderr, "pcap_datalink() error\n");
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", listener->error_buff);
		return (5);
	}

	/*
	*	The expression is the non compiled code that will be used to filter data on the network.
	*
	*	Note:
	*	 For more information go to this website: https://www.tcpdump.org/manpages/pcap-filter.7.html
	*/
	char raw_expression[64] = {0};
	strcat(raw_expression, "src ");
	strcat(raw_expression, inet_ntoa((struct in_addr){listener->targeted_address}));

	printf("raw expression for listener '%s'\n", raw_expression);

	/*
	*	This function will 'compile' just in time a string passed to it.
	*	This is the central point of the program as it is where we are going to choose wich
	*	 port to filter on this expression.
	*
	*	I still need to choose wether i create an expression for each context (each threads, or each ports)
	*	 or if i create a global expression with a smart manager to access and release the packet data.
	*
	*	The global manager might make me create a sort of std::map to access ports quickly and memory efficiently.
	*	Or i could just do it the easy and *fast* way and make an indexes array of each ports, that points to indiviual
	*	 vectors of packets for this port.
	*/
	if (pcap_compile(listener->handle, &listener->compiled_expression, raw_expression, 0, listener->mask) == -1)
	{
		fprintf(stderr, "pcap_compile() error\n");
		fprintf(stderr, "Couldn't parse filter %s: %s\n", "", pcap_geterr(listener->handle));
		return (5);
	}
	
	/*
	*	Now that we have our handle, and our compiled expression, and a device that accepts ethernet packets,
	*	 we can apply the expression to the device and praise for it to work. (please... https://c.tenor.com/fP1Qr3rwSHkAAAAC/tenor.gif)
	*/
	if (pcap_setfilter(listener->handle, &listener->compiled_expression))
	{
		fprintf(stderr, "pcap_setfilter() error\n");
		fprintf(stderr, "Couldn't install filter %s: %s\n", raw_expression, pcap_geterr(listener->handle));
		return (6);
	}

	return (0);
}

void	port_listener_destroy(t_port_listener *const listener)
{
	if (listener->handle != NULL)
	{
		t_port_packet	*packets = g_packet_lists.data;
		for (t_length i = 0; i < g_packet_lists.size; ++i)
			vector_destroy(&packets[i].packets);
		vector_destroy(&g_packet_lists);

		if (listener->compiled_expression.bf_insns != NULL)
			pcap_freecode(&listener->compiled_expression);
		pcap_close(listener->handle);
	}
}

static void	*_listener_handle(void *arg)
{
	t_port_listener *const listener = arg;

	printf("about to launch pcap_loop with %p\n", listener->handle);

	// the process will stay stuck here due to an infinite loop.
	if (pcap_loop(listener->handle, 0, &_individual_net_packet_handler, NULL)) // last param is args value, i will probably not use it.
	{
		fprintf(stderr, "pcap_loop() error\n");
		fprintf(stderr, "Couldn't launch the pcap loop\n");

		printf("ERROR ERROR ERROR :%s\n", pcap_geterr(listener->handle));
		
		return (NULL);
	}
	return (NULL);
}

/*
*	Note that this function should take a pcap handle as an argument or return one, so that we can stop the pcap loop from outside.
*/
int	port_listener_start(t_port_listener	*const listener)
{
	printf("[INFO] Starting port listener...\n");

	if (pthread_create(&listener->thread, NULL, &_listener_handle, listener) != 0)
	{
		fprintf(stderr, "pthread_create() error\n");
		fprintf(stderr, "Couldn't launch listener threads\n");
		return (1);
	}

	return (0);
}

void	port_listener_stop(t_port_listener	*const listener)
{
	printf("[INFO] Stopping port listener.\n");
	pcap_breakloop(listener->handle);
	pthread_join(listener->thread, NULL);
}
