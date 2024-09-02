/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   listener.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: alde-fre <alde-fre@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/08/09 08:20:10 by alde-fre          #+#    #+#             */
/*   Updated: 2024/08/23 13:53:10 by alde-fre         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "net.h"

/*
*	This global store a map of the packets stored for each port.
*/
t_vector	g_packet_lists;

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

	t_length index = _lower_bound(port);
	if (index >= g_packet_lists.size)
		return (NULL);

	t_port_packet *sel = vector_get(&g_packet_lists, index);	// @todo remove function call
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
	
	if (sel != NULL && sel->port == port)
		return (vector_addback(&sel->packets, packet_addr));

	t_port_packet	prt_pckt;
	prt_pckt.packets = vector_create(sizeof(uint8_t *));
	if (prt_pckt.packets.data == NULL)
		return (NULL);
	prt_pckt.port = port;

	return (vector_insert(&g_packet_lists, &prt_pckt, sel_index));
}

void	display_packet_list()
{
	for (t_length i = 0; i < g_packet_lists.size; ++i)
	{
		t_port_packet *packet = vector_get(&g_packet_lists, i);
		printf("Port: %d\n", packet->port);
		printf("Packets:\n");
		for (t_length j = 0; j < packet->packets.size; ++j)
		{
			t_ip_header *ip_header = vector_get(&packet->packets, j);

			char src_ip[INET_ADDRSTRLEN] = {0};
			char dst_ip[INET_ADDRSTRLEN] = {0};

			inet_ntop(AF_INET, &ip_header->saddr, src_ip, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &ip_header->daddr, dst_ip, INET_ADDRSTRLEN);

			printf("	Packet %u:\n", j);
			printf("		ihl = %d\n", ip_header->ihl);
			printf("		version = %d\n", ip_header->version);
			printf("		tos = %d\n", ip_header->tos);
			printf("		tot_len = %d\n", ntohs(ip_header->tot_len));
			printf("		id = %d\n",ntohs(ip_header->id));
			printf("		frag_off = %d\n", ntohs(ip_header->frag_off));
			printf("		ttl = %d\n", ip_header->ttl);
			printf("		protocol = %d\n", ip_header->protocol);
			printf("		check = %d\n", ntohs(ip_header->check));
			printf("		saddr = %s\n", src_ip);
			printf("		daddr = %s\n", dst_ip);
		}
		printf("\n");
	}
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
static void	_individual_net_packet_handler(uint8_t *args, struct pcap_pkthdr const *packet_info, uint8_t const *packet)
{
	t_eth_header	*eth_header;
	t_ip_header		*ip_header;
	t_tcp_header	*tcp_header;
	// udp here	// actually we dont care about the type of packet here so idgaf

	(void)args; // should always be NULL

	printf("PACKET RECEIVED WITH LEN %d:\n", packet_info->len);
	// size_t i = 0;
	// for (; i < packet_info->len / 8; ++i)
	// {
	// 	printf("%0.3zu: %0.16lx\n", i, ((uint64_t *)packet)[i]);
	// }
	// if ((packet_info->len % 8) != 0)
	// 	printf("%0.3zu: %0.*lx\n", i, packet_info->len % 8, ((uint64_t *)packet)[i]);
	
	/*
	*	Ethernet Header
	*/
	eth_header = (t_eth_header *)(packet);
	if (ntohs(eth_header->h_proto) == ETHERTYPE_IP)
	{
		/*
		*	IP Header
		*/
		ip_header = (t_ip_header *)(packet + sizeof(t_eth_header));
		printf("ihl = %d\n", ip_header->ihl);
		printf("version = %d\n", ip_header->version);
		printf("tos = %d\n", ip_header->tos);
		printf("tot_len = %d\n", ip_header->tot_len);
		printf("id = %d\n", ip_header->id);
		printf("frag_off = %d\n", ip_header->frag_off);
		printf("ttl = %d\n", ip_header->ttl);
		printf("protocol = %d\n", ip_header->protocol);
		printf("check = %d\n", ip_header->check);
		printf("IP HEADER SRC ADDR: %s\n", inet_ntoa(*(struct in_addr *)&ip_header->saddr));
		printf("IP HEADER DST ADDR: %s\n", inet_ntoa(*(struct in_addr *)&ip_header->daddr));

		if (ip_header->protocol == IPPROTO_TCP)
		{
			/*
			*	TCP Header
			*/
			tcp_header = (t_tcp_header *)(packet + sizeof(t_eth_header) + sizeof(t_ip_header));
			printf("RECV PACKET FROM PORT %d TO PORT %d\n", ntohs(tcp_header->source), ntohs(tcp_header->dest));

			port_listener_add(ntohs(tcp_header->source), (uint8_t *)ip_header); // we add the ip header to still have the informations about the type of packet recevied (tcp/udp/icmp...)

			if (g_packet_lists.size == 10)
				display_packet_list();
		}
	}
}

int	port_listener_init(t_port_listener *const listener, uint32_t ip_address, t_vector *const port)
{
	memset(listener, 0, sizeof(t_port_listener));

	listener->targeted_address = ip_address;

	listener->device_name = "lo"; // @warning may be the cause of crash later !!! @todo change this for user input !!!
	// pcap_if_t *device_list = NULL;		// @warning need to free this list !
	// pcap_findalldevs(&device_list, listener->error_buff);
	// listener->device_name = device_list->name;


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
	*	2. An integer:	defines the maximum number of bytes to capture. 262144 should be enough or BUFSIZ
	*	3. An integer:	set the interface into promiscuous mode.
	*	4. An integer:	is the time it wait for a response before timeout.
	*	5. An array:	the buffer that will hold any error message.	
	*/
	listener->handle = pcap_open_live(listener->device_name, 262144, 1, 100, listener->error_buff);
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

	pcap_set_timeout(listener->handle, 10000);

	// the process will stay stuck here due to an infinite loop.
	if (pcap_loop(listener->handle, 0, &_individual_net_packet_handler, NULL) == -1) // last	 param is args value, i will probably not use it.
	{
		fprintf(stderr, "pcap_loop() error\n");
		fprintf(stderr, "Couldn't launch the pcap loop\n");

		printf("ERROR ERROR ERROR :%s\n", pcap_geterr(listener->handle));
		
		return (NULL);
	}

	printf("after pcap_loop hehe !!!!!!!!!!!!!!!!!!!\n");

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
