/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   listener.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: alde-fre <alde-fre@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/08/09 08:20:10 by alde-fre          #+#    #+#             */
/*   Updated: 2024/08/09 12:00:16 by alde-fre         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <pcap.h>

#include "net.h"

typedef struct s_port_listener
{
	uint32_t			targeted_address;

	pcap_t				*handle;
	char				error_buff[PCAP_ERRBUF_SIZE];
	char				*device_name;
	bpf_u_int32			address;
	bpf_u_int32			mask;

	struct bpf_program	compiled_expression;	// might end up being individual to each threads (maybe even each port !).
}	t_port_listener;

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

// typedef void (*pcap_handler)(u_char *, const struct pcap_pkthdr *, const u_char *);
// pcap_handler;

static void	_individual_net_packet_handler(uint8_t *args, const struct pcap_pkthdr *pkthdr, const uint8_t *packet)
{
	
}

static inline int	__port_listener_init(t_port_listener *const listener, uint32_t ip_address, t_vector *const port)
{
	listener->targeted_address = ip_address;

	listener->device_name = "enp0s3"; // @warning: may be the cause of crash later !!! @todo: change this for user input !!!

	printf("listening to: %s\n", inet_ntoa((struct in_addr){listener->targeted_address}));
	printf("libpcap_device_name: %s\n", listener->device_name);

	/*
	*	This function gather an address and a mask related to the network.
	*
	*	It is essential because we need to have the network mask to apply
	*	 filters to the packet listener->
	*/
	if (pcap_lookupnet(listener->device_name, &listener->address, &listener->mask, listener->error_buff) == -1)
	{
		fprintf(stderr, "pcap_lookupnet() error\n");
		fprintf(stderr, "Can't get netmask for device %s\n", listener->device_name);
		return (1);
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
	listener->handle = pcap_open_live(listener->device_name, 1, 1, 1000, listener->error_buff);
	if (listener->handle == NULL)
	{
		fprintf(stderr, "pcap_open_live() error\n");
		fprintf(stderr, "Couldn't open device %s: %s\n", listener->device_name, listener->error_buff);
		return (2);
	}

	/*
	*	This function verifies that the selected device provides the necessary link-layer header.
	*
	*	In our case it is the 'Ethernet (10Mb)' layer equivalent to the flag 'DLT_EN10MB'.
	*/
	if (pcap_datalink(listener->handle) != DLT_EN10MB)
	{
		fprintf(stderr, "pcap_datalink() error\n");
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", listener->error_buff);
		return (3);
	}

	/*
	*	The expression is the non compiled code that will be used to filter data on the network.
	*
	*	Note:
	*	 For more information go to this website: https://www.tcpdump.org/manpages/pcap-filter.7.html
	*/
	char raw_expression[64] = {0};
	strcat(raw_expression, "src net ");
	strcat(raw_expression, inet_ntoa((struct in_addr){listener->targeted_address}));

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
		return (4);
	}

	/*
	*	Now that we have our handle, and our compiled expression, and a device that accepts ethernet packets,
	*	 we can apply the expression to the device and praise for it to work. (please... https://c.tenor.com/fP1Qr3rwSHkAAAAC/tenor.gif)
	*/
	if (pcap_setfilter(listener->handle, &listener->compiled_expression))
	{
		fprintf(stderr, "pcap_setfilter() error\n");
		fprintf(stderr, "Couldn't install filter %s: %s\n", raw_expression, pcap_geterr(listener->handle));
		return (5);
	}
}

static inline void	__port_listener_destroy(t_port_listener *const listener)
{
	if (listener->handle != NULL)
	{
		if (listener->compiled_expression.bf_insns != NULL)
			pcap_freecode(&listener->compiled_expression);
		pcap_close(listener->handle);
	}
}

/*
*	Note that this function should take a pcap handle as an argument or return one, so that we can stop the pcap loop from outside.
*/
int	port_listener(uint32_t ip_address, t_vector *const port)
{
	t_port_listener	listener;

	if (__port_listener_init(&listener, ip_address, port))
	{
		__port_listener_destroy(&listener);
		return (1);
	}

	pcap_loop(listener.handle, NULL, (pcap_handler)&_individual_net_packet_handler, NULL); // last param is args value, i will probably 

	// qsort();

	__port_listener_destroy(&listener);
	return (0);
}
