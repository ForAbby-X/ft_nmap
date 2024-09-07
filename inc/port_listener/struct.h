/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   struct.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: alde-fre <alde-fre@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/06 10:55:52 by alde-fre          #+#    #+#             */
/*   Updated: 2024/09/06 22:47:39 by alde-fre         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef PORT_LISTENER_STRUCT_H
# define PORT_LISTENER_STRUCT_H

# include <pcap.h>
# include "vector.h"

typedef struct s_port_listener	t_port_listener;
typedef struct s_packet			t_packet;

struct s_port_listener
{
	uint32_t			address;
	char				*device_name;
	pcap_t				*handle;
	
	struct bpf_program	compiled_expression;			// might end up being individual to each threads (maybe even each port !).
														// ... *sigh* i will only use it for init. after all it is not necessary to keep it...

	t_vector			received_packets;				// : [port, vector(uint8_t *)]
};



#endif