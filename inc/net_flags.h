/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   net_flags.h                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: alde-fre <alde-fre@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/04 11:23:06 by alde-fre          #+#    #+#             */
/*   Updated: 2024/09/04 11:32:06 by alde-fre         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef NET_FLAGS_H
# define NET_FLAGS_H

# define TCP_FLAG_FIN		0x01
# define TCP_FLAG_SYN		0x02
# define TCP_FLAG_RST		0x04
# define TCP_FLAG_PSH		0x08
# define TCP_FLAG_ACK		0x10
# define TCP_FLAG_URG		0x20
# define TCP_FLAG_ECE		0x40
# define TCP_FLAG_CWR		0x80

# define ETH_TYPE_IP		0x0800

/*
*	Just changed this macro, to let it handle multiple flags at once
*
*	The old version is this:
*	'# define TCP_GET_FLAGS(FLAGS, KEY)	(((FLAGS) & ((KEY) >> 4)) != 0)'
*
*	Alan De Freitas - 08/08/2024
*/
# define TCP_GET_FLAGS(FLAGS, KEY)	(((FLAGS) & ((KEY) >> 4)) == ((KEY) >> 4))
# define TCP_SET_FLAGS(FLAGS, KEY)	(((FLAGS) | ((KEY) >> 4)))

#endif