/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   port_listener.h                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: alde-fre <alde-fre@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/06 13:13:47 by alde-fre          #+#    #+#             */
/*   Updated: 2024/09/06 18:04:10 by alde-fre         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef PORT_LISTENER_H
# define PORT_LISTENER_H

# include "port_listener/error.h"
# include "port_listener/struct.h"

// should be stoppable by SIGKILL
t_port_listener_error	port_listener_start(uint32_t target_address, t_vector *ports);

#endif