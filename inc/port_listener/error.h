/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   error.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: alde-fre <alde-fre@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/06 13:02:20 by alde-fre          #+#    #+#             */
/*   Updated: 2024/09/06 16:04:09 by alde-fre         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef PORT_LISTENER_ERROR_H
# define PORT_LISTENER_ERROR_H

typedef enum e_port_listener_error
{
	PORT_LISTENER_SUCCESS = 0,
	PORT_LISTENER_FAILURE,
	PORT_LISTENER_MEMORY_FAILURE,
	PORT_LISTENER_CRITICAL_FAILURE,

	PORT_LISTENER_FIND_DEVICE_ERROR,
} t_port_listener_error;

#endif