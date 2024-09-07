/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   error.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: alde-fre <alde-fre@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/06 11:11:20 by alde-fre          #+#    #+#             */
/*   Updated: 2024/09/06 13:17:16 by alde-fre         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef NMAP_ERROR_H
# define NMAP_ERROR_H

typedef enum e_nmap_error
{
	NMAP_SUCCESS			= 0,
	NMAP_FAILURE,
	NMAP_MEMORY_FAILURE,
	NMAP_CRITICAL_FAILURE,
} t_nmap_error;

#endif
