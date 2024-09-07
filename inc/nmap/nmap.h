/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   nmap.h                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: alde-fre <alde-fre@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/09/06 10:50:22 by alde-fre          #+#    #+#             */
/*  Updated: 2024/09/06 13:06:40 by alde-fre         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

/*
 *	This file exist to isolate every bit of code from the user.
 */

#ifndef NMAP_H
# define NMAP_H

# include "nmap/error.h"
# include "nmap/struct.h"

/*
 *	./ft_nmap --help
 *	Help Screen
 *	ft_nmap [OPTIONS]
 *	--help Print this help screen
 *	--ports ports to scan (eg: 1-10 or 1,2,3 or 1,5-15)
 *	--ip ip addresses to scan in dot format
 *	--file File name containing IP addresses to scan,
 *	--speedup [250 max] number of parallel threads to use
 *	--scan SYN/NULL/FIN/XMAS/ACK/UDP
 */

/* options can be:
 *	- destination address
 *	- ports to scan
 *	- number of threads
 *	- scan type				// a way to store every types we need for the scans
 */

/*
 *	Do this number of options justify them to be stored in a structure ?
 */

t_nmap_error	nmap_scan(uint32_t target_address, t_vector *ports);

#endif