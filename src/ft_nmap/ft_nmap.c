/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: alde-fre <alde-fre@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/08/04 16:19:12 by alde-fre          #+#    #+#             */
/*   Updated: 2024/08/04 18:16:56 by alde-fre         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <sys/select.h>
#include <pthread.h>

#include "ft_nmap/ft_nmap.h"
#include "vector.h"

/// LOCAL STRUCTURE ///

typedef struct s_nmap
{
	t_vector	ports_to_scan;	// vector of all the ports to scan
	t_vector	threads;		// vector of all the working threads
	fd_set		open_fd;		// set of all the open file descriptors
	// @todo ADD IP ADDRESS
	// @todo ADD OPTION FLAGS
}	t_nmap;

/// FUNCTION ///

static inline int	__nmap_scan_init(t_nmap *nmap)
{
	nmap->ports_to_scan = vector_create(sizeof(int));
	if (nmap->ports_to_scan.data == NULL)
		return (1);
	nmap->threads = vector_create(sizeof(pthread_t));
	if (nmap->threads.data == NULL)
	{
		vector_destroy(&nmap->ports_to_scan);
		return (1);
	}
	FD_ZERO(&nmap->open_fd);
	return (0);
}

static inline void	__nmap_scan_free(t_nmap *nmap)
{
	if (nmap->ports_to_scan.data != NULL)
		vector_destroy(&nmap->ports_to_scan);
}

static inline int	__nmap_scan_content(t_nmap *nmap)
{
	// @todo EXECUTE SCAN
	(void)nmap;
	return (0);
}

int	nmap_scan(void)
{
	t_nmap	nmap;

	if (__nmap_scan_init(&nmap))
	{
		__nmap_scan_free(&nmap);
		return (1);
	}

	__nmap_scan_content(&nmap);

	__nmap_scan_free(&nmap);
	return (0);
}