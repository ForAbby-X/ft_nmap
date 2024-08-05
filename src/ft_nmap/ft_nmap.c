/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_nmap.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: alde-fre <alde-fre@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/08/04 16:19:12 by alde-fre          #+#    #+#             */
/*   Updated: 2024/08/05 17:26:48 by alde-fre         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <sys/select.h>
#include <pthread.h>

#include "ft_nmap/ft_nmap.h"
#include "vector.h"

/// LOCAL STRUCTURE ///

/// MANAGER FUNCTIONS ///

static inline int	__nmap_scan_create(t_nmap *const nmap, t_nmap_options const *const options)
{
	*nmap = (t_nmap){0};

	// threads array
	nmap->threads = vector_create_s(sizeof(t_nmap_thread), options->number_of_thread);
	if (nmap->threads.data == NULL)
		return (1);

	vector_resize(&nmap->threads, options->number_of_thread);

	// file descriptor set
	FD_ZERO(&nmap->open_fd);
	
	return (0);
}

static inline int	__nmap_scan_init(t_nmap *const nmap, t_nmap_options const *const options)
{
	// @todo PROBABLY USELESS
	(void)nmap;
	(void)options;
	return (0);
}


static inline void	__nmap_scan_free(t_nmap *const nmap)
{
	if (nmap->threads.data != NULL)
		vector_destroy(&nmap->threads);
}


/// ACTUAL SCANNING FUNCTIONS ///

static inline int	_nmap_scan_port(t_nmap *const nmap, t_nmap_options const *const options, int port)
{
	// @todo EXECUTE SCAN
	(void)nmap;

	printf("Scanning port %d\n", port);

	// @todo conditional for each type of scan
	int socket_fd = socket(options->sock_domain, SOCK_RAW, options->sock_protocol);
	(void)socket_fd;
	
	return (0);
}

static void	*_nmap_thread_wrapper(void *arg)
{
	t_nmap_thread *const nmap_thread = arg;

	for (t_length i = 0; i < nmap_thread->port_size; ++i)
		_nmap_scan_port(nmap_thread->nmap, nmap_thread->options, nmap_thread->port_array[i]);
	
	return (arg);
}

static inline int	__nmap_scan_content(t_nmap *const nmap, t_nmap_options const *const options)
{
	t_length 		size_of_array = options->ports_to_scan.size / options->number_of_thread;
	int				total_remain = options->ports_to_scan.size % options->number_of_thread;

	int				*port_array = (int *)options->ports_to_scan.data;
	t_nmap_thread	*threads_list = (t_nmap_thread *)nmap->threads.data;
	for (t_length i = 0; i < nmap->threads.size; ++i)
	{
		t_length current_array_size = size_of_array + (total_remain-- > 0);

		threads_list[i].nmap = nmap;
		threads_list[i].options = (t_nmap_options *)options;
		threads_list[i].port_array = port_array;
		threads_list[i].port_size = current_array_size;

		printf("Launching thread %u: at %p with %u\n", i, threads_list[i].port_array, threads_list[i].port_size);

		port_array += current_array_size;

		pthread_create(&threads_list[i].thread_ptr, NULL, _nmap_thread_wrapper, threads_list + i);
	}

	// wait for all threads to finish
	for (t_length i = 0; i < nmap->threads.size; ++i)
		pthread_join(threads_list[i].thread_ptr, NULL);

	return (0);
}

int	nmap_scan(t_nmap_options *const options)
{
	t_nmap	nmap;

	if (options->number_of_thread > options->ports_to_scan.size)
	{
		printf("WARNING: Number of thread is greater than number of ports to scan\n");
		printf("WARNING: Number of thread lowered to %u\n", options->ports_to_scan.size);
		options->number_of_thread = options->ports_to_scan.size;
	}

	if (__nmap_scan_create(&nmap, options) || __nmap_scan_init(&nmap, options))
	{
		__nmap_scan_free(&nmap);
		return (1);
	}

	__nmap_scan_content(&nmap, options);

	__nmap_scan_free(&nmap);
	return (0);
}
