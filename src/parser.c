/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parser.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: alde-fre <alde-fre@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/08/05 17:27:44 by alde-fre          #+#    #+#             */
/*   Updated: 2024/08/06 10:54:34 by alde-fre         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

# include "ft_nmap/ft_nmap.h"

// @brief Gather the arguments and fill the nmap options structure accordingly
// @param argc The main number of arguments
// @param argv The main arguments
// @param options The nmap options structure to fill
int nmap_parse(int argc, char **argv, t_nmap_options *const options)
{
	t_vector	token;
	char		*tmp;
	int			i;

	token = vector_create(sizeof(char *));
	if (token.data == NULL)
		return (1);

	i = 0;
	while (++i < argc)
	{
		tmp = ft_strtok(argv[i], " ");
		while (tmp != NULL)
		{
			vector_addback(&token, &tmp);
			tmp = ft_strtok(NULL, " ");
		}
	}

	// @todo PARSE TOKENS
	return (0);
}