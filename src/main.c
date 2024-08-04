/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: alde-fre <alde-fre@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/08/04 14:23:39 by alde-fre          #+#    #+#             */
/*   Updated: 2024/08/04 18:07:58 by alde-fre         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdio.h>
#include <stdlib.h>

#include "vector.h"

int	main(void)
{
	t_vector vec = vector_create(sizeof(int));

	printf("Hello World !\n");

	vector_addback(&vec, &(int){42});
	vector_addback(&vec, &(int){21});
	vector_addback(&vec, &(int){84});
	vector_addback(&vec, &(int){168});
	vector_addback(&vec, &(int){336});
	vector_addback(&vec, &(int){672});
	vector_addback(&vec, &(int){1344});

	for (size_t i = 0; i < vec.size; i++)
	{
		printf("vec[%zu] = %d\n", i, *(int *)vector_get(&vec, i));
	}

	vector_destroy(&vec);
}