# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: alde-fre <alde-fre@student.42.fr>          +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2022/11/25 09:39:09 by alde-fre          #+#    #+#              #
#    Updated: 2024/08/16 14:56:47 by alde-fre         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

### BASE ###

NAME = ft_nmap

SRC_DIR	=  ./src
INC_DIR	= -I ./inc
OBJ_DIR	= ./obj

### LIBS ###

LIBVEC = libvector.a

LIBVEC_DIR = ./lib/libvector
LIBVEC_INC = -I $(LIBVEC_DIR)/inc

### SOURCES ###

SRC		=	ft_nmap.c \
			net/packet.c \
			net/listener.c \
			\
			main.c


### OBJECTS ###

OBJ		= $(addprefix $(OBJ_DIR)/,$(SRC:.c=.o))

### COMPILATION ###

CC		= cc
CFLAGS	= -MMD -MP -Wall -Wextra -Werror


### RULES ###

all: $(LIBVEC) obj $(NAME)

bonus: $(LIBVEC) obj $(NAME_BONUS)

raw: CFLAGS += -O0
raw: all

fast: CFLAGS += -Ofast
fast: all

debug: CFLAGS += -g3
debug: all

.print:
	@> $@
	@echo "\e[1;36mCompiling...\e[0m"

obj:
	@rm -rf .print
	@mkdir -p $(OBJ_DIR)

$(NAME): $(OBJ)
	@echo "\e[1;35mLinking...\e[0m"
	@$(CC) -pg -o $@ $+ -lpthread -lpcap -L $(LIBVEC_DIR) -l vector
	@echo "\e[1;32m➤" $@ "created succesfully !\e[0m"

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c .print
	@echo "\e[0;36m ↳\e[0;36m" $<"\e[0m"
	@mkdir -p $(@D)
	@$(CC) $(CFLAGS) $(INC_DIR) $(LIBVEC_INC) -c $< -o $@

temp:
	@echo "\e[1;36mCompiling...\e[0m";



$(LIBVEC):
	@make -C $(LIBVEC_DIR)


clean:
	rm -rf $(OBJ_DIR)

fclean: clean
	rm -rf $(NAME)

re: fclean all

.PHONY: all clean fclean re
