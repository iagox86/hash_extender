CFLAGS=-std=c89 -g -oS
LIBS=-lssl

all: hash_extender

hash_extender: hash_extender.c
	gcc $(LIBS) $(CFLAGS) -Wall -Werror -o hash_extender hash_extender.c

