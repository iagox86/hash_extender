CFLAGS=-std=c89 -g -oS
LIBS=-lssl

all: ext_owner

ext_owner: ext_owner.c
	gcc $(LIBS) $(CFLAGS) -Wall -Werror -o ext_owner ext_owner.c

