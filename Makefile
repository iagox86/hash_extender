LIBS=-lcurl -lssl

all: ext_owner

ext_owner: ext_owner.c
	gcc $(LIBS) -Wall -Werror -o ext_owner ext_owner.c

