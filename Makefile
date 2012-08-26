CFLAGS=-std=c89 -g -oS -Wall -Werror
LIBS=-lssl

all: hash_extender

hash_extender: hash_extender.o hash_extender_sha1.o hash_extender_md5.o util.o
	gcc -o hash_extender $(LIBS) hash_extender.o hash_extender_sha1.o hash_extender_md5.o util.o

clean:
	rm -f *.o
	rm -f hash_extender

