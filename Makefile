CFLAGS=-std=c89 -g -oS #-Wall -Werror
LIBS=-lssl

all: hash_extender_test

hash_extender_test: hash_extender_test.o hash_extender_sha1.o hash_extender_md5.o test.o util.o
	gcc -o hash_extender_test $(LIBS) hash_extender_test.o hash_extender_sha1.o hash_extender_md5.o test.o util.o

clean:
	rm -f *.o
	rm -f hash_extender hash_extender_test

