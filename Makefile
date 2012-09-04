CFLAGS=-std=c89 -g -oS -Wall -Werror -D_BSD_SOURCE
LIBS=-lssl -lcrypto

all: hash_extender_test

hash_extender_test: hash_extender_test.o hash_extender_sha1.o hash_extender_sha256.o hash_extender_sha512.o hash_extender_md5.o test.o util.o
	gcc -o hash_extender_test hash_extender_test.o hash_extender_sha1.o hash_extender_sha256.o hash_extender_sha512.o hash_extender_md5.o test.o util.o $(LIBS)

clean:
	rm -f *.o *.exe
	rm -f hash_extender hash_extender_test

