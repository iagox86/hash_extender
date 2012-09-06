CFLAGS=-std=c89 -g -oS -Wall -Werror -D_BSD_SOURCE
LIBS=-lssl -lcrypto

all: hash_extender hash_extender_test

hash_extender_test: hash_extender_test.o hash_extender_md4.o hash_extender_md5.o hash_extender_ripemd160.o hash_extender_sha.o hash_extender_sha1.o hash_extender_sha256.o hash_extender_sha512.o hash_extender_whirlpool.o test.o util.o
	gcc -o hash_extender_test hash_extender_test.o hash_extender_md4.o hash_extender_md5.o hash_extender_ripemd160.o hash_extender_sha.o hash_extender_sha1.o hash_extender_sha256.o hash_extender_sha512.o hash_extender_whirlpool.o test.o util.o $(LIBS)

hash_extender: hash_extender.o hash_extender_md4.o hash_extender_md5.o hash_extender_ripemd160.o hash_extender_sha.o hash_extender_sha1.o hash_extender_sha256.o hash_extender_sha512.o hash_extender_whirlpool.o test.o util.o
	gcc -o hash_extender hash_extender.o hash_extender_md4.o hash_extender_md5.o hash_extender_ripemd160.o hash_extender_sha.o hash_extender_sha1.o hash_extender_sha256.o hash_extender_sha512.o hash_extender_whirlpool.o test.o util.o $(LIBS)

clean:
	rm -f *.o *.exe
	rm -f hash_extender hash_extender_test

