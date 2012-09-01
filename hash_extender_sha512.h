#ifndef __HASH_EXTENDER_SHA512_H__
#define __HASH_EXTENDER_SHA512_H__

#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "util.h"

#define SHA512_BLOCK 64

uint8_t *sha512_append_data(uint8_t *data, size_t data_length, size_t secret_length, uint8_t *append, size_t append_length, size_t *new_length);
void sha512_gen_signature(uint8_t *secret, size_t secret_length, uint8_t *data, size_t data_length, uint8_t signature[SHA512_DIGEST_LENGTH]);
void sha512_gen_signature_evil(size_t secret_length, size_t data_length, uint8_t original_signature[SHA512_DIGEST_LENGTH], uint8_t *append, size_t append_length, uint8_t new_signature[SHA512_DIGEST_LENGTH]);

/* Test code */
void sha512_test();

#endif
