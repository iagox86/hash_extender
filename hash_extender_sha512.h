#ifndef __HASH_EXTENDER_SHA512_H__
#define __HASH_EXTENDER_SHA512_H__

#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "util.h"

#define SHA512_BLOCK 64

void sha512_hash(uint8_t *data, uint64_t length, uint8_t *buffer, uint8_t *state, uint64_t state_size);

uint8_t *sha512_append_data(uint8_t *data, uint64_t data_length, uint64_t secret_length, uint8_t *append, uint64_t append_length, uint64_t *new_length);
void sha512_gen_signature(uint8_t *secret, uint64_t secret_length, uint8_t *data, uint64_t data_length, uint8_t signature[SHA512_DIGEST_LENGTH]);
void sha512_gen_signature_evil(uint64_t secret_length, uint64_t data_length, uint8_t original_signature[SHA512_DIGEST_LENGTH], uint8_t *append, uint64_t append_length, uint8_t new_signature[SHA512_DIGEST_LENGTH]);

/* Test code */
void sha512_test();

#endif
