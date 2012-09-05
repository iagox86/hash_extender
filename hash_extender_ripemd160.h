#ifndef __HASH_EXTENDER_RIPEMD160_H__
#define __HASH_EXTENDER_RIPEMD160_H__

#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <openssl/ripemd.h>

#include "util.h"

#define RIPEMD160_BLOCK 64

uint8_t *ripemd160_append_data(uint8_t *data, uint64_t data_length, uint64_t secret_length, uint8_t *append, uint64_t append_length, uint64_t *new_length);
void ripemd160_gen_signature(uint8_t *secret, uint64_t secret_length, uint8_t *data, uint64_t data_length, uint8_t signature[RIPEMD160_DIGEST_LENGTH]);
void ripemd160_gen_signature_evil(uint64_t secret_length, uint64_t data_length, uint8_t original_signature[RIPEMD160_DIGEST_LENGTH], uint8_t *append, uint64_t append_length, uint8_t new_signature[RIPEMD160_DIGEST_LENGTH]);

/* Test code */
void ripemd160_test();

#endif
