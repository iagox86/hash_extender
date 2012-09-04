#ifndef __HASH_EXTENDER_SHA256_H__
#define __HASH_EXTENDER_SHA256_H__

#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "util.h"

#define SHA256_BLOCK 64

uint8_t *sha256_append_data(uint8_t *data, uint64_t data_length, uint64_t secret_length, uint8_t *append, uint64_t append_length, uint64_t *new_length);
void sha256_gen_signature(uint8_t *secret, uint64_t secret_length, uint8_t *data, uint64_t data_length, uint8_t signature[SHA256_DIGEST_LENGTH]);
void sha256_gen_signature_evil(uint64_t secret_length, uint64_t data_length, uint8_t original_signature[SHA256_DIGEST_LENGTH], uint8_t *append, uint64_t append_length, uint8_t new_signature[SHA256_DIGEST_LENGTH]);

/* Test code */
void sha256_test();

#endif
