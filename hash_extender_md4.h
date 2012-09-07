#ifndef __HASH_EXTENDER_MD4_H__
#define __HASH_EXTENDER_MD4_H__

#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <openssl/md4.h>

#include "util.h"

#define MD4_BLOCK 64

uint8_t *md4_append_data(uint8_t *data, uint64_t data_length, uint64_t secret_length, uint8_t *append, uint64_t append_length, uint64_t *new_length);
void md4_gen_signature(uint8_t *secret, uint64_t secret_length, uint8_t *data, uint64_t data_length, uint8_t signature[]);
void md4_gen_signature_evil(uint64_t secret_length, uint64_t data_length, uint8_t original_signature[], uint8_t *append, uint64_t append_length, uint8_t new_signature[]);

/*typedef void(append_data_t)(uint8_t *data, uint64_t data_length, uint64_t secret_length, uint8_t *append, uint64_t append_length, uint64_t *new_length);
typedef void(gen_signature_t)(uint8_t *secret, uint64_t secret_length, uint8_t *data, uint64_t data_length, uint8_t signature[]);
typedef void(gen_signature_evil_t)(uint64_t secret_length, uint64_t data_length, uint8_t original_signature[], uint8_t *append, uint64_t append_length, uint8_t new_signature[]); */
/* Test code */
void md4_test();

#endif
