#ifndef __HASH_EXTENDER_MD5_H__
#define __HASH_EXTENDER_MD5_H__

#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <openssl/md5.h>

#include "util.h"

#define MD5_BLOCK 64

uint8_t *md5_append_data(uint8_t *data, uint64_t data_length, uint64_t secret_length, uint8_t *append, uint64_t append_length, uint64_t *new_length);
void md5_gen_signature(uint8_t *secret, uint64_t secret_length, uint8_t *data, uint64_t data_length, uint8_t signature[MD5_DIGEST_LENGTH]);
void md5_gen_signature_evil(uint64_t secret_length, uint64_t data_length, uint8_t original_signature[MD5_DIGEST_LENGTH], uint8_t *append, uint64_t append_length, uint8_t new_signature[MD5_DIGEST_LENGTH]);

/* Test code */
void md5_test();

#endif
