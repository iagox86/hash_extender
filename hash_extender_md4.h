#ifndef __HASH_EXTENDER_MD4_H__
#define __HASH_EXTENDER_MD4_H__

#include <openssl/md4.h>
#include <stdint.h>

void md4_hash(uint8_t *data, uint64_t length, uint8_t *buffer, uint8_t *state, uint64_t state_size);
uint8_t *md4_append_data(uint8_t *data, uint64_t data_length, uint64_t secret_length, uint8_t *append, uint64_t append_length, uint64_t *new_length);

#endif
