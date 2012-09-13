#ifndef __HASH_EXTENDER_MD5_H__
#define __HASH_EXTENDER_MD5_H__

#include <stdint.h>
#include <openssl/md5.h>

void md5_hash(uint8_t *data, uint64_t length, uint8_t *buffer, uint8_t *state, uint64_t state_size);

#endif
