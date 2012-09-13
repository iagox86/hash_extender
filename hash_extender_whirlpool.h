#ifndef DISABLE_WHIRLPOOL

#ifndef __HASH_EXTENDER_WHIRLPOOL_H__
#define __HASH_EXTENDER_WHIRLPOOL_H__

#include <stdint.h>
#include <openssl/whrlpool.h>

void whirlpool_hash(uint8_t *data, uint64_t length, uint8_t *buffer, uint8_t *state, uint64_t state_size);

#endif
#endif
