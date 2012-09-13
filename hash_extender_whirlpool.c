#ifndef DISABLE_WHIRLPOOL

#include <stdint.h>
#include <string.h>
#include <openssl/whrlpool.h>

void whirlpool_hash(uint8_t *data, uint64_t length, uint8_t *buffer, uint8_t *state, uint64_t state_size)
{
  uint64_t i;

  WHIRLPOOL_CTX c;
  WHIRLPOOL_Init(&c);

  if(state)
  {
    for(i = 0; i < state_size; i++)
      WHIRLPOOL_Update(&c, "A", 1);
    memcpy(c.H.c, state, WHIRLPOOL_DIGEST_LENGTH);
  }

  WHIRLPOOL_Update(&c, data, length);
  WHIRLPOOL_Final(buffer, &c);
}

#endif
