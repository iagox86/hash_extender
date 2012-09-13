#ifdef FREEBSD
#include <sys/endian.h>
#else
#include <endian.h>
#endif

#include <stdint.h>
#include <openssl/sha.h>

void sha512_hash(uint8_t *data, uint64_t length, uint8_t *buffer, uint8_t *state, uint64_t state_size)
{
  uint64_t i;

  SHA512_CTX c;
  SHA512_Init(&c);

  if(state)
  {
    for(i = 0; i < state_size; i++)
      SHA512_Update(&c, "A", 1);

      c.h[0] = htobe64(((uint64_t*)state)[0]);
      c.h[1] = htobe64(((uint64_t*)state)[1]);
      c.h[2] = htobe64(((uint64_t*)state)[2]);
      c.h[3] = htobe64(((uint64_t*)state)[3]);
      c.h[4] = htobe64(((uint64_t*)state)[4]);
      c.h[5] = htobe64(((uint64_t*)state)[5]);
      c.h[6] = htobe64(((uint64_t*)state)[6]);
      c.h[7] = htobe64(((uint64_t*)state)[7]);
  }

  SHA512_Update(&c, data, length);
  SHA512_Final(buffer, &c);
}
