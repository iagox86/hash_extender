#ifdef FREEBSD
#include <sys/endian.h>
#else
#include <endian.h>
#endif

#include <stdint.h>
#include <openssl/sha.h>

void sha256_hash(uint8_t *data, uint64_t length, uint8_t *buffer, uint8_t *state, uint64_t state_size)
{
  uint64_t i;

  SHA256_CTX c;
  SHA256_Init(&c);

  if(state)
  {
    for(i = 0; i < state_size; i++)
      SHA256_Update(&c, "A", 1);

    c.h[0] = htobe32(((int*)state)[0]);
    c.h[1] = htobe32(((int*)state)[1]);
    c.h[2] = htobe32(((int*)state)[2]);
    c.h[3] = htobe32(((int*)state)[3]);
    c.h[4] = htobe32(((int*)state)[4]);
    c.h[5] = htobe32(((int*)state)[5]);
    c.h[6] = htobe32(((int*)state)[6]);
    c.h[7] = htobe32(((int*)state)[7]);
  }

  SHA256_Update(&c, data, length);
  SHA256_Final(buffer, &c);
}
