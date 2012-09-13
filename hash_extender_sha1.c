#ifdef FREEBSD
#include <sys/endian.h>
#else
#include <endian.h>
#endif

#include <stdint.h>
#include <openssl/sha.h>

void sha1_hash(uint8_t *data, uint64_t length, uint8_t *buffer, uint8_t *state, uint64_t state_size)
{
  uint64_t i;

  SHA_CTX c;
  SHA1_Init(&c);

  if(state)
  {
    for(i = 0; i < state_size; i++)
      SHA1_Update(&c, "A", 1);

    c.h0 = htobe32(((int*)state)[0]);
    c.h1 = htobe32(((int*)state)[1]);
    c.h2 = htobe32(((int*)state)[2]);
    c.h3 = htobe32(((int*)state)[3]);
    c.h4 = htobe32(((int*)state)[4]);
  }

  SHA1_Update(&c, data, length);
  SHA1_Final(buffer, &c);
}
