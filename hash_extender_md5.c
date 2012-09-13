#ifdef FREEBSD
#include <sys/endian.h>
#else
#include <endian.h>
#endif

#include <stdint.h>
#include <openssl/md5.h>

void md5_hash(uint8_t *data, uint64_t length, uint8_t *buffer, uint8_t *state, uint64_t state_size)
{
  uint64_t i;

  MD5_CTX c;
  MD5_Init(&c);

  if(state)
  {
    for(i = 0; i < state_size; i++)
      MD5_Update(&c, "A", 1);

    c.A = htole32(((int*)state)[0]);
    c.B = htole32(((int*)state)[1]);
    c.C = htole32(((int*)state)[2]);
    c.D = htole32(((int*)state)[3]);
  }

  MD5_Update(&c, data, length);
  MD5_Final(buffer, &c);
}
