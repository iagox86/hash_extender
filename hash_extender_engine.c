#include <arpa/inet.h>

#ifdef FREEBSD
#include <sys/endian.h>
#elif defined(__APPLE__)
  #include <libkern/OSByteOrder.h>

  #define htobe16(x) OSSwapHostToBigInt16(x)
  #define htole16(x) OSSwapHostToLittleInt16(x)
  #define be16toh(x) OSSwapBigToHostInt16(x)
  #define le16toh(x) OSSwapLittleToHostInt16(x)

  #define htobe32(x) OSSwapHostToBigInt32(x)
  #define htole32(x) OSSwapHostToLittleInt32(x)
  #define be32toh(x) OSSwapBigToHostInt32(x)
  #define le32toh(x) OSSwapLittleToHostInt32(x)

  #define htobe64(x) OSSwapHostToBigInt64(x)
  #define htole64(x) OSSwapHostToLittleInt64(x)
  #define be64toh(x) OSSwapBigToHostInt64(x)
  #define le64toh(x) OSSwapLittleToHostInt64(x)
#else
#include <endian.h>
#endif

#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>
#include <openssl/sha.h>
#include <openssl/sha.h>
#include <openssl/sha.h>
#include "tiger.h"
#ifndef DISABLE_WHIRLPOOL
#include <openssl/whrlpool.h>
#endif

#include "hash_extender_engine.h"

#include "buffer.h"
#include "test.h"
#include "util.h"

static void md4_hash(uint8_t *data, uint64_t length, uint8_t *buffer, uint8_t *state, uint64_t state_size);
static void md5_hash(uint8_t *data, uint64_t length, uint8_t *buffer, uint8_t *state, uint64_t state_size);
static void ripemd160_hash(uint8_t *data, uint64_t length, uint8_t *buffer, uint8_t *state, uint64_t state_size);
static void sha_hash(uint8_t *data, uint64_t length, uint8_t *buffer, uint8_t *state, uint64_t state_size);
static void sha1_hash(uint8_t *data, uint64_t length, uint8_t *buffer, uint8_t *state, uint64_t state_size);
static void sha256_hash(uint8_t *data, uint64_t length, uint8_t *buffer, uint8_t *state, uint64_t state_size);
static void sha512_hash(uint8_t *data, uint64_t length, uint8_t *buffer, uint8_t *state, uint64_t state_size);
static void tiger192v1_hash(uint8_t *data, uint64_t length, uint8_t *buffer, uint8_t *state, uint64_t state_size);
static void tiger192v2_hash(uint8_t *data, uint64_t length, uint8_t *buffer, uint8_t *state, uint64_t state_size);
#ifndef DISABLE_WHIRLPOOL
static void whirlpool_hash(uint8_t *data, uint64_t length, uint8_t *buffer, uint8_t *state, uint64_t state_size);
#endif

/* The hashing function that each implementation needs to impelement. */
typedef void(hash_t)(uint8_t *data, uint64_t length, uint8_t *buffer, uint8_t *state, uint64_t state_size);

/* Define a list of structs. */
typedef struct
{
  char                 *name;
  uint64_t              digest_size;
  bool                  little_endian;
  uint64_t              block_size;
  uint64_t              length_size;

  hash_t               *hash;
} hash_type_t;

static hash_type_t hash_types[] = {
  {"md4",         MD4_DIGEST_LENGTH,       true,  64,  8,  md4_hash},
  {"md5",         MD5_DIGEST_LENGTH,       true,  64,  8,  md5_hash},
  {"ripemd160",   RIPEMD160_DIGEST_LENGTH, true,  64,  8,  ripemd160_hash},
  {"sha",         SHA_DIGEST_LENGTH,       false, 64,  8,  sha_hash},
  {"sha1",        SHA_DIGEST_LENGTH,       false, 64,  8,  sha1_hash},
  {"sha256",      SHA256_DIGEST_LENGTH,    false, 64,  8,  sha256_hash},
  {"sha512",      SHA512_DIGEST_LENGTH,    false, 128, 16, sha512_hash},
  {"tiger192v1",  TIGER_DIGEST_LENGTH,     true,  64,  8,  tiger192v1_hash},
  {"tiger192v2",  TIGER_DIGEST_LENGTH,     true,  64,  8,  tiger192v2_hash},
#ifndef DISABLE_WHIRLPOOL
  {"whirlpool", WHIRLPOOL_DIGEST_LENGTH, false, 64,  32, whirlpool_hash},
#endif
  {0, 0, 0, 0, 0}
};

const char *hash_type_list =
  "md4"
  ", md5"
  ", ripemd160"
  ", sha"
  ", sha1"
  ", sha256"
  ", sha512"
  ", tiger192v1"
  ", tiger192v2"
#ifndef DISABLE_WHIRLPOOL
  ", whirlpool"
#endif
  ;

char *hash_type_array[] = {
  "md4",
  "md5",
  "ripemd160",
  "sha",
  "sha1",
  "sha256",
  "sha512",
  "tiger192v1",
  "tiger192v2",
#ifndef DISABLE_WHIRLPOOL
  "whirlpool",
#endif
  NULL
};

const uint64_t hash_type_count = (sizeof(hash_types) / sizeof(hash_type_t));

static hash_type_t *get_hash_type(char *name)
{
  int i;

 for(i = 0; hash_types[i].name; i++)
    if(!strcmp(hash_types[i].name, name))
      return &hash_types[i];

  return NULL;
}

bool hash_type_exists(char *hash_type_name)
{
  return get_hash_type(hash_type_name) != NULL;
}

uint64_t hash_type_digest_size(char *hash_type_name)
{
  return get_hash_type(hash_type_name)->digest_size;
}

/* Note: this only supports data with a 4-byte size (4.2 billion bits). */
uint8_t *hash_append_data(char *hash_type_name, uint8_t *data, uint64_t data_length, uint64_t secret_length, uint8_t *append, uint64_t append_length, uint64_t *new_length)
{
  hash_type_t *hash_type = get_hash_type(hash_type_name);
  /* Allocate memory for the new buffer (enough room for buffer + two full block (finish the current block, entire next block) + the data) */
  /* Note that this can overflow, so this can't be used in security-sensitive applications! */
  uint8_t *result = malloc(data_length + append_length + (2 * hash_type->block_size));
  uint64_t bit_length;

  /* Start with the current buffer and length. */
  memmove(result, data, data_length);
  *new_length = data_length;

  if (strcmp(hash_type_name, "tiger192v1") != 0)
  { 
    result[(*new_length)++] = 0x80;
  }
  else
  {
    result[(*new_length)++] = 0x01;
  }
  
  while(((*new_length + secret_length) % hash_type->block_size) != (hash_type->block_size - hash_type->length_size))
    result[(*new_length)++] = 0x00;

  /* Convert the original length to bits so we can append it. */
  bit_length = (secret_length + data_length) * 8;

  /* Get to within exactly 8 bytes of the end (since we only store 64-bits of length).
   * If we ever need sizes bigger than 64 bits, this needs to change. */
  while(((*new_length + secret_length) % hash_type->block_size) != (hash_type->block_size - 8))
    result[(*new_length)++] = 0x00;

  /* Set the last 8 bytes of result to the new length with the appropriate
   * endianness. sha512 has room for 16 bytes of size, and whirlpool has room
   * for 32 bytes, but that's not necessary. If we implement a little endian
   * algorithm with >8 bytes of size, this will need to be fixed. */
  if(hash_type->little_endian)
  {
    result[(*new_length)++] = (bit_length >>  0) & 0x000000FF;
    result[(*new_length)++] = (bit_length >>  8) & 0x000000FF;
    result[(*new_length)++] = (bit_length >> 16) & 0x000000FF;
    result[(*new_length)++] = (bit_length >> 24) & 0x000000FF;
    result[(*new_length)++] = (bit_length >> 32) & 0x000000FF;
    result[(*new_length)++] = (bit_length >> 40) & 0x000000FF;
    result[(*new_length)++] = (bit_length >> 48) & 0x000000FF;
    result[(*new_length)++] = (bit_length >> 56) & 0x000000FF;
  }
  else
  {
    result[(*new_length)++] = (bit_length >> 56) & 0x000000FF;
    result[(*new_length)++] = (bit_length >> 48) & 0x000000FF;
    result[(*new_length)++] = (bit_length >> 40) & 0x000000FF;
    result[(*new_length)++] = (bit_length >> 32) & 0x000000FF;
    result[(*new_length)++] = (bit_length >> 24) & 0x000000FF;
    result[(*new_length)++] = (bit_length >> 16) & 0x000000FF;
    result[(*new_length)++] = (bit_length >>  8) & 0x000000FF;
    result[(*new_length)++] = (bit_length >>  0) & 0x000000FF;
  }

  /* Add the appended data to the end of the buffer. */
  memcpy(result + (*new_length), append, append_length);
  *new_length += append_length;

  return result;
}

void hash_gen_signature(char *hash_type_name, uint8_t *secret, uint64_t secret_length, uint8_t *data, uint64_t data_length, uint8_t *signature)
{
  uint8_t *buffer;
  uint64_t buffer_size;
  hash_type_t *hash_type = get_hash_type(hash_type_name);

  /* Create a buffer and add the two strings to it. This is equivalent to
   * calling the hash's _Update() function twice, but the hash_type->hash
   * function doesn't support that type of interface so we generate the entire
   * string first. */
  buffer_t *b = buffer_create(BO_HOST);
  buffer_add_bytes(b, secret, secret_length);
  buffer_add_bytes(b, data, data_length);
  buffer = buffer_create_string_and_destroy(b, &buffer_size);

  /* Hash it using the appropriate function. */
  hash_type->hash(buffer, buffer_size, signature, NULL, 0);
  free(buffer);
}

void hash_gen_signature_evil(char *hash_type_name, uint64_t secret_length, uint64_t data_length, uint8_t original_signature[], uint8_t *append, uint64_t append_length, uint8_t *new_signature)
{
  uint64_t original_data_length;
  hash_type_t *hash_type = get_hash_type(hash_type_name);

  /* This adds the length of the secret, the data, and the appended length
   * field, then rounds it up to the next multiple of the blocksize. */
  original_data_length = (((secret_length + data_length + hash_type->length_size) / hash_type->block_size) * hash_type->block_size) + hash_type->block_size;
  hash_type->hash(append, append_length, new_signature, original_signature, original_data_length);
}

static int hash_test_validate(char *hash_type_name, uint8_t *secret, uint64_t secret_length, uint8_t *data, uint64_t data_length, uint8_t *signature)
{
  hash_type_t *hash_type = get_hash_type(hash_type_name);
  unsigned char result[hash_type->digest_size];

  /* Generate a signature "properly". */
  hash_gen_signature(hash_type_name, secret, secret_length, data, data_length, result);

  /* Check if that signature matches the one we generated. */
  return !memcmp(signature, result, hash_type->digest_size);
}

static void hash_test_extension(char *hash_type_name)
{
  uint8_t *secret    = (uint8_t*)"SECRET";
  uint8_t *data      = (uint8_t*)"DATA";
  uint8_t *append    = (uint8_t*)"APPEND";
  uint8_t *new_data;
  uint64_t new_length;
  hash_type_t *hash_type = get_hash_type(hash_type_name);

  uint8_t original_signature[hash_type->digest_size];
  uint8_t new_signature[hash_type->digest_size];

  printf("%s: Testing some basic hash data...\n", hash_type_name);

  /* Get the original signature. */
  hash_gen_signature(hash_type_name, secret, strlen((char*)secret), data, strlen((char*)data), original_signature);

  /* Create the new data. */
  new_data = hash_append_data(hash_type_name, data, strlen((char*)data), strlen((char*)secret), append, strlen((char*)append), &new_length);

  /* Generate an evil signature with the data appended. */
  hash_gen_signature_evil(hash_type_name, strlen((char*)secret), strlen((char*)data), original_signature, append, strlen((char*)append), new_signature);

  /* Check the new signature. */
  test_check_boolean(" basic extension", hash_test_validate(hash_type_name, secret, strlen((char*)secret), new_data, new_length, new_signature));

  free(new_data);
}

static void hash_test_lengths(char *hash_type_name)
{
  uint8_t secret[1001] = {'A'};
  uint8_t data[1001]   = {'B'};
  uint8_t append[1001] = {'C'};
  uint8_t *new_data;
  uint64_t new_length;
  hash_type_t *hash_type = get_hash_type(hash_type_name);

  uint8_t original_signature[hash_type->digest_size];
  uint8_t new_signature[hash_type->digest_size];

  uint64_t a_len;
  uint64_t d_len;
  uint64_t s_len;
  uint64_t i;
  uint64_t j;
  char *text;

  printf("%s: Testing hash data of various lengths...\n", hash_type->name);

  for(i = 0; i < 3; i++)
  {
    for(j = 0; j < 993; j++)
    {
      a_len = strlen((char*)append);
      d_len = strlen((char*)data);
      s_len = strlen((char*)secret);

      switch (i)
      {
      case 0:
        text = " different lengths (data)";
        s_len = j;
      case 1:
        text = " different lengths (secret)";
        d_len = j;
      case 2:
        text = " different lengths (secret)";
        a_len = j;
      }
      /* Get the original signature. */
      hash_gen_signature(hash_type_name, secret, s_len, data, d_len, original_signature);

      /* Create the new data. */
      new_data = hash_append_data(hash_type_name, data, d_len, s_len, append, a_len, &new_length);

      /* Generate an evil signature with the data appended. */
      hash_gen_signature_evil(hash_type_name, s_len, d_len, original_signature, append, a_len, new_signature);

      /* Check the new signature. */
      test_check_boolean(text, hash_test_validate(hash_type_name, secret, s_len, new_data, new_length, new_signature));

      /* Free the memory we allocatd. */
      free(new_data);
    }
  }

}

void hash_test(void)
{
  int i;

  for(i = 0; hash_types[i].name; i++)
  {
    hash_test_extension(hash_types[i].name);
    hash_test_lengths(hash_types[i].name);
  }
}

static void md4_hash(uint8_t *data, uint64_t length, uint8_t *buffer, uint8_t *state, uint64_t state_size)
{
  uint64_t i;

  MD4_CTX c;
  MD4_Init(&c);

  if(state)
  {
    for(i = 0; i < state_size; i++)
      MD4_Update(&c, "A", 1);

    c.A = htole32(((int*)state)[0]);
    c.B = htole32(((int*)state)[1]);
    c.C = htole32(((int*)state)[2]);
    c.D = htole32(((int*)state)[3]);
  }

  MD4_Update(&c, data, length);
  MD4_Final(buffer, &c);
}

static void md5_hash(uint8_t *data, uint64_t length, uint8_t *buffer, uint8_t *state, uint64_t state_size)
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

static void ripemd160_hash(uint8_t *data, uint64_t length, uint8_t *buffer, uint8_t *state, uint64_t state_size)
{
  uint64_t i;

  RIPEMD160_CTX c;
  RIPEMD160_Init(&c);

  if(state)
  {
    for(i = 0; i < state_size; i++)
      RIPEMD160_Update(&c, "A", 1);

    c.A = htole32(((int*)state)[0]);
    c.B = htole32(((int*)state)[1]);
    c.C = htole32(((int*)state)[2]);
    c.D = htole32(((int*)state)[3]);
    c.E = htole32(((int*)state)[4]);
  }

  RIPEMD160_Update(&c, data, length);
  RIPEMD160_Final(buffer, &c);
}

static void sha_hash(uint8_t *data, uint64_t length, uint8_t *buffer, uint8_t *state, uint64_t state_size)
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

static void sha1_hash(uint8_t *data, uint64_t length, uint8_t *buffer, uint8_t *state, uint64_t state_size)
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

static void sha256_hash(uint8_t *data, uint64_t length, uint8_t *buffer, uint8_t *state, uint64_t state_size)
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

static void sha512_hash(uint8_t *data, uint64_t length, uint8_t *buffer, uint8_t *state, uint64_t state_size)
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


static void tiger192v1_hash(uint8_t *data, uint64_t length, uint8_t *buffer, uint8_t *state, uint64_t state_size)
{
  uint64_t i;

  TIGER_CTX c;
  TIGER_Init_v1(&c);
  
  if(state)
  {
    
    for(i = 0; i < state_size; i++)
      TIGER_Update(&c, "A", 1);

    c.state[0] = htole64(((uint64_t*)state)[0]);
    c.state[1] = htole64(((uint64_t*)state)[1]);
    c.state[2] = htole64(((uint64_t*)state)[2]);
  }
  TIGER_Update(&c, data, length);
  TIGER_Final(buffer, &c);
}

static void tiger192v2_hash(uint8_t *data, uint64_t length, uint8_t *buffer, uint8_t *state, uint64_t state_size)
{
  uint64_t i;

  TIGER_CTX c;
  TIGER_Init_v2(&c);
  
  if(state)
  {
    
    for(i = 0; i < state_size; i++)
      TIGER_Update(&c, "A", 1);

    c.state[0] = htole64(((uint64_t*)state)[0]);
    c.state[1] = htole64(((uint64_t*)state)[1]);
    c.state[2] = htole64(((uint64_t*)state)[2]);
  }
  TIGER_Update(&c, data, length);
  TIGER_Final(buffer, &c);
}

#ifndef DISABLE_WHIRLPOOL

static void whirlpool_hash(uint8_t *data, uint64_t length, uint8_t *buffer, uint8_t *state, uint64_t state_size)
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
