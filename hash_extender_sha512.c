#ifdef FREEBSD
#include <sys/endian.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <openssl/sha.h>

#include "test.h"
#include "util.h"

#define SHA512_BLOCK 128
#define SHA512_LENGTH_SIZE 16

uint8_t *sha512_append_data(uint8_t *data, uint64_t data_length, uint64_t secret_length, uint8_t *append, uint64_t append_length, uint64_t *new_length)
{
  /* Allocate memory for the new buffer (enough room for buffer + two full block (finish the current block, entire next block) + the data) */
  /* Note that this can overflow, so this can't be used in security-sensitive applications! */
  uint8_t *result = malloc(data_length + append_length + (2 * SHA512_BLOCK));
  uint64_t bit_length;

  /* Start with the current buffer and length. */
  memmove(result, data, data_length);
  *new_length = data_length;

  result[(*new_length)++] = 0x80;
  while(((*new_length + secret_length) % SHA512_BLOCK) != (SHA512_BLOCK - SHA512_LENGTH_SIZE))
    result[(*new_length)++] = 0x00;

  /* Convert the original length to bits so we can append it. */
  bit_length = (secret_length + data_length) * 8;

  /* Set the last 16 bytes of result to the new length. */
  result[(*new_length)++] = 0;
  result[(*new_length)++] = 0;
  result[(*new_length)++] = 0;
  result[(*new_length)++] = 0;
  result[(*new_length)++] = 0;
  result[(*new_length)++] = 0;
  result[(*new_length)++] = 0;
  result[(*new_length)++] = 0;
  result[(*new_length)++] = (bit_length >> 56) & 0x000000FF;
  result[(*new_length)++] = (bit_length >> 48) & 0x000000FF;
  result[(*new_length)++] = (bit_length >> 40) & 0x000000FF;
  result[(*new_length)++] = (bit_length >> 32) & 0x000000FF;
  result[(*new_length)++] = (bit_length >> 24) & 0x000000FF;
  result[(*new_length)++] = (bit_length >> 16) & 0x000000FF;
  result[(*new_length)++] = (bit_length >>  8) & 0x000000FF;
  result[(*new_length)++] = (bit_length >>  0) & 0x000000FF;

  /* Add the appended data to the end of the buffer. */
  memcpy(result + (*new_length), append, append_length);
  *new_length += append_length;

  return result;
}

void sha512_gen_signature(uint8_t *secret, uint64_t secret_length, uint8_t *data, uint64_t data_length, uint8_t signature[SHA512_DIGEST_LENGTH])
{
  SHA512_CTX c;
  SHA512_Init(&c);
  SHA512_Update(&c, secret, secret_length);
  SHA512_Update(&c, data, data_length);
  SHA512_Final(signature, &c);
}

void sha512_gen_signature_evil(uint64_t secret_length, uint64_t data_length, uint8_t original_signature[SHA512_DIGEST_LENGTH], uint8_t *append, uint64_t append_length, uint8_t new_signature[SHA512_DIGEST_LENGTH])
{
  SHA512_CTX c;
  uint64_t original_data_length;
  uint64_t i;

  SHA512_Init(&c);

  /* We need to add bytes equal to the original size of the message, plus
   * padding. The reason we add 16 is because the padding is based on the
   * (length % 112) (16 bytes before a full block size). */
  original_data_length = (((secret_length + data_length + SHA512_LENGTH_SIZE) / SHA512_BLOCK) * SHA512_BLOCK) + SHA512_BLOCK;
  for(i = 0; i < original_data_length; i++)
    SHA512_Update(&c, "A", 1);

  /* Restore the original context (letting us start from where the last hash left off). */
  c.h[0] = htobe64(((uint64_t*)original_signature)[0]);
  c.h[1] = htobe64(((uint64_t*)original_signature)[1]);
  c.h[2] = htobe64(((uint64_t*)original_signature)[2]);
  c.h[3] = htobe64(((uint64_t*)original_signature)[3]);
  c.h[4] = htobe64(((uint64_t*)original_signature)[4]);
  c.h[5] = htobe64(((uint64_t*)original_signature)[5]);
  c.h[6] = htobe64(((uint64_t*)original_signature)[6]);
  c.h[7] = htobe64(((uint64_t*)original_signature)[7]);

  /* Add the new data to the hash. */
  SHA512_Update(&c, append, append_length);

  /* Get the new signature. */
  SHA512_Final(new_signature, &c);
}

static int sha512_test_validate(uint8_t *secret, uint64_t secret_length, uint8_t *data, uint64_t data_length, uint8_t *signature)
{
  unsigned char result[SHA512_DIGEST_LENGTH];

  SHA512_CTX c;
  SHA512_Init(&c);
  SHA512_Update(&c, secret, secret_length);
  SHA512_Update(&c, data, data_length);
  SHA512_Final(result, &c);

  return !memcmp(signature, result, SHA512_DIGEST_LENGTH);
}

static void sha512_test_extension()
{
  uint8_t *secret    = (uint8_t*)"SECRET";
  uint8_t *data      = (uint8_t*)"DATA";
  uint8_t *append    = (uint8_t*)"APPEND";
  uint8_t *new_data;
  uint64_t new_length;

  uint8_t original_signature[SHA512_DIGEST_LENGTH];
  uint8_t new_signature[SHA512_DIGEST_LENGTH];

  printf("Testing some basic SHA512 data...\n");

  /* Get the original signature. */
  sha512_gen_signature(secret, strlen((char*)secret), data, strlen((char*)data), original_signature);

  /* Create the new data. */
  new_data = sha512_append_data(data, strlen((char*)data), strlen((char*)secret), append, strlen((char*)append), &new_length);

  /* Generate an evil signature with the data appended. */
  sha512_gen_signature_evil(strlen((char*)secret), strlen((char*)data), original_signature, append, strlen((char*)append), new_signature);

  /* Check the new signature. */
  test_check_boolean("sha512 basic extension", sha512_test_validate(secret, strlen((char*)secret), new_data, new_length, new_signature));

  free(new_data);
}

static void sha512_test_lengths()
{
  uint8_t *secret    = (uint8_t*)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  uint8_t *data      = (uint8_t*)"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
  uint8_t *append    = (uint8_t*)"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
  uint8_t *new_data;
  uint64_t  new_length;

  uint8_t original_signature[SHA512_DIGEST_LENGTH];
  uint8_t new_signature[SHA512_DIGEST_LENGTH];

  uint64_t i;

  printf("Testing SHA512 data of various lengths...\n");

  for(i = 0; i < 993; i++)
  {
    /* Get the original signature. */
    sha512_gen_signature(secret, i, data, strlen((char*)data), original_signature);

    /* Create the new data. */
    new_data = sha512_append_data(data, strlen((char*)data), i, append, strlen((char*)append), &new_length);

    /* Generate an evil signature with the data appended. */
    sha512_gen_signature_evil(i, strlen((char*)data), original_signature, append, strlen((char*)append), new_signature);

    /* Check the new signature. */
    test_check_boolean("sha512 different lengths (secret)", sha512_test_validate(secret, i, new_data, new_length, new_signature));

    /* Free the memory we allocatd. */
    free(new_data);
  }

  for(i = 0; i < 993; i++)
  {
    /* Get the original signature. */
    sha512_gen_signature(secret, strlen((char*)secret), data, i, original_signature);

    /* Create the new data. */
    new_data = sha512_append_data(data, i, strlen((char*)secret), append, strlen((char*)append), &new_length);

    /* Generate an evil signature with the data appended. */
    sha512_gen_signature_evil(strlen((char*)secret), i, original_signature, append, strlen((char*)append), new_signature);

    /* Check the new signature. */
    test_check_boolean("sha512 different lengths (data)", sha512_test_validate(secret, strlen((char*)secret), new_data, new_length, new_signature));

    /* Free the memory we allocatd. */
    free(new_data);
  }

  for(i = 0; i < 993; i++)
  {
    /* Get the original signature. */
    sha512_gen_signature(secret, strlen((char*)secret), data, strlen((char*)data), original_signature);

    /* Create the new data. */
    new_data = sha512_append_data(data, strlen((char*)data), strlen((char*)secret), append, i, &new_length);

    /* Generate an evil signature with the data appended. */
    sha512_gen_signature_evil(strlen((char*)secret), strlen((char*)data), original_signature, append, i, new_signature);

    /* Check the new signature. */
    test_check_boolean("sha512 different lengths (secret)", sha512_test_validate(secret, strlen((char*)secret), new_data, new_length, new_signature));

    /* Free the memory we allocatd. */
    free(new_data);
  }
}

void sha512_test()
{
  sha512_test_extension();
  sha512_test_lengths();
}

