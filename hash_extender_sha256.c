#include <endian.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <openssl/sha.h>

#include "test.h"
#include "util.h"

#define SHA256_BLOCK 64
#define SHA256_LENGTH_SIZE 8

/* Note: this only supports data with a 4-byte size (4.2 billion bits). */
uint8_t *sha256_append_data(uint8_t *data, uint64_t data_length, uint64_t secret_length, uint8_t *append, uint64_t append_length, uint64_t *new_length)
{
  /* Allocate memory for the new buffer (enough room for buffer + a full block + the data) */
  uint8_t *result = (uint8_t*) malloc(1000 + data_length + append_length + SHA256_BLOCK); /* (This can overflow if we're ever using this in a security-sensitive context) */
  uint64_t bit_length;

  /* Start with the current buffer and length. */
  memmove(result, data, data_length);
  *new_length = data_length;

  result[(*new_length)++] = 0x80;
  while(((*new_length + secret_length) % SHA256_BLOCK) != (SHA256_BLOCK - SHA256_LENGTH_SIZE))
    result[(*new_length)++] = 0x00;

  /* Convert the original length to bits so we can append it. */
  bit_length = (secret_length + data_length) * 8;

  /* Set the last 4 bytes of result to the new length. */
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

void sha256_gen_signature(uint8_t *secret, uint64_t secret_length, uint8_t *data, uint64_t data_length, uint8_t signature[SHA256_DIGEST_LENGTH])
{
  SHA256_CTX c;
  SHA256_Init(&c);
  SHA256_Update(&c, secret, secret_length);
  SHA256_Update(&c, data, data_length);
  SHA256_Final(signature, &c);
}

void sha256_gen_signature_evil(uint64_t secret_length, uint64_t data_length, uint8_t original_signature[SHA256_DIGEST_LENGTH], uint8_t *append, uint64_t append_length, uint8_t new_signature[SHA256_DIGEST_LENGTH])
{
  SHA256_CTX c;
  uint64_t original_data_length;
  uint64_t i;

  SHA256_Init(&c);

  /* We need to add bytes equal to the original size of the message, plus
   * padding. The reason we add 8 is because the padding is based on the
   * (length % 56) (8 bytes before a full block size). */
  original_data_length = (((secret_length + data_length + SHA256_LENGTH_SIZE) / SHA256_BLOCK) * SHA256_BLOCK) + SHA256_BLOCK;
  for(i = 0; i < original_data_length; i++)
    SHA256_Update(&c, "A", 1);

  /* Restore the original context (letting us start from where the last hash left off). */
  c.h[0] = htobe32(((uint32_t*)original_signature)[0]);
  c.h[1] = htobe32(((uint32_t*)original_signature)[1]);
  c.h[2] = htobe32(((uint32_t*)original_signature)[2]);
  c.h[3] = htobe32(((uint32_t*)original_signature)[3]);
  c.h[4] = htobe32(((uint32_t*)original_signature)[4]);
  c.h[5] = htobe32(((uint32_t*)original_signature)[5]);
  c.h[6] = htobe32(((uint32_t*)original_signature)[6]);
  c.h[7] = htobe32(((uint32_t*)original_signature)[7]);

  /* Add the new data to the hash. */
  SHA256_Update(&c, append, append_length);

  /* Get the new signature. */
  SHA256_Final(new_signature, &c);
}

static int sha256_test_validate(uint8_t *secret, uint64_t secret_length, uint8_t *data, uint64_t data_length, uint8_t *signature)
{
  unsigned char result[SHA256_DIGEST_LENGTH];

  SHA256_CTX c;
  SHA256_Init(&c);
  SHA256_Update(&c, secret, secret_length);
  SHA256_Update(&c, data, data_length);
  SHA256_Final(result, &c);

  return !memcmp(signature, result, SHA256_DIGEST_LENGTH);
}

static void sha256_test_extension()
{
  uint8_t *secret    = (uint8_t*)"SECRET";
  uint8_t *data      = (uint8_t*)"DATA";
  uint8_t *append    = (uint8_t*)"APPEND";
  uint8_t *new_data;
  uint64_t  new_length;

  uint8_t original_signature[SHA256_DIGEST_LENGTH];
  uint8_t new_signature[SHA256_DIGEST_LENGTH];

  printf("Testing some basic SHA256 data...\n");

  /* Get the original signature. */
  sha256_gen_signature(secret, strlen((char*)secret), data, strlen((char*)data), original_signature);

  /* Create the new data. */
  new_data = sha256_append_data(data, strlen((char*)data), strlen((char*)secret), append, strlen((char*)append), &new_length);

  /* Generate an evil signature with the data appended. */
  sha256_gen_signature_evil(strlen((char*)secret), strlen((char*)data), original_signature, append, strlen((char*)append), new_signature);

  /* Check the new signature. */
  test_check_boolean("sha256 basic extension", sha256_test_validate(secret, strlen((char*)secret), new_data, new_length, new_signature));

  free(new_data);
}

static void sha256_test_lengths()
{
  uint8_t *secret    = (uint8_t*)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  uint8_t *data      = (uint8_t*)"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
  uint8_t *append    = (uint8_t*)"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
  uint8_t *new_data;
  uint64_t  new_length;

  uint8_t original_signature[SHA256_DIGEST_LENGTH];
  uint8_t new_signature[SHA256_DIGEST_LENGTH];

  uint64_t i;

  printf("Testing SHA256 data of various lengths...\n");

  for(i = 0; i < 1000; i++)
  {
    /* Get the original signature. */
    sha256_gen_signature(secret, i, data, strlen((char*)data), original_signature);

    /* Create the new data. */
    new_data = sha256_append_data(data, strlen((char*)data), i, append, strlen((char*)append), &new_length);

    /* Generate an evil signature with the data appended. */
    sha256_gen_signature_evil(i, strlen((char*)data), original_signature, append, strlen((char*)append), new_signature);

    /* Check the new signature. */
    test_check_boolean("sha256 different lengths (secret)", sha256_test_validate(secret, i, new_data, new_length, new_signature));

    /* Free the memory we allocatd. */
    free(new_data);
  }

  for(i = 0; i < 1000; i++)
  {
    /* Get the original signature. */
    sha256_gen_signature(secret, strlen((char*)secret), data, i, original_signature);

    /* Create the new data. */
    new_data = sha256_append_data(data, i, strlen((char*)secret), append, strlen((char*)append), &new_length);

    /* Generate an evil signature with the data appended. */
    sha256_gen_signature_evil(strlen((char*)secret), i, original_signature, append, strlen((char*)append), new_signature);

    /* Check the new signature. */
    test_check_boolean("sha256 different lengths (data)", sha256_test_validate(secret, strlen((char*)secret), new_data, new_length, new_signature));

    /* Free the memory we allocatd. */
    free(new_data);
  }

  for(i = 0; i < 1000; i++)
  {
    /* Get the original signature. */
    sha256_gen_signature(secret, strlen((char*)secret), data, strlen((char*)data), original_signature);

    /* Create the new data. */
    new_data = sha256_append_data(data, strlen((char*)data), strlen((char*)secret), append, i, &new_length);

    /* Generate an evil signature with the data appended. */
    sha256_gen_signature_evil(strlen((char*)secret), strlen((char*)data), original_signature, append, i, new_signature);

    /* Check the new signature. */
    test_check_boolean("sha256 different lengths (secret)", sha256_test_validate(secret, strlen((char*)secret), new_data, new_length, new_signature));

    /* Free the memory we allocatd. */
    free(new_data);
  }
}

void sha256_test()
{
  sha256_test_extension();
  sha256_test_lengths();
}

