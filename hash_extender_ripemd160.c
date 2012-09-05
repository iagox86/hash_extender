#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <openssl/ripemd.h>

#include "test.h"
#include "util.h"

#define RIPEMD160_BLOCK 64
#define RIPEMD160_LENGTH_SIZE 8

/* Note: this only supports data with a 4-byte size (4.2 billion bits). */
uint8_t *ripemd160_append_data(uint8_t *data, uint64_t data_length, uint64_t secret_length, uint8_t *append, uint64_t append_length, uint64_t *new_length)
{
  /* Allocate memory for the new buffer (enough room for buffer + two full block (finish the current block, entire next block) + the data) */
  /* Note that this can overflow, so this can't be used in security-sensitive applications! */
  uint8_t *result = malloc(data_length + append_length + (2 * RIPEMD160_BLOCK));
  uint64_t bit_length;

  /* Start with the current buffer and length. */
  memmove(result, data, data_length);
  *new_length = data_length;

  result[(*new_length)++] = 0x80;
  while(((*new_length + secret_length) % RIPEMD160_BLOCK) != (RIPEMD160_BLOCK - RIPEMD160_LENGTH_SIZE))
    result[(*new_length)++] = 0x00;

  /* Convert the original length to bits so we can append it. */
  bit_length = (secret_length + data_length) * 8;

  /* Set the last 4 bytes of result to the new length. */
  result[(*new_length)++] = (bit_length >>  0) & 0x000000FF;
  result[(*new_length)++] = (bit_length >>  8) & 0x000000FF;
  result[(*new_length)++] = (bit_length >> 16) & 0x000000FF;
  result[(*new_length)++] = (bit_length >> 24) & 0x000000FF;
  result[(*new_length)++] = (bit_length >> 32) & 0x000000FF;
  result[(*new_length)++] = (bit_length >> 40) & 0x000000FF;
  result[(*new_length)++] = (bit_length >> 48) & 0x000000FF;
  result[(*new_length)++] = (bit_length >> 56) & 0x000000FF;

  /* Add the appended data to the end of the buffer. */
  memcpy(result + (*new_length), append, append_length);
  *new_length += append_length;

  return result;
}

void ripemd160_gen_signature(uint8_t *secret, uint64_t secret_length, uint8_t *data, uint64_t data_length, uint8_t signature[RIPEMD160_DIGEST_LENGTH])
{
  RIPEMD160_CTX c;
  RIPEMD160_Init(&c);
  RIPEMD160_Update(&c, secret, secret_length);
  RIPEMD160_Update(&c, data, data_length);
  RIPEMD160_Final(signature, &c);
}

void ripemd160_gen_signature_evil(uint64_t secret_length, uint64_t data_length, uint8_t original_signature[RIPEMD160_DIGEST_LENGTH], uint8_t *append, uint64_t append_length, uint8_t new_signature[RIPEMD160_DIGEST_LENGTH])
{
  RIPEMD160_CTX c;
  uint64_t original_data_length;
  uint64_t i;

  RIPEMD160_Init(&c);

  /* We need to add bytes equal to the original size of the message, plus
   * padding. The reason we add 8 is because the padding is based on the
   * (length % 56) (8 bytes before a full block size). */
  original_data_length = (((secret_length + data_length + RIPEMD160_LENGTH_SIZE) / RIPEMD160_BLOCK) * RIPEMD160_BLOCK) + RIPEMD160_BLOCK;
  for(i = 0; i < original_data_length; i++)
    RIPEMD160_Update(&c, "A", 1);

  /* Restore the original context (letting us start from where the last hash left off). */
  c.A = htole32(((int*)original_signature)[0]);
  c.B = htole32(((int*)original_signature)[1]);
  c.C = htole32(((int*)original_signature)[2]);
  c.D = htole32(((int*)original_signature)[3]);
  c.E = htole32(((int*)original_signature)[4]);

  /* Add the new data to the hash. */
  RIPEMD160_Update(&c, append, append_length);

  /* Get the new signature. */
  RIPEMD160_Final(new_signature, &c);
}

static int ripemd160_test_validate(uint8_t *secret, uint64_t secret_length, uint8_t *data, uint64_t data_length, uint8_t *signature)
{
  unsigned char result[RIPEMD160_DIGEST_LENGTH];

  RIPEMD160_CTX c;
  RIPEMD160_Init(&c);
  RIPEMD160_Update(&c, secret, secret_length);
  RIPEMD160_Update(&c, data, data_length);
  RIPEMD160_Final(result, &c);

  return !memcmp(signature, result, RIPEMD160_DIGEST_LENGTH);
}

static void ripemd160_test_extension()
{
  uint8_t *secret    = (uint8_t*)"SECRET";
  uint8_t *data      = (uint8_t*)"DATA";
  uint8_t *append    = (uint8_t*)"APPEND";
  uint8_t *new_data;
  uint64_t  new_length;

  uint8_t original_signature[RIPEMD160_DIGEST_LENGTH];
  uint8_t new_signature[RIPEMD160_DIGEST_LENGTH];

  printf("Testing some basic RIPEMD160 data...\n");

  /* Get the original signature. */
  ripemd160_gen_signature(secret, strlen((char*)secret), data, strlen((char*)data), original_signature);

  /* Create the new data. */
  new_data = ripemd160_append_data(data, strlen((char*)data), strlen((char*)secret), append, strlen((char*)append), &new_length);

  /* Generate an evil signature with the data appended. */
  ripemd160_gen_signature_evil(strlen((char*)secret), strlen((char*)data), original_signature, append, strlen((char*)append), new_signature);

  /* Check the new signature. */
  test_check_boolean("ripemd160 basic extension", ripemd160_test_validate(secret, strlen((char*)secret), new_data, new_length, new_signature));

  free(new_data);
}

static void ripemd160_test_lengths()
{
  uint8_t *secret    = (uint8_t*)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  uint8_t *data      = (uint8_t*)"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
  uint8_t *append    = (uint8_t*)"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
  uint8_t *new_data;
  uint64_t  new_length;

  uint8_t original_signature[RIPEMD160_DIGEST_LENGTH];
  uint8_t new_signature[RIPEMD160_DIGEST_LENGTH];

  uint64_t i;

  printf("Testing RIPEMD160 data of various lengths...\n");

  for(i = 0; i < 993; i++)
  {
    /* Get the original signature. */
    ripemd160_gen_signature(secret, i, data, strlen((char*)data), original_signature);

    /* Create the new data. */
    new_data = ripemd160_append_data(data, strlen((char*)data), i, append, strlen((char*)append), &new_length);

    /* Generate an evil signature with the data appended. */
    ripemd160_gen_signature_evil(i, strlen((char*)data), original_signature, append, strlen((char*)append), new_signature);

    /* Check the new signature. */
    test_check_boolean("ripemd160 different lengths (secret)", ripemd160_test_validate(secret, i, new_data, new_length, new_signature));

    /* Free the memory we allocatd. */
    free(new_data);
  }

  for(i = 0; i < 993; i++)
  {
    /* Get the original signature. */
    ripemd160_gen_signature(secret, strlen((char*)secret), data, i, original_signature);

    /* Create the new data. */
    new_data = ripemd160_append_data(data, i, strlen((char*)secret), append, strlen((char*)append), &new_length);

    /* Generate an evil signature with the data appended. */
    ripemd160_gen_signature_evil(strlen((char*)secret), i, original_signature, append, strlen((char*)append), new_signature);

    /* Check the new signature. */
    test_check_boolean("ripemd160 different lengths (data)", ripemd160_test_validate(secret, strlen((char*)secret), new_data, new_length, new_signature));

    /* Free the memory we allocatd. */
    free(new_data);
  }

  for(i = 0; i < 993; i++)
  {
    /* Get the original signature. */
    ripemd160_gen_signature(secret, strlen((char*)secret), data, strlen((char*)data), original_signature);

    /* Create the new data. */
    new_data = ripemd160_append_data(data, strlen((char*)data), strlen((char*)secret), append, i, &new_length);

    /* Generate an evil signature with the data appended. */
    ripemd160_gen_signature_evil(strlen((char*)secret), strlen((char*)data), original_signature, append, i, new_signature);

    /* Check the new signature. */
    test_check_boolean("ripemd160 different lengths (secret)", ripemd160_test_validate(secret, strlen((char*)secret), new_data, new_length, new_signature));

    /* Free the memory we allocatd. */
    free(new_data);
  }
}

void ripemd160_test()
{
  ripemd160_test_extension();
  ripemd160_test_lengths();
}

