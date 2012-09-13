#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "hash_extender_md4.h"
#include "hash_extender_md5.h"
#include "hash_extender_ripemd160.h"
#include "hash_extender_sha.h"
#include "hash_extender_sha1.h"
#include "hash_extender_sha256.h"
#include "hash_extender_sha512.h"
#include "hash_extender_whirlpool.h"

#include "hash_extender_engine.h"

#include "buffer.h"
#include "test.h"
#include "util.h"

hash_type_t hash_types[] = {
  {"md4",       MD4_DIGEST_LENGTH,       TRUE,  64,  8,  md4_hash},
  {"md5",       MD5_DIGEST_LENGTH,       TRUE,  64,  8,  md5_hash},
  {"ripemd160", RIPEMD160_DIGEST_LENGTH, TRUE,  64,  8,  ripemd160_hash},
  {"sha",       SHA_DIGEST_LENGTH,       FALSE, 64,  8,  sha_hash},
  {"sha1",      SHA_DIGEST_LENGTH,       FALSE, 64,  8,  sha1_hash},
  {"sha256",    SHA256_DIGEST_LENGTH,    FALSE, 64,  8,  sha256_hash},
  {"sha512",    SHA512_DIGEST_LENGTH,    FALSE, 128, 16, sha512_hash},
#ifndef DISABLE_WHIRLPOOL
  {"whirlpool", WHIRLPOOL_DIGEST_LENGTH, FALSE, 64,  32, whirlpool_hash},
#endif
  {0, 0, 0, 0, 0}
};

uint64_t hash_type_count = (sizeof(hash_types) / sizeof(hash_type_t));



/* Note: this only supports data with a 4-byte size (4.2 billion bits). */
uint8_t *hash_append_data(hash_type_t hash_type, uint8_t *data, uint64_t data_length, uint64_t secret_length, uint8_t *append, uint64_t append_length, uint64_t *new_length)
{
  /* Allocate memory for the new buffer (enough room for buffer + two full block (finish the current block, entire next block) + the data) */
  /* Note that this can overflow, so this can't be used in security-sensitive applications! */
  uint8_t *result = malloc(data_length + append_length + (2 * hash_type.block_size));
  uint64_t bit_length;

  /* Start with the current buffer and length. */
  memmove(result, data, data_length);
  *new_length = data_length;

  result[(*new_length)++] = 0x80;
  while(((*new_length + secret_length) % hash_type.block_size) != (hash_type.block_size - hash_type.length_size))
    result[(*new_length)++] = 0x00;

  /* Convert the original length to bits so we can append it. */
  bit_length = (secret_length + data_length) * 8;

  /* Get to within exactly 8 bytes of the end (since we only store 64-bits of length).
   * If we ever need sizes bigger than 64 bits, this needs to change. */
  while(((*new_length + secret_length) % hash_type.block_size) != (hash_type.block_size - 8))
    result[(*new_length)++] = 0x00;

  /* Set the last 8 bytes of result to the new length with the appropriate
   * endianness. */
  if(hash_type.little_endian)
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

void hash_gen_signature(hash_type_t hash_type, uint8_t *secret, uint64_t secret_length, uint8_t *data, uint64_t data_length, uint8_t *signature)
{
  uint8_t *buffer;
  uint64_t buffer_size;

  buffer_t *b = buffer_create(BO_HOST);
  buffer_add_bytes(b, secret, secret_length);
  buffer_add_bytes(b, data, data_length);
  buffer = buffer_create_string_and_destroy(b, &buffer_size);

  hash_type.hash(buffer, buffer_size, signature, NULL, 0);
  free(buffer);
}

void hash_gen_signature_evil(hash_type_t hash_type, uint64_t secret_length, uint64_t data_length, uint8_t original_signature[], uint8_t *append, uint64_t append_length, uint8_t *new_signature)
{
  uint64_t original_data_length;

  original_data_length = (((secret_length + data_length + hash_type.length_size) / hash_type.block_size) * hash_type.block_size) + hash_type.block_size;
  hash_type.hash(append, append_length, new_signature, original_signature, original_data_length);
}

static int hash_test_validate(hash_type_t hash_type, uint8_t *secret, uint64_t secret_length, uint8_t *data, uint64_t data_length, uint8_t *signature)
{
  unsigned char result[hash_type.digest_size];

  hash_gen_signature(hash_type, secret, secret_length, data, data_length, result);

  return !memcmp(signature, result, hash_type.digest_size);
}

static void hash_test_extension(hash_type_t hash_type)
{
  uint8_t *secret    = (uint8_t*)"SECRET";
  uint8_t *data      = (uint8_t*)"DATA";
  uint8_t *append    = (uint8_t*)"APPEND";
  uint8_t *new_data;
  uint64_t  new_length;

  uint8_t original_signature[hash_type.digest_size];
  uint8_t new_signature[hash_type.digest_size];

  printf("%s: Testing some basic hash data...\n", hash_type.name);

  /* Get the original signature. */
  hash_gen_signature(hash_type, secret, strlen((char*)secret), data, strlen((char*)data), original_signature);

  /* Create the new data. */
  new_data = hash_append_data(hash_type, data, strlen((char*)data), strlen((char*)secret), append, strlen((char*)append), &new_length);

  /* Generate an evil signature with the data appended. */
  hash_gen_signature_evil(hash_type, strlen((char*)secret), strlen((char*)data), original_signature, append, strlen((char*)append), new_signature);

  /* Check the new signature. */
  test_check_boolean(" basic extension", hash_test_validate(hash_type, secret, strlen((char*)secret), new_data, new_length, new_signature));

  free(new_data);
}

static void hash_test_lengths(hash_type_t hash_type)
{
  uint8_t *secret    = (uint8_t*)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  uint8_t *data      = (uint8_t*)"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
  uint8_t *append    = (uint8_t*)"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
  uint8_t *new_data;
  uint64_t  new_length;

  uint8_t original_signature[hash_type.digest_size];
  uint8_t new_signature[hash_type.digest_size];

  uint64_t i;

  printf("%s: Testing hash data of various lengths...\n", hash_type.name);

  for(i = 0; i < 993; i++)
  {
    /* Get the original signature. */
    hash_gen_signature(hash_type, secret, i, data, strlen((char*)data), original_signature);

    /* Create the new data. */
    new_data = hash_append_data(hash_type, data, strlen((char*)data), i, append, strlen((char*)append), &new_length);

    /* Generate an evil signature with the data appended. */
    hash_gen_signature_evil(hash_type, i, strlen((char*)data), original_signature, append, strlen((char*)append), new_signature);

    /* Check the new signature. */
    test_check_boolean(" different lengths (secret)", hash_test_validate(hash_type, secret, i, new_data, new_length, new_signature));

    /* Free the memory we allocatd. */
    free(new_data);
  }

  for(i = 0; i < 993; i++)
  {
    /* Get the original signature. */
    hash_gen_signature(hash_type, secret, strlen((char*)secret), data, i, original_signature);

    /* Create the new data. */
    new_data = hash_append_data(hash_type, data, i, strlen((char*)secret), append, strlen((char*)append), &new_length);

    /* Generate an evil signature with the data appended. */
    hash_gen_signature_evil(hash_type, strlen((char*)secret), i, original_signature, append, strlen((char*)append), new_signature);

    /* Check the new signature. */
    test_check_boolean(" different lengths (data)", hash_test_validate(hash_type, secret, strlen((char*)secret), new_data, new_length, new_signature));

    /* Free the memory we allocatd. */
    free(new_data);
  }

  for(i = 0; i < 993; i++)
  {
    /* Get the original signature. */
    hash_gen_signature(hash_type, secret, strlen((char*)secret), data, strlen((char*)data), original_signature);

    /* Create the new data. */
    new_data = hash_append_data(hash_type, data, strlen((char*)data), strlen((char*)secret), append, i, &new_length);

    /* Generate an evil signature with the data appended. */
    hash_gen_signature_evil(hash_type, strlen((char*)secret), strlen((char*)data), original_signature, append, i, new_signature);

    /* Check the new signature. */
    test_check_boolean(" different lengths (secret)", hash_test_validate(hash_type, secret, strlen((char*)secret), new_data, new_length, new_signature));

    /* Free the memory we allocatd. */
    free(new_data);
  }
}

void hash_test(hash_type_t hash_type)
{
  hash_test_extension(hash_type);
  hash_test_lengths(hash_type);
}

