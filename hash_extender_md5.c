#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <openssl/md5.h>

#include "util.h"

#define MD5_BLOCK 64

int md5_check_signature(uint8_t *secret, size_t secret_length, uint8_t *data, size_t data_length, uint8_t *signature)
{
  unsigned char result[MD5_DIGEST_LENGTH];

  MD5_CTX c;
  MD5_Init(&c);
  MD5_Update(&c, secret, secret_length);
  MD5_Update(&c, data, data_length);
  MD5_Final(result, &c);

  print_hex(signature, MD5_DIGEST_LENGTH);
  print_hex(result,    MD5_DIGEST_LENGTH);

  return !memcmp(signature, result, MD5_DIGEST_LENGTH);
}

/* Note: this only supports data with a 4-byte size (4.2 billion bits). */
uint8_t *md5_append_data(uint8_t *data, size_t data_length, size_t secret_length, uint8_t *append, size_t append_length, size_t *new_length)
{
  /* Allocate memory for the new buffer (enough room for buffer + a full block + the data) */
  uint8_t *result = (uint8_t*) malloc(1000 + data_length + append_length + MD5_BLOCK); /* (This can overflow if we're ever using this in a security-sensitive context) */
  size_t bit_length;

  /* Start with the current buffer and length. */
  memmove(result, data, data_length);
  *new_length = data_length;


  result[(*new_length)++] = 0x80;
  while(((*new_length + secret_length) % MD5_BLOCK) != 56)
    result[(*new_length)++] = 0x00;

  /* Convert the original length to bits so we can append it. */
  bit_length = (secret_length + data_length) * 8;

  /* Set the last 4 bytes of result to the new length. */
  result[(*new_length)++] = 0;
  result[(*new_length)++] = 0;
  result[(*new_length)++] = 0;
  result[(*new_length)++] = 0;
  result[(*new_length)++] = (bit_length >> 24) & 0x000000FF;
  result[(*new_length)++] = (bit_length >> 16) & 0x000000FF;
  result[(*new_length)++] = (bit_length >>  8) & 0x000000FF;
  result[(*new_length)++] = (bit_length >>  0) & 0x000000FF;

  /* Add the appended data to the end of the buffer. */
  memcpy(result + (*new_length), append, append_length);
  *new_length += append_length;

  return result;
}

void md5_gen_signature(uint8_t *secret, size_t secret_length, uint8_t *data, size_t data_length, uint8_t signature[MD5_DIGEST_LENGTH])
{
  MD5_CTX c;
  MD5_Init(&c);
  MD5_Update(&c, secret, secret_length);
  MD5_Update(&c, data, data_length);
  MD5_Final(signature, &c);
}

void md5_gen_signature_evil(size_t secret_length, size_t data_length, uint8_t original_signature[MD5_DIGEST_LENGTH], uint8_t *append, size_t append_length, uint8_t new_signature[MD5_DIGEST_LENGTH])
{
  MD5_CTX c;
  size_t original_data_length;
  size_t i;

  MD5_Init(&c);

  /* We need to add bytes equal to the original size of the message, plus
   * padding. The reason we add 8 is because the padding is based on the
   * (length % 56) (8 bytes before a full block size). */
  original_data_length = (((secret_length + data_length + 8) / MD5_BLOCK) * MD5_BLOCK) + MD5_BLOCK;
  for(i = 0; i < original_data_length; i++)
    MD5_Update(&c, "A", 1);

  /* Restore the original context (letting us start from where the last hash left off). */
  /* TODO: is ntonl() the appropriate function here? Will this work on a big-endian system? */
  c.A = htonl(((int*)original_signature)[0]);
  c.B = htonl(((int*)original_signature)[1]);
  c.C = htonl(((int*)original_signature)[2]);
  c.D = htonl(((int*)original_signature)[3]);

  /* Add the new data to the hash. */
  MD5_Update(&c, append, append_length);

  /* Get the new signature. */
  MD5_Final(new_signature, &c);
}

void md5_test_basic_extension()
{
  uint8_t *secret    = (uint8_t*)"SECRET";
  uint8_t *data      = (uint8_t*)"DATA";
  uint8_t *append    = (uint8_t*)"APPEND";
  uint8_t *new_data;
  size_t  new_length;

  uint8_t original_signature[MD5_DIGEST_LENGTH];
  uint8_t new_signature[MD5_DIGEST_LENGTH];

  /* Get the original signature. */
  md5_gen_signature(secret, strlen((char*)secret), data, strlen((char*)data), original_signature);

  /* Create the new data. */
  new_data = md5_append_data(data, strlen((char*)data), strlen((char*)secret), append, strlen((char*)append), &new_length);

  /* Generate an evil signature with the data appended. */
  md5_gen_signature_evil(strlen((char*)secret), strlen((char*)data), original_signature, append, strlen((char*)append), new_signature);

  /* Check the new signature. */
  if(md5_check_signature(secret, strlen((char*)secret), new_data, new_length, new_signature))
  {
    printf("Passed!\n");
  }
  else
  {
    printf("Failed!\n");
  }

  free(new_data);
}

void md5_test_different_length_secret()
{
  uint8_t *secret    = (uint8_t*)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  uint8_t *data      = (uint8_t*)"DATA";
  uint8_t *append    = (uint8_t*)"APPENDZ0R";
  uint8_t *new_data;
  size_t  new_length;

  uint8_t original_signature[MD5_DIGEST_LENGTH];
  uint8_t new_signature[MD5_DIGEST_LENGTH];

  size_t i;

  for(i = 0; i < 75; i++)
  {
    /* Get the original signature. */
    md5_gen_signature(secret, i, data, strlen((char*)data), original_signature);

    /* Create the new data. */
    new_data = md5_append_data(data, strlen((char*)data), i, append, strlen((char*)append), &new_length);

    /* Generate an evil signature with the data appended. */
    md5_gen_signature_evil(i, strlen((char*)data), original_signature, append, strlen((char*)append), new_signature);

    /* Check the new signature. */
    if(!md5_check_signature(secret, i, new_data, new_length, new_signature))
    {
      printf("Length %ld: Failed!\n", i);
      printf("  signature + data = %d\n", (int)(strlen((char*)data) + i));
    }
    free(new_data);
  }
}

void md5_test_different_length_data()
{
  uint8_t *secret    = (uint8_t*)"SECRET";
  uint8_t *data      = (uint8_t*)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  uint8_t *append    = (uint8_t*)"APPENDZ0R";
  uint8_t *new_data;
  size_t  new_length;

  uint8_t original_signature[MD5_DIGEST_LENGTH];
  uint8_t new_signature[MD5_DIGEST_LENGTH];

  size_t i;

  for(i = 0; i < 75; i++)
  {
    /* Get the original signature. */
    md5_gen_signature(secret, strlen((char*)secret), data, i, original_signature);

    /* Create the new data. */
    new_data = md5_append_data(data, i, strlen((char*)secret), append, strlen((char*)append), &new_length);

    /* Generate an evil signature with the data appended. */
    md5_gen_signature_evil(strlen((char*)secret), i, original_signature, append, strlen((char*)append), new_signature);

    /* Check the new signature. */
    if(!md5_check_signature(secret, strlen((char*)secret), new_data, new_length, new_signature))
    {
      printf("Length %ld: Failed!\n", i);
      printf("  signature + data = %d\n", (int)(strlen((char*)secret) + i));
    }
    free(new_data);
  }
}

void md5_test_different_length_append()
{
  uint8_t *secret    = (uint8_t*)"SEKRET";
  uint8_t *data      = (uint8_t*)"DATA";
  uint8_t *append    = (uint8_t*)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  uint8_t *new_data;
  size_t  new_length;

  uint8_t original_signature[MD5_DIGEST_LENGTH];
  uint8_t new_signature[MD5_DIGEST_LENGTH];

  size_t i;

  for(i = 0; i < 75; i++)
  {
    /* Get the original signature. */
    md5_gen_signature(secret, strlen((char*)secret), data, strlen((char*)data), original_signature);

    /* Create the new data. */
    new_data = md5_append_data(data, strlen((char*)data), strlen((char*)secret), append, i, &new_length);

    /* Generate an evil signature with the data appended. */
    md5_gen_signature_evil(strlen((char*)secret), strlen((char*)data), original_signature, append, i, new_signature);

    /* Check the new signature. */
    if(!md5_check_signature(secret, strlen((char*)secret), new_data, new_length, new_signature))
    {
      printf("Length %ld: Failed!\n", i);
      printf("  signature + data = %d\n", (int)(strlen((char*)data) + i));
    }
    free(new_data);
  }
}

