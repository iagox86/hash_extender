#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <openssl/sha.h>

#include "util.h"

#define SHA1_BLOCK 64

int sha1_check_signature(uint8_t *secret, size_t secret_length, uint8_t *data, size_t data_length, uint8_t *signature)
{
  unsigned char result[SHA_DIGEST_LENGTH];

  SHA_CTX c;
  SHA1_Init(&c);
  SHA1_Update(&c, secret, secret_length);
  SHA1_Update(&c, data, data_length);
  SHA1_Final(result, &c);

  return !memcmp(signature, result, SHA_DIGEST_LENGTH);
}

/* Note: this only supports data with a 4-byte size (4.2 billion bits). */
uint8_t *sha1_append_data(uint8_t *data, size_t data_length, size_t secret_length, uint8_t *append, size_t append_length, size_t *new_length)
{
  /* Allocate memory for the new buffer (enough room for buffer + a full block + the data) */
  uint8_t *result = (uint8_t*) malloc(1000 + data_length + append_length + SHA1_BLOCK); /* (This can overflow if we're ever using this in a security-sensitive context) */
  size_t bit_length;

  /* Start with the current buffer and length. */
  memmove(result, data, data_length);
  *new_length = data_length;


  result[(*new_length)++] = 0x80;
  while(((*new_length + secret_length) % SHA1_BLOCK) != 56)
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

void sha1_gen_signature(uint8_t *secret, size_t secret_length, uint8_t *data, size_t data_length, uint8_t signature[SHA_DIGEST_LENGTH])
{
  SHA_CTX c;
  SHA1_Init(&c);
  SHA1_Update(&c, secret, secret_length);
  SHA1_Update(&c, data, data_length);
  SHA1_Final(signature, &c);
}

void sha1_gen_signature_evil(size_t secret_length, size_t data_length, uint8_t original_signature[SHA_DIGEST_LENGTH], uint8_t *append, size_t append_length, uint8_t new_signature[SHA_DIGEST_LENGTH])
{
  SHA_CTX c;
  size_t original_data_length;
  size_t i;

  SHA1_Init(&c);

  /* We need to add bytes equal to the original size of the message, plus
   * padding. The reason we add 8 is because the padding is based on the
   * (length % 56) (8 bytes before a full block size). */
  original_data_length = (((secret_length + data_length + 8) / SHA1_BLOCK) * SHA1_BLOCK) + SHA1_BLOCK;
  for(i = 0; i < original_data_length; i++)
    SHA1_Update(&c, "A", 1);

  /* Restore the original context (letting us start from where the last hash left off). */
  /* TODO: is ntonl() the appropriate function here? Will this work on a big-endian system? */
  c.h0 = htonl(((int*)original_signature)[0]);
  c.h1 = htonl(((int*)original_signature)[1]);
  c.h2 = htonl(((int*)original_signature)[2]);
  c.h3 = htonl(((int*)original_signature)[3]);
  c.h4 = htonl(((int*)original_signature)[4]);

  /* Add the new data to the hash. */
  SHA1_Update(&c, append, append_length);

  /* Get the new signature. */
  SHA1_Final(new_signature, &c);
}

void sha1_test_normal_signture_generation()
{
  uint8_t *secret    = (uint8_t*)"ivtAUQRQ6dFmH9";
  uint8_t *data      = (uint8_t*)"count=1&lat=37.351&user_id=5&long=-119.827&waffle=chicken";
  uint8_t signature[SHA_DIGEST_LENGTH];

  sha1_gen_signature(secret, strlen((char*)secret), data, strlen((char*)data), signature);

  printf("Generated: ");
  print_hex(signature, SHA_DIGEST_LENGTH);
  printf("Should be: d2dc907fbdbfd02a77d22e502fd15bf6c2004a1f\n");
}

void sha1_test_evil_signature_generation()
{
  uint8_t *secret    = (uint8_t*)"XXXXXXXXXXXXXX"; /* We don't know the actual secret here. */
  uint8_t *data      = (uint8_t*)"count=2&lat=37.351&user_id=1&long=-119.827&waffle=chicken";
  uint8_t *signature = (uint8_t*)"\xe8\xc5\x7b\xb7\xcb\xb6\xfa\x98\xd1\x16\xed\x06\x62\x2d\x60\x00\xee\x43\x1d\x49";

  uint8_t *append    = (uint8_t*)"&waffle=liege";
  uint8_t *new_data;
  size_t  new_length;
  uint8_t new_signature[SHA_DIGEST_LENGTH];

  new_data = sha1_append_data(data, strlen((char*)data), strlen((char*)secret), append, strlen((char*)append), &new_length);

  sha1_gen_signature_evil(strlen((char*)secret), strlen((char*)data), signature, append, strlen((char*)append), new_signature);

  printf("Generated: ");
  print_hex(new_signature, SHA_DIGEST_LENGTH);
  printf("Should be: adb43a448aad421b4b1b11b1973af6ab95b69221\n");

  free(new_data);
}

void sha1_test_basic_extension()
{
  uint8_t *secret    = (uint8_t*)"SECRET";
  uint8_t *data      = (uint8_t*)"DATA";
  uint8_t *append    = (uint8_t*)"APPEND";
  uint8_t *new_data;
  size_t  new_length;

  uint8_t original_signature[SHA_DIGEST_LENGTH];
  uint8_t new_signature[SHA_DIGEST_LENGTH];

  /* Get the original signature. */
  sha1_gen_signature(secret, strlen((char*)secret), data, strlen((char*)data), original_signature);

  /* Create the new data. */
  new_data = sha1_append_data(data, strlen((char*)data), strlen((char*)secret), append, strlen((char*)append), &new_length);

  /* Generate an evil signature with the data appended. */
  sha1_gen_signature_evil(strlen((char*)secret), strlen((char*)data), original_signature, append, strlen((char*)append), new_signature);

  /* Check the new signature. */
  if(sha1_check_signature(secret, strlen((char*)secret), new_data, new_length, new_signature))
  {
    printf("Passed!\n");
  }

  free(new_data);
}

void sha1_test_different_length_secret()
{
  uint8_t *secret    = (uint8_t*)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  uint8_t *data      = (uint8_t*)"DATA";
  uint8_t *append    = (uint8_t*)"APPENDZ0R";
  uint8_t *new_data;
  size_t  new_length;

  uint8_t original_signature[SHA_DIGEST_LENGTH];
  uint8_t new_signature[SHA_DIGEST_LENGTH];

  size_t i;

  for(i = 0; i < 275; i++)
  {
    /* Get the original signature. */
    sha1_gen_signature(secret, i, data, strlen((char*)data), original_signature);

    /* Create the new data. */
    new_data = sha1_append_data(data, strlen((char*)data), i, append, strlen((char*)append), &new_length);

    /* Generate an evil signature with the data appended. */
    sha1_gen_signature_evil(i, strlen((char*)data), original_signature, append, strlen((char*)append), new_signature);

    /* Check the new signature. */
    if(!sha1_check_signature(secret, i, new_data, new_length, new_signature))
    {
      printf("Length %ld: Failed!\n", i);
      printf("  signature + data = %d\n", (int)(strlen((char*)data) + i));
    }
    free(new_data);
  }
}

void sha1_test_different_length_data()
{
  uint8_t *secret    = (uint8_t*)"SECRET";
  uint8_t *data      = (uint8_t*)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  uint8_t *append    = (uint8_t*)"APPENDZ0R";
  uint8_t *new_data;
  size_t  new_length;

  uint8_t original_signature[SHA_DIGEST_LENGTH];
  uint8_t new_signature[SHA_DIGEST_LENGTH];

  size_t i;

  for(i = 0; i < 75; i++)
  {
    /* Get the original signature. */
    sha1_gen_signature(secret, strlen((char*)secret), data, i, original_signature);

    /* Create the new data. */
    new_data = sha1_append_data(data, i, strlen((char*)secret), append, strlen((char*)append), &new_length);

    /* Generate an evil signature with the data appended. */
    sha1_gen_signature_evil(strlen((char*)secret), i, original_signature, append, strlen((char*)append), new_signature);

    /* Check the new signature. */
    if(!sha1_check_signature(secret, strlen((char*)secret), new_data, new_length, new_signature))
    {
      printf("Length %ld: Failed!\n", i);
      printf("  signature + data = %d\n", (int)(strlen((char*)secret) + i));
    }
    free(new_data);
  }
}

void sha1_test_different_length_append()
{
  uint8_t *secret    = (uint8_t*)"SEKRET";
  uint8_t *data      = (uint8_t*)"DATA";
  uint8_t *append    = (uint8_t*)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  uint8_t *new_data;
  size_t  new_length;

  uint8_t original_signature[SHA_DIGEST_LENGTH];
  uint8_t new_signature[SHA_DIGEST_LENGTH];

  size_t i;

  for(i = 0; i < 75; i++)
  {
    /* Get the original signature. */
    sha1_gen_signature(secret, strlen((char*)secret), data, strlen((char*)data), original_signature);

    /* Create the new data. */
    new_data = sha1_append_data(data, strlen((char*)data), strlen((char*)secret), append, i, &new_length);

    /* Generate an evil signature with the data appended. */
    sha1_gen_signature_evil(strlen((char*)secret), strlen((char*)data), original_signature, append, i, new_signature);

    /* Check the new signature. */
    if(!sha1_check_signature(secret, strlen((char*)secret), new_data, new_length, new_signature))
    {
      printf("Length %ld: Failed!\n", i);
      printf("  signature + data = %d\n", (int)(strlen((char*)data) + i));
    }
    free(new_data);
  }
}

