#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <openssl/sha.h>

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

#if 0
/* Create a buffer and URLEncode stuff (yes, this is shitty code :) ) */
void print_url(unsigned char *url, int url_length, unsigned char *signature)
{
  char *buffer = malloc((url_length * 4) + 1);
  int offset = 0;
  int i;
  memcpy(buffer, url, url_length);

  /* Do a shitty urlencode */
  for(i = 0; i < url_length; i++)
  {
    if(url[i] < 0x20 || url[i] > 0x7F)
    {
      sprintf(buffer + offset, "\\x%02x", url[i]);
      offset += 4;
    }
    else
    {
      sprintf(buffer + offset, "%c", url[i]);
      offset += 1;
    }
  }

  printf("echo -ne \"%s|sig:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\" > payload.bin\n", buffer,
      signature[0],  signature[1],  signature[2],  signature[3],
      signature[4],  signature[5],  signature[6],  signature[7],
      signature[8],  signature[9],  signature[10], signature[11],
      signature[12], signature[13], signature[14], signature[15],
      signature[16], signature[17], signature[18], signature[19]
      );

  printf("wget -qO- --post-file=payload.bin https://level07-2.stripe-ctf.com/user-khqqbglfcj/orders\n");
}

void print_hex(unsigned char *data, unsigned int length)
{
  unsigned int i;

  for(i = 0; i < length; i++)
    printf("%02x", data[i]);
  printf("\n");
}

void add_padding(unsigned char *data, int *new_length)
{
  int original_length = (int)strlen((char*)data);
  *new_length = original_length;

  data[(*new_length)++] = 0x80;

  /* Loop until we only require four bytes */
  while(((*new_length) + 4) % 64 != 0)
    data[(*new_length)++] = 0x00;

  /* Bytes -> bits */
  original_length = original_length * 8;

  data[(*new_length)++] = (original_length >> 24) & 0x000000FF;
  data[(*new_length)++] = (original_length >> 16) & 0x000000FF;
  data[(*new_length)++] = (original_length >>  8) & 0x000000FF;
  data[(*new_length)++] = (original_length >>  0) & 0x000000FF;
}

void get_signature(char *secret, char *params, unsigned char *signature)
{
  SHA_CTX c;

  /* Hash the secret and the params */
  SHA1_Init(&c);
  SHA1_Update(&c, secret, strlen(secret));
  SHA1_Update(&c, params, strlen(params));
  SHA1_Final(signature, &c);
}

void test_legit(char *secret, char *params, unsigned char signature[20])
{
  /* Get the valid signature */
  get_signature(secret, params, signature);

  printf("Signature: ");
  print_hex(signature, 20);

  printf("Valid URL based on signature:\n");
  print_url((unsigned char*)params, strlen((char*)params), signature);
}

void test_hack(char *params, char *extra, char *original_hash)
{
  SHA_CTX c;
  char to_sign[2000];
  char url[2000];
  int length;
  char signature[20];

  /* Generate the data to hash */
  strcpy(to_sign, "XXXXXXXXXXXXXX");
  strcat(to_sign, params);
  add_padding(to_sign, &length);

  /* Generate the url for the user */
  memset(url, 0, sizeof(url));
  memcpy(url, to_sign + 14, length - 14);
  memcpy(url + length - 14, extra, strlen(extra));

  /* Start the hash */
  SHA1_Init(&c);
  SHA1_Update(&c, to_sign, length);

  /* Replace the internal state */
  c.h0 = htonl(((int*)original_hash)[0]);
  c.h1 = htonl(((int*)original_hash)[1]);
  c.h2 = htonl(((int*)original_hash)[2]);
  c.h3 = htonl(((int*)original_hash)[3]);
  c.h4 = htonl(((int*)original_hash)[4]);

  /* Add the extra stuff to the params */
  SHA1_Update(&c, extra, strlen(extra));
  SHA1_Final(signature, &c);

  print_url(url, length - 14 + strlen(extra), signature);
}
#endif

int main()
{

  return 0;
}
