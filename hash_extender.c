#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <openssl/sha.h>

#define SHA1_BLOCK 64

void print_hex(unsigned char *data, unsigned int length)
{
  unsigned int i;

  for(i = 0; i < length; i++)
    printf("%02x", data[i]);
  printf("\n");
}

static char get_character_from_byte(uint8_t byte)
{
  if(byte < 0x20 || byte > 0x7F)
    return '.';
  return byte;
}

void print_hex_fancy(uint8_t *data, size_t length)
{
  size_t i, j;

  for(i = 0; i < length; i++)
  {
    if(!(i % 16))
    {
      if(i > 0)
      {
        printf("   ");
        for(j = 16; j > 0; j--)
        {
          printf("%c", get_character_from_byte(data[i - j]));
        }
      }
      printf("\n%04X: ", (int)i);
    }

    printf("%02X ", data[i]);
  }

  for(i = length % 16; i < 17; i++)
    printf("   ");
  for(i = length - (length % 16); i < length; i++)
    printf("%c", get_character_from_byte(data[i]));

  printf("\nLength: 0x%X (%d)\n", (int)length, (int)length);
}

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
  uint8_t *result = (uint8_t*) malloc(data_length + append_length + SHA1_BLOCK); /* (This can overflow if we're ever using this in a security-sensitive context) */
  size_t bit_length;

  /* Start with the current buffer and length. */
  memmove(result, data, data_length);
  *new_length = data_length;

  /* SHA1 uses a 1 bit (0x80) followed by enough 0 bits to get 4 bytes from the end of the buffer. */
  result[(*new_length)++] = 0x80;
  while(((*new_length + 4 + secret_length) % SHA1_BLOCK) != 0)
    result[(*new_length)++] = 0x00;

  /* Convert the original length to bits */
  bit_length = (secret_length + data_length) * 8;

  /* Set the last 4 bytes of result to the new length. */
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

  /* Round the total bytes we need to add to the next highest multiple of SHA_DIGEST_LENGTH. */
  original_data_length = (((secret_length + data_length) / SHA1_BLOCK) * SHA1_BLOCK) + SHA1_BLOCK;
  for(i = 0; i < original_data_length; i++)
    SHA1_Update(&c, "A", 1);

  /* Restore the original context (letting us start from where the last hash left off). */
  /* . TODO: is ntonl() the appropriate function here? */
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

void test_normal_signture_generation()
{
  uint8_t *secret    = (uint8_t*)"ivtAUQRQ6dFmH9";
  uint8_t *data      = (uint8_t*)"count=1&lat=37.351&user_id=5&long=-119.827&waffle=chicken";
  uint8_t signature[SHA_DIGEST_LENGTH];

  sha1_gen_signature(secret, strlen((char*)secret), data, strlen((char*)data), signature);

  printf("Generated: ");
  print_hex(signature, SHA_DIGEST_LENGTH);
  printf("Should be: d2dc907fbdbfd02a77d22e502fd15bf6c2004a1f\n");
}

void test_evil_signature_generation()
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

void test_basic_extension()
{
  uint8_t *secret    = (uint8_t*)"ivtAUQRQ6dFmH9";
  uint8_t *data      = (uint8_t*)"count=2&lat=37.351&user_id=1&long=-119.827&waffle=chicken";
  uint8_t *append    = (uint8_t*)"&waffle=liege";
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

void test_different_length_secret()
{
  uint8_t *secret    = (uint8_t*)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  uint8_t *data      = (uint8_t*)"DATA";
  uint8_t *append    = (uint8_t*)"APPENDZ0R";
  uint8_t *new_data;
  size_t  new_length;

  uint8_t original_signature[SHA_DIGEST_LENGTH];
  uint8_t new_signature[SHA_DIGEST_LENGTH];

  size_t i;

  for(i = 0; i < 175; i++)
  {
    /* Get the original signature. */
    sha1_gen_signature(secret, i, data, strlen((char*)data), original_signature);

    /* Create the new data. */
    new_data = sha1_append_data(data, strlen((char*)data), i, append, strlen((char*)append), &new_length);

    /* Generate an evil signature with the data appended. */
    sha1_gen_signature_evil(i, strlen((char*)data), original_signature, append, strlen((char*)append), new_signature);

    /* Check the new signature. */
    if(!sha1_check_signature(secret, i, new_data, new_length, new_signature))
      printf("Length %ld: Failed!\n", i);
  }

  free(new_data);
}


int main()
{
  printf("test_evil_signature_generation:\n");
  test_evil_signature_generation();
  printf("\n-----------------------------------------------------\n\n");
  printf("test_normal_signture_generation:\n");
  test_normal_signture_generation();
  printf("\n-----------------------------------------------------\n\n");
  printf("test_basic_extension:\n");
  test_basic_extension();
  printf("\n-----------------------------------------------------\n\n");
  printf("test_different_length_secret:\n");
  test_different_length_secret();

  return 0;
}

#if 0

/****************************************************\
 * Everything below here is old and commented out!  *
\****************************************************/


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


