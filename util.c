#include <ctype.h>

#include "buffer.h"
#include "test.h"
#include "util.h"

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

void print_hex_fancy(uint8_t *data, uint64_t length)
{
  uint64_t i, j;

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

void die(char *msg)
{
  fprintf(stderr, "FATAL ERROR: %s\n", msg);
  exit(EXIT_FAILURE);
}

void die_MEM(void)
{
  die("Out of memory");
}

/* Read and return an entire file. */
uint8_t *read_file(char *filename, uint64_t *out_length)
{
  char buffer[1024];
  size_t bytes_read;
  buffer_t *b = buffer_create(BO_HOST);
  FILE *f = fopen(filename, "rb");

  if(!f)
    die("Couldn't open input file");

  while((bytes_read = fread(buffer, 1, 1024, f)) != 0)
  {
    buffer_add_bytes(b, buffer, bytes_read);
  }

  return buffer_create_string_and_destroy(b, out_length);
}
