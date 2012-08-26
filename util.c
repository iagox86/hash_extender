#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

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


