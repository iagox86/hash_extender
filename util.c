#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "buffer.h"
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

void DIE(char *msg)
{
  fprintf(stderr, "FATAL ERROR: %s\n", msg);
  exit(1);
}

void DIE_MEM()
{
  DIE("Out of memory");
}

/* Convert an html-encoded string (a string containing, for example, %12%34,
 * as well as '+' instead of ' ') to a raw string. Returns the newly allocated
 * string, as well as the length. */
static uint8_t *html_to_raw(char *str, uint64_t *out_length)
{
  buffer_t *b = buffer_create(BO_HOST);
  uint64_t i = 0;
  uint8_t c;

  while(i < strlen(str))
  {
    /* The typecasts to 'int' here are to fix warnings from cygwin. */
    if(str[i] == '%' && (i + 2) < strlen(str) && isxdigit((int)str[i + 1]) && isxdigit((int)str[i + 2]))
    {
      c =  (isdigit((int)str[i + 1]) ? (str[i + 1] - '0') : (tolower((int)str[i + 1]) - 'a' + 10)) << 4;
      c |= (isdigit((int)str[i + 2]) ? (str[i + 2] - '0') : (tolower((int)str[i + 2]) - 'a' + 10)) << 0;
      buffer_add_int8(b, c);
      i += 3;
    }
    else if(str[i] == '+')
    {
      buffer_add_int8(b, ' ');
      i++;
    }
    else
    {
      buffer_add_int8(b, str[i]);
      i++;
    }
  }

  return buffer_get(b, out_length);
}

/* Convert a string in hex format (eg, "ab123d43...") into a raw string.
 * Returns the newly allocated string, as well as the length. */
static uint8_t *hex_to_raw(char *str, uint64_t *out_length)
{
  buffer_t *b = buffer_create(BO_HOST);
  uint64_t i = 0;
  uint8_t c;

  while(i + 1 < strlen(str))
  {
    c =  (isdigit((int)str[i + 0]) ? (str[i + 0] - '0') : (tolower((int)str[i + 0]) - 'a' + 10)) << 4;
    c |= (isdigit((int)str[i + 1]) ? (str[i + 1] - '0') : (tolower((int)str[i + 1]) - 'a' + 10)) << 0;
    buffer_add_int8(b, c);
    i += 2;
  }

  return buffer_get(b, out_length);
}

/**Convert a string in a C-like format (that is, containing literal escapes
 * like '\n', '\r', '\x25', etc) into a raw string. Return the newly allocated
 * string as well as the length. */
static uint8_t *cstr_to_raw(char *str, uint64_t *out_length)
{
  buffer_t *b = buffer_create(BO_HOST);
  uint64_t i = 0;
  uint8_t c;
  uint64_t in_length = strlen(str);

  while(i < in_length)
  {
    /* The typecasts to 'int' here are to fix warnings from cygwin. */
    if(str[i] == '\\')
    {
      i++;
      if(i < in_length && str[i] == 'a')
      {
        buffer_add_int8(b, 0x07);
        i++;
      }
      else if(i < in_length && str[i] == 'b')
      {
        buffer_add_int8(b, 0x08);
        i++;
      }
      else if(i < in_length && str[i] == 't')
      {
        buffer_add_int8(b, 0x09);
        i++;
      }
      else if(i < in_length && str[i] == 'n')
      {
        buffer_add_int8(b, 0x0a);
        i++;
      }
      else if(i < in_length && str[i] == 'v')
      {
        buffer_add_int8(b, 0x0b);
        i++;
      }
      else if(i < in_length && str[i] == 'f')
      {
        buffer_add_int8(b, 0x0c);
        i++;
      }
      else if(i < in_length && str[i] == 'r')
      {
        buffer_add_int8(b, 0x0d);
        i++;
      }
      else if(i < in_length && str[i] == 'e')
      {
        buffer_add_int8(b, 0x1b);
        i++;
      }
      else if(i + 2 < in_length && str[i] == 'x' && isxdigit((int)str[i + 1]) && isxdigit((int)str[i + 2]))
      {
        c =  (isdigit((int)str[i + 1]) ? (str[i + 1] - '0') : (tolower((int)str[i + 1]) - 'a' + 10)) << 4;
        c |= (isdigit((int)str[i + 2]) ? (str[i + 2] - '0') : (tolower((int)str[i + 2]) - 'a' + 10)) << 0;
        buffer_add_int8(b, c);
        i += 3;
      }
      else
      {
        buffer_add_int8(b, '\\');
      }
    }
    else if(str[i] == '+')
    {
      buffer_add_int8(b, ' ');
      i++;
    }
    else
    {
      buffer_add_int8(b, str[i]);
      i++;
    }
  }

  return buffer_get(b, out_length);
}

uint8_t *format_to_raw(char *str, format_t format, uint64_t *out_length)
{
  uint8_t *out;

  switch(format)
  {
    case FORMAT_NONE:
      *out_length = 0;
      return malloc(0);

    case FORMAT_RAW:
      out = malloc(strlen(str) + 1);
      memcpy(out, str, strlen(str) + 1);
      *out_length = strlen(str);
      return out;

    case FORMAT_HTML:
    case FORMAT_HTML_PURE:
      return html_to_raw(str, out_length);

    case FORMAT_HEX:
      return hex_to_raw(str, out_length);

    case FORMAT_CSTR:
    case  FORMAT_CSTR_PURE:
      return cstr_to_raw(str, out_length);

    default:
      fprintf(stderr, "Unknown format: %d\n", format);
      exit(1);
  }

  return NULL;
}

void output_format(format_t format, uint8_t *data, uint64_t data_length)
{
  uint64_t i;

  if(format == FORMAT_NONE)
  {
    /* Don't output at all. */
  }
  else if(format == FORMAT_RAW)
  {
    /* Output the bytes directly. */
    for(i = 0; i < data_length; i++)
      printf("%c", data[i]);
  }
  else if(format == FORMAT_HTML || format == FORMAT_HTML_PURE)
  {
    for(i = 0; i < data_length; i++)
    {
      if((isalpha(data[i]) || isdigit(data[i])) && format != FORMAT_HTML_PURE)
      {
        printf("%c", data[i]);
      }
      else if(data[i] == ' ')
      {
        printf(" ");
      }
      else
      {
        printf("%%%02x", data[i]);
      }
    }
  }
  else if(format == FORMAT_HEX)
  {
    for(i = 0; i < data_length; i++)
      printf("%02x", data[i]);
  }
  else if(format ==  FORMAT_CSTR || format == FORMAT_CSTR_PURE)
  {
    for(i = 0; i < data_length; i++)
    {
      if((isalpha(data[i]) || isdigit(data[i])) && format != FORMAT_CSTR_PURE)
      {
        printf("%c", data[i]);
      }
      else
      {
        printf("\\x%02x", data[i]);
      }
    }
  }
}

uint8_t *read_file(char *filename, uint64_t *out_length)
{
  char buffer[1024];
  size_t bytes_read;
  buffer_t *b = buffer_create(BO_HOST);
  FILE *f = fopen(filename, "rb");

  if(!f)
    DIE("Couldn't open input file");

  while((bytes_read = fread(buffer, 1, 1024, f)) != 0)
  {
    buffer_add_bytes(b, buffer, bytes_read);
  }

  return buffer_get(b, out_length);
}
