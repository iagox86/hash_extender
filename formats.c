#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "buffer.h"
#include "test.h"
#include "util.h"

#include "formats.h"

uint8_t *encode_none(uint8_t *data, uint64_t data_length, uint64_t *out_length);
uint8_t *decode_raw(uint8_t *data, uint64_t data_length, uint64_t *out_length);
uint8_t *encode_raw(uint8_t *data, uint64_t data_length, uint64_t *out_length);
uint8_t *decode_html(uint8_t *data, uint64_t data_length, uint64_t *out_length);
uint8_t *encode_html(uint8_t *data, uint64_t data_length, uint64_t *out_length);
uint8_t *decode_hex(uint8_t *data, uint64_t data_length, uint64_t *out_length);
uint8_t *encode_hex(uint8_t *data, uint64_t data_length, uint64_t *out_length);
uint8_t *decode_cstr(uint8_t *data, uint64_t data_length, uint64_t *out_length);
uint8_t *encode_cstr(uint8_t *data, uint64_t data_length, uint64_t *out_length);

format_t formats[] = {
  {"none", encode_none, NULL, NULL},
  {"raw",  encode_raw,  decode_raw,  NULL},
  {"hex",  encode_hex,  decode_hex,  NULL},
  {"html", encode_html, decode_html, NULL},
  {"cstr", encode_cstr, decode_cstr, NULL},
  {0, 0, 0, 0}
};

char *encode_formats = "none, raw, hex, html, cstr";
char *decode_formats = "raw, hex, html, cstr";

format_t *format_get_by_name(char *name)
{
  int i;
  for(i = 0; formats[i].name; i++)
  {
    if(!strcmp(formats[i].name, name))
      return &formats[i];
  }
  return NULL;
}

static uint8_t hex_to_int(uint8_t *hex)
{
  /* These are defined as ints because cygwin. */
  int digit1 = hex[0];
  int digit2 = hex[1];
  return (uint8_t)
           ((isdigit(digit1) ? (digit1 - '0') : (tolower(digit1) - 'a' + 10)) << 4) |
           ((isdigit(digit2) ? (digit2 - '0') : (tolower(digit2) - 'a' + 10)) << 0);
}

uint8_t *encode_none(uint8_t *data, uint64_t data_length, uint64_t *out_length)
{
  *out_length = 0;
  return malloc(0);
}

uint8_t *decode_raw(uint8_t *data, uint64_t data_length, uint64_t *out_length)
{
  uint8_t *result = malloc(data_length);
  memcpy(result, data, data_length);
  *out_length = data_length;
  return result;
}

uint8_t *encode_raw(uint8_t *data, uint64_t data_length, uint64_t *out_length)
{
  uint8_t *result = malloc(data_length);
  memcpy(result, data, data_length);
  *out_length = data_length;
  return result;
}


uint8_t *decode_html(uint8_t *data, uint64_t data_length, uint64_t *out_length)
{
  buffer_t *b = buffer_create(BO_HOST);
  uint64_t i = 0;

  while(i < data_length)
  {
    /* The typecasts to 'int' here are to fix warnings from cygwin. */
    if(data[i] == '%' && (i + 2) < data_length && isxdigit((int)data[i + 1]) && isxdigit((int)data[i + 2]))
    {
      /* Add the new character to the string as a uint8_t. */
      buffer_add_int8(b, hex_to_int(&data[i] + 1));

      /* We consumed three digits here. */
      i += 3;
    }
    else if(data[i] == '+')
    {
      /* In html encoding, a '+' is a space. */
      buffer_add_int8(b, ' ');
      i++;
    }
    else
    {
      /* If it's not %NN or +, it's just a raw number.k */
      buffer_add_int8(b, data[i]);
      i++;
    }
  }

  return buffer_create_string_and_destroy(b, out_length);
}

uint8_t *encode_html(uint8_t *data, uint64_t data_length, uint64_t *out_length)
{
  int i;
  buffer_t *b = buffer_create(BO_HOST);
  char tmp[16];

  for(i = 0; i < data_length; i++)
  {
    if(isalpha(data[i]) || isdigit(data[i]))
    {
      buffer_add_int8(b, data[i]);
    }
    else if(data[i] == ' ')
    {
      buffer_add_int8(b, '+');
    }
    else
    {
      sprintf(tmp, "%%%02x", data[i]);
      buffer_add_string(b, tmp);
    }
  }

  return buffer_create_string_and_destroy(b, out_length);
}

uint8_t *decode_hex(uint8_t *data, uint64_t data_length, uint64_t *out_length)
{
  buffer_t *b = buffer_create(BO_HOST);
  uint64_t i = 0;

  while(i + 1 < data_length)
  {
    /* Add the new character to the string as a uint8_t. */
    buffer_add_int8(b, hex_to_int(&data[i]));

    /* We consumed three digits here. */
    i += 2;
  }

  return buffer_create_string_and_destroy(b, out_length);
}

uint8_t *encode_hex(uint8_t *data, uint64_t data_length, uint64_t *out_length)
{
  int i;
  buffer_t *b = buffer_create(BO_HOST);
  char tmp[16];

  for(i = 0; i < data_length; i++)
  {
    sprintf(tmp, "%02x", data[i]);
    buffer_add_string(b, tmp);
  }

  return buffer_create_string_and_destroy(b, out_length);
}

uint8_t *decode_cstr(uint8_t *data, uint64_t data_length, uint64_t *out_length)
{
  buffer_t *b = buffer_create(BO_HOST);
  uint64_t i = 0;
  uint64_t in_length = data_length;

  while(i < in_length)
  {
    if(data[i] == '\\')
    {
      /* Consume the slash. */
      i++;

      /* Check for the various format specifiers - \a, \b, \t, \n, \r, etc) */
      if(i < in_length && data[i] == 'a')
      {
        buffer_add_int8(b, 0x07);
        i++;
      }
      else if(i < in_length && data[i] == 'b')
      {
        buffer_add_int8(b, 0x08);
        i++;
      }
      else if(i < in_length && data[i] == 't')
      {
        buffer_add_int8(b, 0x09);
        i++;
      }
      else if(i < in_length && data[i] == 'n')
      {
        buffer_add_int8(b, 0x0a);
        i++;
      }
      else if(i < in_length && data[i] == 'v')
      {
        buffer_add_int8(b, 0x0b);
        i++;
      }
      else if(i < in_length && data[i] == 'f')
      {
        buffer_add_int8(b, 0x0c);
        i++;
      }
      else if(i < in_length && data[i] == 'r')
      {
        buffer_add_int8(b, 0x0d);
        i++;
      }
      else if(i < in_length && data[i] == 'e')
      {
        buffer_add_int8(b, 0x1b);
        i++;
      }
      else if(i + 2 < in_length && data[i] == 'x' && isxdigit((int)data[i + 1]) && isxdigit((int)data[i + 2]))
      {
        /* Add the new character to the string as a uint8_t. */
        buffer_add_int8(b, hex_to_int(&data[i] + 1));

        /* We consumed three digits here. */
        i += 3;
      }
      else
      {
        buffer_add_int8(b, '\\');
      }
    }
    else
    {
      buffer_add_int8(b, data[i]);
      i++;
    }
  }

  return buffer_create_string_and_destroy(b, out_length);
}

uint8_t *encode_cstr(uint8_t *data, uint64_t data_length, uint64_t *out_length)
{
  int i;
  buffer_t *b = buffer_create(BO_HOST);
  char tmp[16];

  for(i = 0; i < data_length; i++)
  {
    if(isalpha(data[i]) || isdigit(data[i]))
    {
      buffer_add_int8(b, data[i]);
    }
    else
    {
      sprintf(tmp, "\\x%02x", data[i]);
      buffer_add_string(b, tmp);
    }
  }

  return buffer_create_string_and_destroy(b, out_length);
}

