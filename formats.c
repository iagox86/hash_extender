#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "buffer.h"
#include "test.h"
#include "util.h"

#include "formats.h"

static uint8_t *encode_none(uint8_t *data, uint64_t data_length, uint64_t *out_length);
static void     test_none();

static uint8_t *encode_raw(uint8_t *data, uint64_t data_length, uint64_t *out_length);
static uint8_t *decode_raw(uint8_t *data, uint64_t data_length, uint64_t *out_length);
static void     test_raw();

static uint8_t *encode_html(uint8_t *data, uint64_t data_length, uint64_t *out_length);
static uint8_t *decode_html(uint8_t *data, uint64_t data_length, uint64_t *out_length);
static void     test_html();

static uint8_t *encode_html_pure(uint8_t *data, uint64_t data_length, uint64_t *out_length);
static void     test_html_pure();

static uint8_t *encode_hex(uint8_t *data, uint64_t data_length, uint64_t *out_length);
static uint8_t *decode_hex(uint8_t *data, uint64_t data_length, uint64_t *out_length);
static void     test_hex();

static uint8_t *encode_cstr(uint8_t *data, uint64_t data_length, uint64_t *out_length);
static uint8_t *decode_cstr(uint8_t *data, uint64_t data_length, uint64_t *out_length);
static void     test_cstr();

static uint8_t *encode_cstr_pure(uint8_t *data, uint64_t data_length, uint64_t *out_length);
static void     test_cstr_pure();

/* Define some types so we can stores function pointers. */
typedef uint8_t* (func_encoder)(uint8_t *data, uint64_t data_length, uint64_t *out_length);
typedef uint8_t* (func_decoder)(uint8_t *data, uint64_t data_length, uint64_t *out_length);
typedef void (func_test)();

typedef struct {
  char *name;
  func_encoder *encoder;
  func_decoder *decoder;
  func_test *tester;
} format_t;

static format_t formats[] = {
  {"none",      encode_none,      NULL,        test_none},
  {"raw",       encode_raw,       decode_raw,  test_raw},
  {"hex",       encode_hex,       decode_hex,  test_hex},
  {"html",      encode_html,      decode_html, test_html},
  {"html-pure", encode_html_pure, NULL,        test_html_pure},
  {"cstr",      encode_cstr,      decode_cstr, test_cstr},
  {"cstr-pure", encode_cstr_pure, NULL,        test_cstr_pure},
  {0, 0, 0, 0}
};

const char *encode_formats = "none, raw, hex, html, html-pure, cstr, cstr-pure";
const char *decode_formats = "raw, hex, html, cstr";

static format_t *format_get_by_name(char *name)
{
  int i;
  for(i = 0; formats[i].name; i++)
  {
    if(!strcmp(formats[i].name, name))
      return &formats[i];
  }
  return NULL;
}

BOOL format_exists(char *format_name)
{
  int i;
  for(i = 0; formats[i].name; i++)
    if(!strcmp(formats[i].name, format_name))
      return TRUE;
  return FALSE;
}

uint8_t *format_encode(char *format_name, uint8_t *data, uint64_t data_length, uint64_t *out_length)
{
  format_t *format = format_get_by_name(format_name);
  if(format && format->encoder)
    return format->encoder(data, data_length, out_length);
  else
    return NULL;
}

uint8_t *format_decode(char *format_name, uint8_t *data, uint64_t data_length, uint64_t *out_length)
{
  format_t *format = format_get_by_name(format_name);
  if(format && format->decoder)
    return format->decoder(data, data_length, out_length);
  else
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

static void test_hex_to_int()
{
  int i;
  char buffer[] = "AA\0";

  printf("Testing hex_to_int...\n");
  for(i = 0; i < 256; i++)
  {
    sprintf(buffer, "%02x", i);
    test_check_integer("hex_to_int", hex_to_int((uint8_t*)buffer), i);
  }
}

static uint8_t *encode_none(uint8_t *data, uint64_t data_length, uint64_t *out_length)
{
  *out_length = 0;
  return malloc(0);
}

static void test_none()
{
  int      i;
  char     raw_data[32];
  size_t   raw_length;
  uint8_t *encoded_data;
  uint64_t encoded_length;
  uint8_t  expected_data[32];
  uint64_t expected_length;

  for(i = 0; i < 256; i++)
  {
    raw_length = sprintf(raw_data, "%%%02x \\x%02x %02x", i, i, i);
    encoded_data = encode_none((uint8_t*)raw_data, raw_length, &encoded_length);
    expected_data[0] = '\0';
    expected_length = 0;
    test_check_memory("encode_none", expected_data, expected_length, encoded_data, encoded_length);
    free(encoded_data);
  }
}

static uint8_t *encode_raw(uint8_t *data, uint64_t data_length, uint64_t *out_length)
{
  uint8_t *result = malloc(data_length);
  memcpy(result, data, data_length);
  *out_length = data_length;
  return result;
}

static uint8_t *decode_raw(uint8_t *data, uint64_t data_length, uint64_t *out_length)
{
  uint8_t *result = malloc(data_length);
  memcpy(result, data, data_length);
  *out_length = data_length;
  return result;
}

static void test_raw()
{
  int       i;
  char      raw_data[32];
  size_t    raw_length;
  uint8_t  *encoded_data;
  uint64_t  encoded_length;
  uint8_t  *decoded_data;
  uint64_t  decoded_length;
  uint8_t   expected_data[32];
  uint64_t  expected_length;

  for(i = 0; i < 256; i++)
  {
    raw_length = sprintf(raw_data, "%%%02x \\x%02x %02x", i, i, i);
    encoded_data = encode_raw((uint8_t*)raw_data, raw_length, &encoded_length);
    expected_length = sprintf((char*)expected_data, "%%%02x \\x%02x %02x", i, i, i);
    test_check_memory("encode_raw", expected_data, expected_length, encoded_data, encoded_length);
    free(encoded_data);
  }

  for(i = 0; i < 256; i++)
  {
    raw_length = sprintf(raw_data, "%%%02x \\x%02x %02x", i, i, i);
    decoded_data = decode_raw((uint8_t*)raw_data, raw_length, &decoded_length);
    expected_length = sprintf((char*)expected_data, "%%%02x \\x%02x %02x", i, i, i);
    test_check_memory("decode_raw", expected_data, expected_length, decoded_data, decoded_length);
    free(decoded_data);
  }
}

static uint8_t *encode_html(uint8_t *data, uint64_t data_length, uint64_t *out_length)
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

static uint8_t *decode_html(uint8_t *data, uint64_t data_length, uint64_t *out_length)
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

static void test_html()
{
  int       i;
  char      raw_data[32];
  size_t    raw_length;
  uint8_t  *encoded_data;
  uint64_t  encoded_length;
  uint8_t  *decoded_data;
  uint64_t  decoded_length;
  uint8_t   expected_data[32];
  uint64_t  expected_length;

  for(i = 0; i < 256; i++)
  {
    raw_length = sprintf(raw_data, "%c", i);
    encoded_data = encode_html((uint8_t*)raw_data, raw_length, &encoded_length);

    if(isalnum(i))
    {
      expected_length = sprintf((char*)expected_data, "%c", i);
    }
    else if(i == ' ')
    {
      expected_length = sprintf((char*)expected_data, "+");
    }
    else
    {
      expected_length = sprintf((char*)expected_data, "%%%02x", i);
    }

    test_check_memory("encode_html", expected_data, expected_length, encoded_data, encoded_length);
    free(encoded_data);
  }

  for(i = 0; i < 256; i++)
  {
    raw_length = sprintf(raw_data, "%%%02x \\x%02x %02x", i, i, i);
    decoded_data = decode_html((uint8_t*)raw_data, raw_length, &decoded_length);
    expected_length = sprintf((char*)expected_data, "%c \\x%02x %02x", i, i, i);
    test_check_memory("decode_html", expected_data, expected_length, decoded_data, decoded_length);
    free(decoded_data);
  }
}

static uint8_t *encode_html_pure(uint8_t *data, uint64_t data_length, uint64_t *out_length)
{
  int i;
  buffer_t *b = buffer_create(BO_HOST);
  char tmp[16];

  for(i = 0; i < data_length; i++)
  {
    sprintf(tmp, "%%%02x", data[i]);
    buffer_add_string(b, tmp);
  }

  return buffer_create_string_and_destroy(b, out_length);
}

static void test_html_pure()
{
  int       i;
  char      raw_data[32];
  size_t    raw_length;
  uint8_t  *encoded_data;
  uint64_t  encoded_length;
  uint8_t   expected_data[32];
  uint64_t  expected_length;

  for(i = 0; i < 256; i++)
  {
    raw_length = sprintf(raw_data, "%c", i);
    encoded_data = encode_html_pure((uint8_t*)raw_data, raw_length, &encoded_length);
    expected_length = sprintf((char*)expected_data, "%%%02x", i);
    test_check_memory("encode_html_pure", expected_data, expected_length, encoded_data, encoded_length);
    free(encoded_data);
  }
}

static uint8_t *encode_hex(uint8_t *data, uint64_t data_length, uint64_t *out_length)
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

static uint8_t *decode_hex(uint8_t *data, uint64_t data_length, uint64_t *out_length)
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

static void test_hex()
{
  int       i;
  char      raw_data[32];
  size_t    raw_length;
  uint8_t  *encoded_data;
  uint64_t  encoded_length;
  uint8_t  *decoded_data;
  uint64_t  decoded_length;
  uint8_t   expected_data[32];
  uint64_t  expected_length;

  for(i = 0; i < 256; i++)
  {
    raw_length = sprintf(raw_data, "%c%c%c", i, i, i);
    encoded_data = encode_hex((uint8_t*)raw_data, raw_length, &encoded_length);
    expected_length = sprintf((char*)expected_data, "%02x%02x%02x", i, i, i);
    test_check_memory("encode_hex", expected_data, expected_length, encoded_data, encoded_length);
    free(encoded_data);
  }

  for(i = 0; i < 256; i++)
  {
    raw_length = sprintf(raw_data, "%02x%02x%02x", (uint8_t)(i - 1), (uint8_t)(i), (uint8_t)(i + 1));
    decoded_data = decode_hex((uint8_t*)raw_data, raw_length, &decoded_length);
    expected_length = sprintf((char*)expected_data, "%c%c%c", i - 1, i, i + 1);
    test_check_memory("decode_hex", expected_data, expected_length, decoded_data, decoded_length);
    free(decoded_data);
  }
}

static uint8_t *encode_cstr(uint8_t *data, uint64_t data_length, uint64_t *out_length)
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

static uint8_t *decode_cstr(uint8_t *data, uint64_t data_length, uint64_t *out_length)
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

static void test_cstr()
{
  int       i;
  char      raw_data[32];
  size_t    raw_length;
  uint8_t  *encoded_data;
  uint64_t  encoded_length;
  uint8_t  *decoded_data;
  uint64_t  decoded_length;
  uint8_t   expected_data[32];
  uint64_t  expected_length;

  for(i = 0; i < 256; i++)
  {
    raw_length = sprintf(raw_data, "%c", i);
    encoded_data = encode_cstr((uint8_t*)raw_data, raw_length, &encoded_length);

    if(isalnum(i))
    {
      expected_length = sprintf((char*)expected_data, "%c", i);
    }
    else
    {
      expected_length = sprintf((char*)expected_data, "\\x%02x", i);
    }

    test_check_memory("encode_cstr", expected_data, expected_length, encoded_data, encoded_length);
    free(encoded_data);
  }

  for(i = 0; i < 256; i++)
  {
    raw_length = sprintf(raw_data, "%%%02x \\x%02x %02x", i, i, i);
    decoded_data = decode_cstr((uint8_t*)raw_data, raw_length, &decoded_length);
    expected_length = sprintf((char*)expected_data, "%%%02x %c %02x", i, i, i);
    test_check_memory("decode_cstr", expected_data, expected_length, decoded_data, decoded_length);
    free(decoded_data);
  }
}

static void test_cstr_pure()
{
  int       i;
  char      raw_data[32];
  size_t    raw_length;
  uint8_t  *encoded_data;
  uint64_t  encoded_length;
  uint8_t   expected_data[32];
  uint64_t  expected_length;

  for(i = 0; i < 256; i++)
  {
    raw_length = sprintf(raw_data, "%c", i);
    encoded_data = encode_cstr_pure((uint8_t*)raw_data, raw_length, &encoded_length);
    expected_length = sprintf((char*)expected_data, "\\x%02x", i);
    test_check_memory("encode_cstr", expected_data, expected_length, encoded_data, encoded_length);
    free(encoded_data);
  }
}

static uint8_t *encode_cstr_pure(uint8_t *data, uint64_t data_length, uint64_t *out_length)
{
  int i;
  buffer_t *b = buffer_create(BO_HOST);
  char tmp[16];

  for(i = 0; i < data_length; i++)
  {
    sprintf(tmp, "\\x%02x", data[i]);
    buffer_add_string(b, tmp);
  }

  return buffer_create_string_and_destroy(b, out_length);
}

void format_test()
{
  int i;

  test_hex_to_int();

  for(i = 0; formats[i].name; i++)
  {
    if(formats[i].tester)
    {
      printf("Testing format %s...\n", formats[i].name);
      formats[i].tester();
    }
    else
    {
      fprintf(stderr, "WARNING: No test for format %s\n", formats[i].name);
    }
  }
}

