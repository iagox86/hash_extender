#include <ctype.h>

#include "buffer.h"
#include "test.h"
#include "util.h"

#include "formats.h"

/* I usually hate prototypes, but I want the array of function pointers at the
 * top so I don't really have a choice in this case. */
static uint8_t *encode_none(uint8_t *data, uint64_t data_length, uint64_t *out_length);
static void     test_none(void);

static uint8_t *encode_raw(uint8_t *data, uint64_t data_length, uint64_t *out_length);
static uint8_t *decode_raw(uint8_t *data, uint64_t data_length, uint64_t *out_length);
static void     test_raw(void);

static uint8_t *encode_html(uint8_t *data, uint64_t data_length, uint64_t *out_length);
static uint8_t *decode_html(uint8_t *data, uint64_t data_length, uint64_t *out_length);
static void     test_html(void);

static uint8_t *encode_html_pure(uint8_t *data, uint64_t data_length, uint64_t *out_length);
static void     test_html_pure(void);

static uint8_t *encode_hex(uint8_t *data, uint64_t data_length, uint64_t *out_length);
static uint8_t *decode_hex(uint8_t *data, uint64_t data_length, uint64_t *out_length);
static void     test_hex(void);

static uint8_t *encode_cstr(uint8_t *data, uint64_t data_length, uint64_t *out_length);
static uint8_t *decode_cstr(uint8_t *data, uint64_t data_length, uint64_t *out_length);
static void     test_cstr(void);

static uint8_t *encode_cstr_pure(uint8_t *data, uint64_t data_length, uint64_t *out_length);
static void     test_cstr_pure(void);

static uint8_t *encode_fancy(uint8_t *data, uint64_t data_length, uint64_t *out_length);
static void     test_fancy(void);

/* Define some types so we can stores function pointers. */
typedef uint8_t* (func_encoder)(uint8_t *data, uint64_t data_length, uint64_t *out_length);
typedef uint8_t* (func_decoder)(uint8_t *data, uint64_t data_length, uint64_t *out_length);
typedef void (func_test)(void);

/* This struct defines a format - the name, an encoder, decoder, and a test
 * routine. */
typedef struct {
  char *name;
  func_encoder *encoder;
  func_decoder *decoder;
  func_test *tester;
} format_t;

/* A list of format types. To add a new type, add the function to this list,
 * then to the two strings below. */
static format_t formats[] = {
  {"none",      encode_none,      NULL,        test_none},
  {"raw",       encode_raw,       decode_raw,  test_raw},
  {"hex",       encode_hex,       decode_hex,  test_hex},
  {"html",      encode_html,      decode_html, test_html},
  {"html-pure", encode_html_pure, NULL,        test_html_pure},
  {"cstr",      encode_cstr,      decode_cstr, test_cstr},
  {"cstr-pure", encode_cstr_pure, NULL,        test_cstr_pure},
  {"fancy",     encode_fancy,     NULL,        test_fancy},
  {0, 0, 0, 0}
};

const char *encode_formats = "none, raw, hex, html, html-pure, cstr, cstr-pure, fancy";
const char *decode_formats = "raw, hex, html, cstr";

/* A simple function to get the format by the name, rather than searching
 * manually in code every time. */
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

bool format_exists(char *format_name)
{
  return format_get_by_name(format_name) != NULL;
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

/* Convert a single hex digit (encoded in ascii) at the start of 'hex' to the
 * actual value. */
static uint8_t hex_to_int(uint8_t *hex)
{
  /* These are defined as ints because cygwin. */
  int digit1 = hex[0];
  int digit2 = hex[1];

  return (uint8_t)
           ((isdigit(digit1) ? (digit1 - '0') : (tolower(digit1) - 'a' + 10)) << 4) |
           ((isdigit(digit2) ? (digit2 - '0') : (tolower(digit2) - 'a' + 10)) << 0);
}

static void test_hex_to_int(void)
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

static uint8_t *encode_none(uint8_t *data, uint64_t data_length, uint64_t *out_length) {
  /* Encoding the type 'none' is so easy it's basically cheating. Simply return
   * a 0-length string. */
  *out_length = 0;
  return malloc(0);
}

static void test_none(void)
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
  /* Create a new string and copy the data into it. */
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

static void test_raw(void)
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
    if(isalnum(data[i]))
    {
      /* If the character is alphanumeric, add it as-is. */
      buffer_add_int8(b, data[i]);
    }
    else if(data[i] == ' ')
    {
      /* If the character is a space, add a '+'. */
      buffer_add_int8(b, '+');
    }
    else
    {
      /* Otherwise, encode it as a % followed by a hex code. */
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
    /* If the character is a '%' and we aren't at the end of the string, decode
     * the hex character and add it to the string.
     *
     * The typecasts to 'int' here are to fix warnings from cygwin. */
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

static void test_html(void)
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

  /* Check some sidecases (the '%' is at the end of the string). */
  decoded_data = decode_html((uint8_t*)"%", 1, &decoded_length);
  test_check_memory("decode_html", (uint8_t*)"%", 1, decoded_data, decoded_length);
  free(decoded_data);

  decoded_data = decode_html((uint8_t*)"%2", 2, &decoded_length);
  test_check_memory("decode_html", (uint8_t*)"%2", 2, decoded_data, decoded_length);
  free(decoded_data);

  decoded_data = decode_html((uint8_t*)"%25", 3, &decoded_length);
  test_check_memory("decode_html", (uint8_t*)"%", 1, decoded_data, decoded_length);
  free(decoded_data);

  /* Check other sidecases (the string contains non-hex characters). */
  decoded_data = decode_html((uint8_t*)"%2g", 3, &decoded_length);
  test_check_memory("decode_html", (uint8_t*)"%2g", 3, decoded_data, decoded_length);
  free(decoded_data);

  decoded_data = decode_html((uint8_t*)"%g2", 3, &decoded_length);
  test_check_memory("decode_html", (uint8_t*)"%g2", 3, decoded_data, decoded_length);
  free(decoded_data);
}

static uint8_t *encode_html_pure(uint8_t *data, uint64_t data_length, uint64_t *out_length)
{
  int i;
  buffer_t *b = buffer_create(BO_HOST);
  char tmp[16];

  /* Encode every character as %xx. */
  for(i = 0; i < data_length; i++)
  {
    sprintf(tmp, "%%%02x", data[i]);
    buffer_add_string(b, tmp);
  }

  return buffer_create_string_and_destroy(b, out_length);
}

static void test_html_pure(void)
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

  /* Encode every character as 2 digits of hex. */
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

  /* If we wind up with an odd number of characters, the final character is
   * ignored. */
  while(i + 1 < data_length)
  {
    /* Skip over and ignore non-hex digits. */
    if(!isxdigit(data[i]) || !isxdigit(data[i+1]))
    {
      i++;
      continue;
    }

    /* Add the new character to the string as a uint8_t. */
    buffer_add_int8(b, hex_to_int(&data[i]));

    /* We consumed three digits here. */
    i += 2;
  }

  return buffer_create_string_and_destroy(b, out_length);
}

static void test_hex(void)
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

  /* Side-case: odd numbers of hex digits. */
  decoded_data = decode_hex((uint8_t*)"41424", 5, &decoded_length);
  test_check_memory("decode_hex ('41424')", (uint8_t*)"AB", 2, decoded_data, decoded_length);
  free(decoded_data);

  /* Side-case: non-hex characters in the string. */
  decoded_data = decode_hex((uint8_t*)"414z4", 5, &decoded_length);
  test_check_memory("decode_hex ('414z4')", (uint8_t*)"A", 1, decoded_data, decoded_length);
  free(decoded_data);

  decoded_data = decode_hex((uint8_t*)"4141z4141", 9, &decoded_length);
  test_check_memory("decode_hex ('4141z4141')", (uint8_t*)"AAAA", 4, decoded_data, decoded_length);
  free(decoded_data);
}

static uint8_t *encode_cstr(uint8_t *data, uint64_t data_length, uint64_t *out_length)
{
  int i;
  buffer_t *b = buffer_create(BO_HOST);
  char tmp[16];

  for(i = 0; i < data_length; i++)
  {
    if(isalnum(data[i]))
    {
      /* Add letters/numbers as-is. */
      buffer_add_int8(b, data[i]);
    }
    else
    {
      /* Encode all other characters as "\xNN". */
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
      if(i < in_length && data[i] == '\\')
      {
        buffer_add_int8(b, '\\');
        i++;
      }
      else if(i < in_length && data[i] == 'a')
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
      /* Ensure the data is sane. */
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

static void test_cstr(void)
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

  /* A slash with no character following. */
  decoded_data = decode_cstr((uint8_t*)"\\", 1, &decoded_length);
  test_check_memory("decode_cstr ('\\')", (uint8_t*)"\\", 1, decoded_data, decoded_length);
  free(decoded_data);

  /* \x with no character following. */
  decoded_data = decode_cstr((uint8_t*)"\\x", 2, &decoded_length);
  test_check_memory("decode_cstr ('\\x')", (uint8_t*)"\\x", 2, decoded_data, decoded_length);
  free(decoded_data);

  /* \x with one character following. */
  decoded_data = decode_cstr((uint8_t*)"\\x1", 3, &decoded_length);
  test_check_memory("decode_cstr ('\\x1')", (uint8_t*)"\\x1", 3, decoded_data, decoded_length);
  free(decoded_data);

  /* \b with a 3 after. */
  decoded_data = decode_cstr((uint8_t*)"\\b3", 3, &decoded_length);
  test_check_memory("decode_cstr ('\\b3')", (uint8_t*)"\x08""3", 2, decoded_data, decoded_length);
  free(decoded_data);

  /* \x with an improper hex code. */
  decoded_data = decode_cstr((uint8_t*)"\\x1z", 4, &decoded_length);
  test_check_memory("decode_cstr ('\\x1z')", (uint8_t*)"\\x1z", 4, decoded_data, decoded_length);
  free(decoded_data);

  /* \x with one character following. */
  decoded_data = decode_cstr((uint8_t*)"\\x1", 3, &decoded_length);
  test_check_memory("decode_cstr ('\\x1')", (uint8_t*)"\\x1", 3, decoded_data, decoded_length);
  free(decoded_data);

  /* All the special escape codes. */
  decoded_data = decode_cstr((uint8_t*)"\\\\\\a\\b\\t\\n\\v\\f\\r\\e", 18, &decoded_length);
  test_check_memory("decode_cstr ('\\\\\\a\\b\\t\\n\\v\\f\\r\\e')", (uint8_t*)"\\\x07\x08\x09\x0a\x0b\x0c\x0d\x1b", 9, decoded_data, decoded_length);
  free(decoded_data);
}

static uint8_t *encode_cstr_pure(uint8_t *data, uint64_t data_length, uint64_t *out_length)
{
  int i;
  buffer_t *b = buffer_create(BO_HOST);
  char tmp[16];

  /* Encode every character as \xNN. */
  for(i = 0; i < data_length; i++)
  {
    sprintf(tmp, "\\x%02x", data[i]);
    buffer_add_string(b, tmp);
  }

  return buffer_create_string_and_destroy(b, out_length);
}

static void test_cstr_pure(void)
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

/* A helper functdion for encode_fancy. */
#define get_character_from_byte(b) ((b < 0x20 || b > 0x7f) ? '.' : b)

/* Note: This function isn't tested, so be careful about messing around! */
static uint8_t *encode_fancy(uint8_t *data, uint64_t data_length, uint64_t *out_length)
{
  uint64_t i, j;
  buffer_t *b = buffer_create(BO_HOST);
  char tmp[64];

  for(i = 0; i < data_length; i++)
  {
    if((i % 16) == 0) /* if i is a multiple of 16... */
    {
      if(i > 0)
      {
        sprintf(tmp, "   ");
        buffer_add_string(b, tmp);
        for(j = 16; j > 0; j--)
          buffer_add_int8(b, get_character_from_byte(data[i - j]));
      }
      sprintf(tmp, "\n%04X: ", (uint16_t)i);
      buffer_add_string(b, tmp);
    }

    sprintf(tmp, "%02X ", data[i]);
    buffer_add_string(b, tmp);
  }

  if((i % 16) == 0)
  {
    sprintf(tmp, "   ");
    buffer_add_string(b, tmp);
    for(j = 16; j > 0; j--)
      buffer_add_int8(b, get_character_from_byte(data[i - j]));
  }
  else
  {
    /* Add padding spaces. */
    for(i = data_length % 16; i < 17; i++)
      buffer_add_string(b, "   ");

    for(i = data_length - (data_length % 16); i < data_length; i++)
      buffer_add_int8(b, get_character_from_byte(data[i]));
  }


  sprintf(tmp, "\nLength: 0x%"PRIX64" (%"PRId64")\n", data_length, data_length);
  buffer_add_string(b, tmp);

  /* Null terminate the buffer. */
  buffer_add_int8(b, 0);

  return buffer_create_string_and_destroy(b, out_length);
}

void test_fancy(void)
{
  /* This is to UI-ey to test, not much we can do without just re-implementing
   * the entire thing. */
}

void format_test(void)
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

