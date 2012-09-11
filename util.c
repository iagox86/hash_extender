#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

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
  exit(1);
}

void die_MEM()
{
  die("Out of memory");
}

static uint8_t hex_to_int(char *hex)
{
  /* These are defined as ints because cygwin. */
  int digit1 = hex[0];
  int digit2 = hex[1];
  return (uint8_t)
           ((isdigit(digit1) ? (digit1 - '0') : (tolower(digit1) - 'a' + 10)) << 4) |
           ((isdigit(digit2) ? (digit2 - '0') : (tolower(digit2) - 'a' + 10)) << 0);
}

/* Convert an html-encoded string (a string containing, for example, %12%34,
 * as well as '+' instead of ' ') to a raw string. Returns the newly allocated
 * string, as well as the length. */
static uint8_t *html_to_raw(char *str, uint64_t *out_length)
{
  buffer_t *b = buffer_create(BO_HOST);
  uint64_t i = 0;

  while(i < strlen(str))
  {
    /* The typecasts to 'int' here are to fix warnings from cygwin. */
    if(str[i] == '%' && (i + 2) < strlen(str) && isxdigit((int)str[i + 1]) && isxdigit((int)str[i + 2]))
    {
      /* Add the new character to the string as a uint8_t. */
      buffer_add_int8(b, hex_to_int(&str[i] + 1));

      /* We consumed three digits here. */
      i += 3;
    }
    else if(str[i] == '+')
    {
      /* In html encoding, a '+' is a space. */
      buffer_add_int8(b, ' ');
      i++;
    }
    else
    {
      /* If it's not %NN or +, it's just a raw number.k */
      buffer_add_int8(b, str[i]);
      i++;
    }
  }

  return buffer_create_string_and_destroy(b, out_length);
}

/* Convert a string in hex format (eg, "ab123d43...") into a raw string.
 * Returns the newly allocated string, as well as the length. */
static uint8_t *hex_to_raw(char *str, uint64_t *out_length)
{
  buffer_t *b = buffer_create(BO_HOST);
  uint64_t i = 0;

  while(i + 1 < strlen(str))
  {
    /* Add the new character to the string as a uint8_t. */
    buffer_add_int8(b, hex_to_int(&str[i]));

    /* We consumed three digits here. */
    i += 2;
  }

  return buffer_create_string_and_destroy(b, out_length);
}

/**Convert a string in a C-like format (that is, containing literal escapes
 * like '\n', '\r', '\x25', etc) into a raw string. Return the newly allocated
 * string as well as the length. */
static uint8_t *cstr_to_raw(char *str, uint64_t *out_length)
{
  buffer_t *b = buffer_create(BO_HOST);
  uint64_t i = 0;
  uint64_t in_length = strlen(str);

  while(i < in_length)
  {
    if(str[i] == '\\')
    {
      /* Consume the slash. */
      i++;

      /* Check for the various format specifiers - \a, \b, \t, \n, \r, etc) */
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
        /* Add the new character to the string as a uint8_t. */
        buffer_add_int8(b, hex_to_int(&str[i] + 1));

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
      buffer_add_int8(b, str[i]);
      i++;
    }
  }

  return buffer_create_string_and_destroy(b, out_length);
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

static uint8_t *output_format_internal(format_t format, uint8_t *data, uint64_t data_length, uint64_t *out_length)
{
  uint64_t i;
  buffer_t *b = buffer_create(BO_HOST);
  char tmp[16]; /* For holding temporary values. */

  if(format == FORMAT_NONE)
  {
    /* Don't output at all. */
    return buffer_create_string_and_destroy(b, out_length);
  }
  else if(format == FORMAT_RAW)
  {
    /* Output the bytes directly. */
    for(i = 0; i < data_length; i++)
      buffer_add_int8(b, data[i]);
  }
  else if(format == FORMAT_HTML || format == FORMAT_HTML_PURE)
  {
    /* FORMAT_HTML outputs standard ascii characters as normal, but encodes
     * non-ascii as %NN. FORMAT_HTML_PURE outputs everything in %NN format. */
    for(i = 0; i < data_length; i++)
    {
      if((isalpha(data[i]) || isdigit(data[i])) && format != FORMAT_HTML_PURE)
      {
        buffer_add_int8(b, data[i]);
      }
      else if(data[i] == ' ' && format != FORMAT_HTML_PURE)
      {
        buffer_add_int8(b, '+');
      }
      else
      {
        sprintf(tmp, "%%%02x", data[i]);
        buffer_add_string(b, tmp);
      }
    }
  }
  else if(format == FORMAT_HEX)
  {
    for(i = 0; i < data_length; i++)
    {
      sprintf(tmp, "%02x", data[i]);
      buffer_add_string(b, tmp);
    }
  }
  else if(format ==  FORMAT_CSTR || format == FORMAT_CSTR_PURE)
  {
    /* FORMAT_CSTR outputs standard ascii characters as normal, but encodes
     * non-ascii as \xNN. FORMAT_CSTR_PURE outputs everything in \xNN format. */
    for(i = 0; i < data_length; i++)
    {
      if((isalpha(data[i]) || isdigit(data[i])) && format != FORMAT_CSTR_PURE)
      {
        buffer_add_int8(b, data[i]);
      }
      else
      {
        sprintf(tmp, "\\x%02x", data[i]);
        buffer_add_string(b, tmp);
      }
    }
  }

  return buffer_create_string_and_destroy(b, out_length);
}

void output_format(format_t format, uint8_t *data, uint64_t data_length)
{
  uint8_t *out_data;
  uint64_t out_length;

  out_data = output_format_internal(format, data, data_length, &out_length);
  fwrite(out_data, 1, out_length, stdout);
  free(out_data);
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

static void test_hex_to_int()
{
  int i;
  char buffer[3] = "\0\0\0";

  printf("Testing hex_to_int...\n");
  for(i = 0; i < 256; i++)
  {
    sprintf(buffer, "%02x", i);
    test_check_integer("hex_to_int", hex_to_int(buffer), i);
  }
}

static void test_format_to_raw()
{
  int i;
  char buffer[32];
  uint8_t *result;
  uint64_t length;

  char expected[32];
  size_t expected_length;

  printf("Testing format_to_raw()...\n");
  for(i = 0; i < 255; i++)
  {
    sprintf(buffer, "%%%02x - %02x - \\x%02x", i, i, i);

    result = format_to_raw(buffer, FORMAT_NONE, &length);
    test_check_memory("format_to_raw(FORMAT_NONE)", (uint8_t*)"", 0, result, length);
    free(result);

    sprintf(buffer, "%%%02x - a - %%%02x", i, i);
    expected_length = sprintf(expected, "%c - a - %c", i, i);
    result = format_to_raw(buffer, FORMAT_HTML, &length);
    test_check_memory("format_to_raw(FORMAT_HTML)", (uint8_t*)expected, expected_length, result, length);
    free(result);

    sprintf(buffer, "%%%02x - a - %%%02x", i, i + 1);
    expected_length = sprintf(expected, "%c - a - %c", i, i + 1);
    result = format_to_raw(buffer, FORMAT_HTML_PURE, &length);
    test_check_memory("format_to_raw(FORMAT_HTML_PURE)", (uint8_t*)expected, expected_length, result, length);
    free(result);

    sprintf(buffer, "%02x%02x%02x", (uint8_t)(i - 1), (uint8_t)i, (uint8_t)(i + 1));
    expected_length = sprintf(expected, "%c%c%c", i - 1, i, i + 1);
    result = format_to_raw(buffer, FORMAT_HEX, &length);
    test_check_memory("format_to_raw(FORMAT_HEX)", (uint8_t*)expected, expected_length, result, length);
    free(result);

    sprintf(buffer, "\\x%02x - a - \\x%02x", (uint8_t)i, (uint8_t)(i + 1));
    expected_length = sprintf(expected, "%c - a - %c", i, i + 1);
    result = format_to_raw(buffer, FORMAT_CSTR, &length);
    test_check_memory("format_to_raw(FORMAT_CSTR)", (uint8_t*)expected, expected_length, result, length);
    free(result);

    sprintf(buffer, "\\x%02x - a - \\x%02x", (uint8_t)i, (uint8_t)(i + 1));
    expected_length = sprintf(expected, "%c - a - %c", i, i + 1);
    result = format_to_raw(buffer, FORMAT_CSTR_PURE, &length);
    test_check_memory("format_to_raw(FORMAT_CSTR_PURE)", (uint8_t*)expected, expected_length, result, length);
    free(result);
  }
}

static void test_output_format()
{
  int i;
  char buffer[32];
  int buffer_length;
  uint8_t *result;
  uint64_t out_length;

  char expected[32];
  size_t expected_length;

  printf("Testing output_format()...\n");
  for(i = 0; i < 256; i++)
  {
    buffer_length = sprintf(buffer, "%c", i);

    if(isalnum(i))
    {
      result = output_format_internal(FORMAT_NONE, (uint8_t*)buffer, buffer_length, &out_length);
      expected[0] = '\0';
      expected_length = 0;
      test_check_memory("output_format_internal(FORMAT_NONE, alpha-numeric)", (uint8_t*)expected, expected_length, result, out_length);
      free(result);

      result = output_format_internal(FORMAT_HTML, (uint8_t*)buffer, buffer_length, &out_length);
      expected_length = sprintf(expected, "%c", i);
      test_check_memory("output_format_internal(FORMAT_HTML, alpha-numeric)", (uint8_t*)expected, expected_length, result, out_length);
      free(result);

      result = output_format_internal(FORMAT_HTML_PURE, (uint8_t*)buffer, buffer_length, &out_length);
      expected_length = sprintf(expected, "%%%02x", i);
      test_check_memory("output_format_internal(FORMAT_HTML_PURE, alpha-numeric)", (uint8_t*)expected, expected_length, result, out_length);
      free(result);

      result = output_format_internal(FORMAT_HEX, (uint8_t*)buffer, buffer_length, &out_length);
      expected_length = sprintf(expected, "%02x", i);
      test_check_memory("output_format_internal(FORMAT_HEX, alpha-numeric)", (uint8_t*)expected, expected_length, result, out_length);
      free(result);

      result = output_format_internal(FORMAT_CSTR, (uint8_t*)buffer, buffer_length, &out_length);
      expected_length = sprintf(expected, "%c", i);
      test_check_memory("output_format_internal(FORMAT_CSTR, alpha-numeric)", (uint8_t*)expected, expected_length, result, out_length);
      free(result);

      result = output_format_internal(FORMAT_CSTR_PURE, (uint8_t*)buffer, buffer_length, &out_length);
      expected_length = sprintf(expected, "\\x%02x", i);
      test_check_memory("output_format_internal(FORMAT_CSTR_PURE, alpha-numeric)", (uint8_t*)expected, expected_length, result, out_length);
      free(result);
    }
    else if(i == 0x20)
    {
      result = output_format_internal(FORMAT_NONE, (uint8_t*)buffer, buffer_length, &out_length);
      expected[0] = '\0';
      expected_length = 0;
      test_check_memory("output_format_internal(FORMAT_NONE, alpha-numeric)", (uint8_t*)expected, expected_length, result, out_length);
      free(result);

      result = output_format_internal(FORMAT_HTML, (uint8_t*)buffer, buffer_length, &out_length);
      expected_length = sprintf(expected, "+");
      test_check_memory("output_format_internal(FORMAT_HTML, alpha-numeric)", (uint8_t*)expected, expected_length, result, out_length);
      free(result);

      result = output_format_internal(FORMAT_HTML_PURE, (uint8_t*)buffer, buffer_length, &out_length);
      expected_length = sprintf(expected, "%%%02x", i);
      test_check_memory("output_format_internal(FORMAT_HTML_PURE, alpha-numeric)", (uint8_t*)expected, expected_length, result, out_length);
      free(result);

      result = output_format_internal(FORMAT_HEX, (uint8_t*)buffer, buffer_length, &out_length);
      expected_length = sprintf(expected, "%02x", i);
      test_check_memory("output_format_internal(FORMAT_HEX, alpha-numeric)", (uint8_t*)expected, expected_length, result, out_length);
      free(result);

      result = output_format_internal(FORMAT_CSTR, (uint8_t*)buffer, buffer_length, &out_length);
      expected_length = sprintf(expected, "\\x%02x", i);
      test_check_memory("output_format_internal(FORMAT_CSTR, alpha-numeric)", (uint8_t*)expected, expected_length, result, out_length);
      free(result);

      result = output_format_internal(FORMAT_CSTR_PURE, (uint8_t*)buffer, buffer_length, &out_length);
      expected_length = sprintf(expected, "\\x%02x", i);
      test_check_memory("output_format_internal(FORMAT_CSTR_PURE, alpha-numeric)", (uint8_t*)expected, expected_length, result, out_length);
      free(result);
    }
    else
    {
      result = output_format_internal(FORMAT_NONE, (uint8_t*)buffer, buffer_length, &out_length);
      expected[0] = '\0';
      expected_length = 0;
      test_check_memory("output_format_internal(FORMAT_NONE, alpha-numeric)", (uint8_t*)expected, expected_length, result, out_length);
      free(result);

      result = output_format_internal(FORMAT_HTML, (uint8_t*)buffer, buffer_length, &out_length);
      expected_length = sprintf(expected, "%%%02x", i);
      test_check_memory("output_format_internal(FORMAT_HTML, alpha-numeric)", (uint8_t*)expected, expected_length, result, out_length);
      free(result);

      result = output_format_internal(FORMAT_HTML_PURE, (uint8_t*)buffer, buffer_length, &out_length);
      expected_length = sprintf(expected, "%%%02x", i);
      test_check_memory("output_format_internal(FORMAT_HTML_PURE, alpha-numeric)", (uint8_t*)expected, expected_length, result, out_length);
      free(result);

      result = output_format_internal(FORMAT_HEX, (uint8_t*)buffer, buffer_length, &out_length);
      expected_length = sprintf(expected, "%02x", i);
      test_check_memory("output_format_internal(FORMAT_HEX, alpha-numeric)", (uint8_t*)expected, expected_length, result, out_length);
      free(result);

      result = output_format_internal(FORMAT_CSTR, (uint8_t*)buffer, buffer_length, &out_length);
      expected_length = sprintf(expected, "\\x%02x", i);
      test_check_memory("output_format_internal(FORMAT_CSTR, alpha-numeric)", (uint8_t*)expected, expected_length, result, out_length);
      free(result);

      result = output_format_internal(FORMAT_CSTR_PURE, (uint8_t*)buffer, buffer_length, &out_length);
      expected_length = sprintf(expected, "\\x%02x", i);
      test_check_memory("output_format_internal(FORMAT_CSTR_PURE, alpha-numeric)", (uint8_t*)expected, expected_length, result, out_length);
      free(result);
    }
  }
}

void util_test()
{
  test_hex_to_int();
  test_format_to_raw();
  test_output_format();
}

