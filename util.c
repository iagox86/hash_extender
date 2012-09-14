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

#if 0
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
#endif


void util_test()
{
#if 0
  test_hex_to_int();
  test_format_to_raw();
  test_output_format();
#endif
}

