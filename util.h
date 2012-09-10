#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

typedef enum {
  /* Don't output anything at all. */
  FORMAT_NONE = 1,

  /* Output as-is. */
  FORMAT_RAW,

  /* Output non-alpha/num as %NN (and spaces as '+'). */
  FORMAT_HTML,

  /* Output everything as %NN. */
  FORMAT_HTML_PURE,

  /* Output everything as plain hex (a1b2c3...). */
  FORMAT_HEX,

  /* Output non-alpha/num as \xNN. */
  FORMAT_CSTR,

  /* Output everything as \xNN. */
  FORMAT_CSTR_PURE,
} format_t;

void print_hex(unsigned char *data, unsigned int length);
void print_hex_fancy(uint8_t *data, uint64_t length);
void die(char *msg);
void die_MEM();
uint8_t *format_to_raw(char *str, format_t format, uint64_t *out_length);
void output_format(format_t format, uint8_t *data, uint64_t data_length);

uint8_t *read_file(char *filename, uint64_t *out_length);

#endif
