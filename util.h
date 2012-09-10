#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

typedef enum {
  FORMAT_NONE = 1,
  FORMAT_RAW,
  FORMAT_HTML,
  FORMAT_HTML_PURE,
  FORMAT_HEX,
  FORMAT_CSTR,
  FORMAT_CSTR_PURE,
} format_t;

void print_hex(unsigned char *data, unsigned int length);
void print_hex_fancy(uint8_t *data, uint64_t length);
void DIE(char *msg);
void DIE_MEM();
uint8_t *format_to_raw(char *str, format_t format, uint64_t *out_length);
void output_format(format_t format, uint8_t *data, uint64_t data_length);

uint8_t *read_file(char *filename, uint64_t *out_length);

#endif
