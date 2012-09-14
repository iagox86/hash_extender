#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "buffer.h"
#include "test.h"
#include "util.h"

typedef uint8_t* (func_decoder)(uint8_t *data, uint64_t data_length, uint64_t *out_length);
typedef uint8_t* (func_encoder)(uint8_t *data, uint64_t data_length, uint64_t *out_length);
typedef void (func_test)();

typedef struct {
  char *name;
  func_encoder *encoder;
  func_decoder *decoder;
  func_test *tester;
} format_t;

extern format_t formats[];
extern char *encode_formats;
extern char *decode_formats;

format_t *format_get_by_name(char *name);

