#include <stdint.h>
#include "util.h"

/* A comma-separated (and user-readable) list of encoders. */
extern const char *encode_formats;

/* A comma-separated (and user-readable) list of decoders. */
extern const char *decode_formats;

BOOL     format_exists(char *format);
uint8_t *format_encode(char *format_name, uint8_t *data, uint64_t data_length, uint64_t *out_length);
uint8_t *format_decode(char *format_name, uint8_t *data, uint64_t data_length, uint64_t *out_length);

void format_test();

