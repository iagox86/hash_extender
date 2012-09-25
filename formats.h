#ifndef __FORMATS_H__
#define __FORMATS_H__

/* formats.h
 * By Ron Bowes
 * Created September/2012
 *
 * See LICENSE.txt
 *
 * This module implements encoders/decoders of various formats. It was
 * originally written for the hash_extender tool, but is generic enough to be
 * used elsewhere.
 *
 * As a programmer, you basically call format_encode() to encode a string in a
 * particular format, or format_decode() to convert it back. Both of these
 * functions take a string representing the format name, as well as the
 * incoming data and length. It returns an allocated string containing the
 * encoded or decoded data, and returns the string's length in the final
 * argument. Be sure to free() the variable.
 *
 * A user-readable list of encoders and decoders can be accessed through the
 * variables below, and format_exists() can be used to verify whether or not an
 * encoder is valid.
 *
 * If you want to add your own encoder/decoder, it's pretty easy. Add the
 * functions to formats.c, update the 'formats' array at the top, and add it to
 * the encode_formats/decode_formats string as applicable. That's it!  I highly
 * recommend using the buffer module to build the strings, so you don't have to
 * worry about messing around with building strings by hand.
 *
 * The formats implemented are:
 * - none - output nothing in any case
 * - raw - output the string as-is
 * - hex - the string is encoded in hexadecimal (eg, "AAA" -> "414141"). This
 *   is useful for hashes, for instance, which are generally represented this
 *   way.
 * - html - non-alphanumeric characters are encoded in html style and spaces
 *   are replaced with '+' - eg, '!a %z' -> '%21a+%25z'
 * - html-pure - all characters are encoded in html style - eg. 'ABC' ->
 *   '%41%42%43'
 * - cstr - non-alphanumeric characters are encoded in cstring style - eg, '!a
 *   %z' -> '\x21a\x20\x25z'
 * - cstr-pure - all characters are encoded - cstr style - eg. 'ABC' ->
 *   '\x41\x42\x43'
 */

#include "util.h"

/* A comma-separated (and user-readable) list of encoders. */
extern const char *encode_formats;

/* A comma-separated (and user-readable) list of decoders. */
extern const char *decode_formats;

/* Check if the format exists. */
bool     format_exists(char *format);

/* Encode the data and return it in a newly allocated string. */
uint8_t *format_encode(char *format_name, uint8_t *data, uint64_t data_length, uint64_t *out_length);

/* Decode the data and return it in a newly allocated string. */
uint8_t *format_decode(char *format_name, uint8_t *data, uint64_t data_length, uint64_t *out_length);

/* Perform self-tests. */
void format_test(void);

#endif
