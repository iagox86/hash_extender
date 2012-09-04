#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

void print_hex(unsigned char *data, unsigned int length);
void print_hex_fancy(uint8_t *data, uint64_t length);

#endif
