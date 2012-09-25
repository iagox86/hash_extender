#ifndef _UTIL_H_
#define _UTIL_H_

#include <err.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void print_hex(unsigned char *data, unsigned int length);
void print_hex_fancy(uint8_t *data, uint64_t length);
void die(char *msg);
void die_MEM(void);

uint8_t *read_file(char *filename, uint64_t *out_length);

void util_test(void);

#endif
