#ifndef __TEST_H__
#define __TEST_H__

#include <stdio.h>
#include <stdint.h>

#include "util.h"

void test_check_memory(char *description, uint8_t *expected, uint64_t expected_length, uint8_t *result, size_t result_length);
void test_check_integer(char *description, uint32_t expected, uint32_t result);
void test_check_boolean(char *description, uint8_t passed);
void test_report();

#endif
