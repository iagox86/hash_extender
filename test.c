#include <stdio.h>
#include <stdint.h>

#include "util.h"

static int tests_run = 0;
static int tests_passed = 0;

static void test_passed()
{
  tests_run++;
  tests_passed++;
}

static void test_failed()
{
  tests_run++;
}

void test_check_boolean(char *description, uint8_t passed)
{
  if(passed)
  {
    test_passed();
  }
  else
  {
    test_failed();
    printf("FAIL: %s\n", description);
  }
}

void test_check_memory(char *description, uint8_t *expected, size_t expected_length, uint8_t *result, size_t result_length)
{
  if(expected_length == result_length && !memcmp(expected, result, expected_length))
  {
    test_passed();
  }
  else
  {
    test_failed();

    printf("FAIL: %s\n", description);
    printf("  Expected: ");
    print_hex(expected, expected_length);

    printf("  Result:   ");
    print_hex(result, result_length);

    printf("\n");
  }
}

void test_check_integer(char *description, uint32_t expected, uint32_t result)
{
  if(expected == result)
  {
    test_passed();
  }
  else
  {
    test_failed();

    printf("FAIL: %s\n", description);
    printf("  Expected: 0x%08x\n", expected);
    printf("  Result:   0x%08x\n", result);
    printf("\n");
  }
}

void test_report()
{
  if(tests_run == 0)
  {
    printf("No tests run!\n");
  }
  else
  {
    printf("--------------------------------------------------------------------------------\n");
    printf("TESTS PASSED: %d / %d [%2.2f%%]\n", tests_passed, tests_run, 100 * (float)tests_passed / tests_run);
    printf("--------------------------------------------------------------------------------\n");
  }
}

