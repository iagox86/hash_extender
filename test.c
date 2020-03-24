#include "util.h"

static int tests_run = 0;
static int tests_passed = 0;

static void test_passed(void)
{
  tests_run++;
  tests_passed++;
}

static void test_failed(void)
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

void test_check_memory(char *description, uint8_t *expected, uint64_t expected_length, uint8_t *result, uint64_t result_length)
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
    printf("   --> (\"%s\")\n", expected);

    printf("  Result:   ");
    print_hex(result, result_length);
    printf("   --> (\"%s\")\n", result);

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

void test_report(void)
{
  if(tests_run == 0)
  {
    printf("No tests run!\n");
  }
  else
  {
    printf("--------------------------------------------------------------------------------\n");
    printf("TESTS PASSED: %d / %d [%2.4f%%]\n", tests_passed, tests_run, 100 * (float)tests_passed / tests_run);
    printf("--------------------------------------------------------------------------------\n");
  }

  if (tests_passed != tests_run) {
      exit(1);
  }
}

