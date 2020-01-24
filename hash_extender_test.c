#include "formats.h"
#include "hash_extender_engine.h"
#include "test.h"
#include "tiger.h"

int main(void)
{
  hash_test();
  format_test();
  test_report();

  return EXIT_SUCCESS;
}
