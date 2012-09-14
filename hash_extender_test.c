#include <stdio.h>
#include "test.h"
#include "hash_extender_engine.h"

int main()
{
  int i;

  for(i = 0; hash_types[i].name; i++)
    hash_test(hash_types[i]);
  util_test();

  test_report();

  return 0;
}

