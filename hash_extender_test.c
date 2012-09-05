#include <stdio.h>
#include "hash_extender_sha1.h"
#include "hash_extender_sha256.h"
#include "hash_extender_sha512.h"
#include "hash_extender_md5.h"
#include "hash_extender_md4.h"
#include "test.h"

int main()
{
  sha1_test();
  md5_test();
  sha256_test();
  sha512_test();
  md4_test();

  test_report();

  return 0;
}

