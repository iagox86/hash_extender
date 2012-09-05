#include <stdio.h>
#include "hash_extender_md4.h"
#include "hash_extender_md5.h"
#include "hash_extender_ripemd160.h"
#include "hash_extender_sha.h"
#include "hash_extender_sha1.h"
#include "hash_extender_sha256.h"
#include "hash_extender_sha512.h"
#include "hash_extender_whirlpool.h"
#include "test.h"

int main()
{

  md4_test();
  md5_test();
  ripemd160_test();
  sha1_test();
  sha256_test();
  sha512_test();
  sha_test();
  whirlpool_test();

  test_report();

  return 0;
}

