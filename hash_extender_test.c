#include <stdio.h>
#include "hash_extender_md4.h"
#include "hash_extender_md5.h"
#include "hash_extender_ripemd160.h"
#include "hash_extender_sha.h"
#include "hash_extender_sha1.h"
#include "hash_extender_sha256.h"
#include "hash_extender_sha512.h"
#ifndef DISABLE_WHIRLPOOL
#include "hash_extender_whirlpool.h"
#endif
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

