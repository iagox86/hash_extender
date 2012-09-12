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
  hash_type_2_t hash_type = hash_types_2[0];
  uint8_t signature[MD5_DIGEST_LENGTH];
  uint8_t new_signature[MD5_DIGEST_LENGTH];

  hash_gen_signature(hash_type, (uint8_t*)"secret", 6, (uint8_t*)"data", 4, signature);

  printf("Type: %s\n", hash_type.name); 
  print_hex(signature, MD5_DIGEST_LENGTH);

  hash_gen_signature_evil(hash_type, 6, 4, signature, (uint8_t *)"append", 6, new_signature);
  print_hex(new_signature, MD5_DIGEST_LENGTH);

  hash_test(hash_type);
  test_report();

#if 0
  md4_test();
  md5_test();
  ripemd160_test();
  sha1_test();
  sha256_test();
  sha512_test();
  sha_test();
#ifndef DISABLE_WHIRLPOOL
  whirlpool_test();
#endif
  util_test();

  test_report();
#endif

  return 0;
}

