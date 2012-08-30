#include <stdio.h>
#include "hash_extender_sha1.h"
#include "hash_extender_sha256.h"
#include "hash_extender_md5.h"

int main()
{
#if 0
  printf("sha1_test_evil_signature_generation:\n");
  sha1_test_evil_signature_generation();
  printf("\n-----------------------------------------------------\n\n");
  printf("sha1_test_normal_signture_generation:\n");
  sha1_test_normal_signture_generation();
  printf("\n-----------------------------------------------------\n\n");
  printf("sha1_test_basic_extension:\n");
  sha1_test_basic_extension();
  printf("\n-----------------------------------------------------\n\n");
  printf("sha1_test_different_length_secret:\n");
  sha1_test_different_length_secret();
  printf("\n-----------------------------------------------------\n\n");
  printf("sha1_test_different_length_data:\n");
  sha1_test_different_length_data();
  printf("\n-----------------------------------------------------\n\n");
  printf("sha1_test_different_length_append:\n");
  sha1_test_different_length_append();
#endif

  printf("\n-----------------------------------------------------\n\n");
  printf("md5_test_basic_extension:\n");
  md5_test_basic_extension();

#if 0
  printf("\n-----------------------------------------------------\n\n");
  printf("sha256_test_basic_extension:\n");
  sha256_test_basic_extension();
#endif

  return 0;
}

