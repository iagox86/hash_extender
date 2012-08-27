#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <openssl/md5.h>

#include "util.h"

#define MD5_BLOCK 64

int MD5_check_signature(uint8_t *secret, size_t secret_length, uint8_t *data, size_t data_length, uint8_t *signature);
uint8_t *MD5_append_data(uint8_t *data, size_t data_length, size_t secret_length, uint8_t *append, size_t append_length, size_t *new_length);
void MD5_gen_signature(uint8_t *secret, size_t secret_length, uint8_t *data, size_t data_length, uint8_t signature[MD5_DIGEST_LENGTH]);
void MD5_gen_signature_evil(size_t secret_length, size_t data_length, uint8_t original_signature[MD5_DIGEST_LENGTH], uint8_t *append, size_t append_length, uint8_t new_signature[MD5_DIGEST_LENGTH]);

void md5_test_normal_signture_generation();
void md5_test_evil_signature_generation();
void md5_test_basic_extension();
void md5_test_different_length_secret();
void md5_test_different_length_data();
void md5_test_different_length_append();


