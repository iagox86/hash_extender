#ifndef __HASH_EXTENDER_ENGINE_H__
#define __HASH_EXTENDER_ENGINE_H__

#include "util.h"

#define MAX_DIGEST_LENGTH (512/8) /* TODO: Is this used? */
extern uint64_t hash_type_count;
extern char *hash_type_list;
extern char *hash_type_array[];

BOOL hash_type_exists(char *hash_type_name);
uint64_t hash_type_digest_size(char *hash_type_name);

uint8_t *hash_append_data(char *hash_type_name, uint8_t *data, uint64_t data_length, uint64_t secret_length, uint8_t *append, uint64_t append_length, uint64_t *new_length);
void hash_gen_signature(char *hash_type_name, uint8_t *secret, uint64_t secret_length, uint8_t *data, uint64_t data_length, uint8_t *signature);
void hash_gen_signature_evil(char *hash_type_name, uint64_t secret_length, uint64_t data_length, uint8_t *original_signature, uint8_t *append, uint64_t append_length, uint8_t *new_signature);

void hash_test();

#endif
