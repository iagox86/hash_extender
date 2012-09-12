#ifndef __HASH_EXTENDER_ENGINE_H__
#define __HASH_EXTENDER_ENGINE_H__

#include "util.h"

#define MAX_DIGEST_LENGTH (512/8)

/* The hashing function that each implementation needs to impelement. */
typedef void(hash_t)(uint8_t *data, uint64_t length, uint8_t *buffer, uint8_t *state, uint64_t state_size);

/* Define a list of structs. */
typedef struct
{
  char                 *name;
  uint64_t              digest_size;
  BOOL                  little_endian;
  uint64_t              block_size;
  uint64_t              length_size;

  hash_t               *hash;
} hash_type_t;

extern hash_type_t hash_types[];
extern uint64_t hash_type_count;

uint8_t *hash_append_data(hash_type_t hash_type, uint8_t *data, uint64_t data_length, uint64_t secret_length, uint8_t *append, uint64_t append_length, uint64_t *new_length);
void hash_gen_signature(hash_type_t hash_type, uint8_t *secret, uint64_t secret_length, uint8_t *data, uint64_t data_length, uint8_t *signature);
void hash_gen_signature_evil(hash_type_t hash_type, uint64_t secret_length, uint64_t data_length, uint8_t *original_signature, uint8_t *append, uint64_t append_length, uint8_t *new_signature);

/* Test code */
void hash_test(hash_type_t hash_type);

#endif
