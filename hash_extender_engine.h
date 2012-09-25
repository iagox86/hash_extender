#ifndef __HASH_EXTENDER_ENGINE_H__
#define __HASH_EXTENDER_ENGINE_H__

/* hash_extender_engine.h
 * By Ron Bowes
 * Created September/2012
 *
 * See LICENSE.txt
 *
 * This module implements a hash length extension attack against a variety of
 * hash types, and can easily be modified to accept more.
 *
 * As a user, there are two functions that really matter: The first is
 * hash_append_data(), which appends the requested data to the string in a such
 * a way that we can sign it properly (that is, with the padding in between the
 * old string and the new string). The second is hash_gen_signature_evil()
 * which creates a new signature for the string with the appended data. For
 * more information on the nitty gritty details of this attack, have a look at
 * README.txt, it explains the attack in full.
 *
 * Hash types are idenfied by name. You can get a list of names either in
 * string format (hash_type_list) or in array format (hash_type_array). You can
 * also use hash_type_exists to check if it exists.
 *
 * One hash type - WHIRLPOOL - doesn't appear to be present in versions of
 * OpenSSL until fairly recently. As such, the Makefile detects whether or not
 * it exists and automatically disables the WHIRLPOOL support if it doesn't.
 *
 * Adding new hash types is fairly easy. Add it to the hash_types table at the
 * top of hash_extender_engine.c, then implement the required hashing function.
 * The hashing function hashes data of a given length, but has two additional
 * arguments - state and state_size - which, if populated, are the starting
 * state and the amount of data that has already been hashed (respectively). Be
 * sure to also add your hash type to hash_type_list and hash_type_array.
 */

#include "util.h"

/* The maximum length that any digest can be. */
#define MAX_DIGEST_LENGTH (512/8)

/* The total number of hash types (calculated automatically). */
extern const uint64_t hash_type_count;

/* A string containing a user-readable list of hash types. */
extern const char *hash_type_list;

/* A list of hash types an an array. */
extern       char *hash_type_array[];

/* Check whether or not the given hash type exists. */
bool hash_type_exists(char *hash_type_name);

/* Basically an accessor method for the hash type's digest size. */
uint64_t hash_type_digest_size(char *hash_type_name);

/* Append data to the hash. */
uint8_t *hash_append_data(char *hash_type_name, uint8_t *data, uint64_t data_length, uint64_t secret_length, uint8_t *append, uint64_t append_length, uint64_t *new_length);

/* Generate a legit signature for the data - prepend the secret to the data and
 * sign it with the appropriate hash. Used primarily for testing. */
void hash_gen_signature(char *hash_type_name, uint8_t *secret, uint64_t secret_length, uint8_t *data, uint64_t data_length, uint8_t *signature);

/* Generate a signature for the data based on the appended data and the state
 * rather than using the secret. */
void hash_gen_signature_evil(char *hash_type_name, uint64_t secret_length, uint64_t data_length, uint8_t *original_signature, uint8_t *append, uint64_t append_length, uint8_t *new_signature);

/* Self-tests. */
void hash_test(void);

#endif
