#ifndef __TIGER_H_
#define __TIGER_H__

#include "util.h"

typedef struct tiger_state_t TIGER_CTX;

#define TIGER_DIGEST_LENGTH 24
#define TIGER_BLOCK_SIZE 64

struct tiger_state_t {
    uint64_t state[3];
    uint32_t Nl, Nh;
    uint8_t buffer[TIGER_BLOCK_SIZE];
};

int TIGER_Init(TIGER_CTX *c);
int TIGER_Update(TIGER_CTX *c, const void *data, size_t len);
int TIGER_Final(unsigned char *md, TIGER_CTX *c);
/* unsigned char *TIGER(const unsigned char *d, size_t n, unsigned char *md); */
void TIGER_Transform(TIGER_CTX *c, const unsigned char *data);

void test_tiger(const char *d, size_t n);

#endif