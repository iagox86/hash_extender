#ifndef __TIGER_H__
#define __TIGER_H__

#include "util.h"

typedef struct tiger_state_t TIGER_CTX;

#define TIGER_DIGEST_LENGTH 24
#define TIGER_BLOCK_SIZE 64

#define TIGER_V1 0x01
#define TIGER_V2 0x02


struct tiger_state_t {
    uint64_t state[3];
    uint32_t Nl, Nh;
    uint8_t buffer[TIGER_BLOCK_SIZE];
    uint8_t version;
};

int TIGER_Init(TIGER_CTX *c);

int TIGER_Init_v1(TIGER_CTX *c);
int TIGER_Init_v2(TIGER_CTX *c);

int TIGER_Update(TIGER_CTX *c, const void *data, size_t len);
int TIGER_Final(unsigned char *md, TIGER_CTX *c);
void TIGER_Transform(TIGER_CTX *c, const unsigned char *data);

#endif
