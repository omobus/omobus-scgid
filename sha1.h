/* -*- H -*- */
/* Copyright (c) 2006 - 2022 omobus-scgid authors, see the included COPYRIGHT file. */

#ifndef __SHA1_H__
#define __SHA1_H__ 1

#include <inttypes.h>

#define SHA1_BYTES 20

typedef struct _SHA1_CTX {
    uint32_t state[5];
    uint32_t count[2];  
    unsigned char buffer[64];
} SHA1_CTX;

void SHA1Init(SHA1_CTX *context);
void SHA1Update(SHA1_CTX *context, const unsigned char *data, unsigned int len);
void SHA1Final(unsigned char digest[SHA1_BYTES], SHA1_CTX *context);

#endif
