/* -*- H -*- */
/* Copyright (c) 2006 - 2020 omobus-scgid authors, see the included COPYRIGHT file. */

#ifndef __md5_h__
#define __md5_h__

#include <inttypes.h>

#define MD5_BYTES 16

typedef struct _MD5_CTX {
    uint32_t buf[4];
    uint32_t bits[2];
    unsigned char in[64];
} MD5_CTX;

#ifdef __cplusplus
extern "C" {
#endif

void md5init(MD5_CTX *ctx);
void md5update(MD5_CTX *ctx, const unsigned char *buf, size_t len);
void md5final(unsigned char *digest, MD5_CTX *ctx);

#ifdef __cplusplus
}
#endif

#endif //__md5_h__
