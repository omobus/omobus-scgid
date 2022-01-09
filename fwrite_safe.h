/* -*- H -*- */
/* Copyright (c) 2006 - 2022 omobus-scgid authors, see the included COPYRIGHT file. */

#ifndef __fwrite_safe_h__
#define __fwrite_safe_h__

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

int fwrite_safe(FILE *f, const void *buf, size_t size);

#ifdef __cplusplus
};
#endif

#endif //__fwrite_safe_h__
