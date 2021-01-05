/* -*- H -*- */
/* Copyright (c) 2006 - 2021 omobus-scgid authors, see the included COPYRIGHT file. */

#ifndef __memdup_h__
#define __memdup_h__

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

void *memdup(const void *in, size_t size);

#ifdef __cplusplus
} //extern "C"
#endif

#endif //__memdup_h__
