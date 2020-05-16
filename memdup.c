/* -*- C -*- */
/* Copyright (c) 2006 - 2020 omobus-scgid authors, see the included COPYRIGHT file. */

#include <stdlib.h>
#include <memory.h>
#include "memdup.h"

void *memdup(const void *in, size_t size)
{
    void *out = NULL;
    if( in != NULL && size > 0 && (out = malloc(size)) != NULL ) {
	memcpy(out, in, size);
    }
    return out;
}
