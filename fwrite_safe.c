/* -*- C -*- */
/* Copyright (c) 2006 - 2020 omobus-scgid authors, see the included COPYRIGHT file. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

#include "fwrite_safe.h"
#include "omobus-scgid.h"

int fwrite_safe(FILE *f, const void *buf, size_t size)
{
    const char *ptr = (const char *) buf;
    size_t s = 0;
    while( size > 0 && (s = fwrite(ptr, 1, size, f)) > 0 ) {
	size -= s; ptr += s;
    }
    return size != 0 ? OMOBUS_ERR : OMOBUS_OK;
}
