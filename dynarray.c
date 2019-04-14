/* -*- C -*- */
/* Copyright (c) 2006 - 2019 omobus-scgid authors, see the included COPYRIGHT file. */

#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include "dynarray.h"

#define bytes_size(elem, max)	((elem)*(max))

typedef struct _dactx {
    size_t elem, grow, size, max, _reallocs;
    void *ptr;
} dactx;

dynarray_t da_create(size_t elem, size_t init, size_t grow)
{
    dactx *ctx;

    if( grow == 0 ) {
	if( (grow = 4096/elem) == 0 ) {
	    grow = 1;
	}
    }

    if( (ctx = (dactx *) malloc(sizeof(dactx))) != NULL ) {
	memset(ctx, 0, sizeof(dactx));
	ctx->elem = elem;
	ctx->grow = grow;
	ctx->ptr = init == 0 ? NULL : malloc(bytes_size(elem, init));
	ctx->max = ctx->ptr == NULL || init == 0 ? 0 : init;
    }

    return ctx;
}

void da_destroy(dynarray_t da)
{
    dactx *ctx;
    if( (ctx = (dactx *) da) != NULL ) {
	da_clear(da);
	free(ctx);
    }
}

void da_clear(dynarray_t da)
{
    dactx *ctx;
    if( (ctx = (dactx *) da) != NULL ) {
	if( ctx->ptr != NULL ) {
	    free(ctx->ptr);
	    ctx->ptr = NULL;
	}
	ctx->size = ctx->max = ctx->_reallocs = 0;
    }
}

void da_shrink(dynarray_t da, size_t size)
{
    dactx *ctx;

    if( (ctx = (dactx *) da) != NULL && ctx->size > size ) {
	ctx->size = size;
	ctx->_reallocs = 0;
    }
}

void da_zero(dynarray_t da)
{
    dactx *ctx;

    if( (ctx = (dactx *) da) != NULL && ctx->max > 0 && ctx->ptr != NULL ) {
	memset(ctx->ptr, 0, bytes_size(ctx->elem, ctx->max));
    }
}

void *da_push(dynarray_t da)
{
    dactx *ctx;
    void *p = NULL;

    if( (ctx = (dactx *) da) == NULL ) {
	errno = EINVAL;
	return NULL;
    }
    if( ctx->max > ctx->size ) {
	p = ((unsigned char *)ctx->ptr) + bytes_size(ctx->elem, ctx->size);
	ctx->size++;
    } else if( (ctx->ptr = realloc(ctx->ptr, bytes_size(ctx->elem, ctx->max + ctx->grow))) != NULL ) {
	ctx->max += ctx->grow;
	p = ((unsigned char *)ctx->ptr) + bytes_size(ctx->elem, ctx->size);
	ctx->size++;
	ctx->_reallocs++;
    }

    return p;
}

void *da_push_z(dynarray_t da)
{
    void *p;
    if( (p = da_push(da)) != NULL ) {
	memset(p, 0, ((dactx *) da)->elem);
    }
    return p;
}

void da_pop_back(dynarray_t da)
{
    dactx *ctx;
    if( (ctx = (dactx *) da) != NULL && ctx->size > 0 ) {
	ctx->size--;
    }
}

short da_empty(dynarray_t da)
{
    dactx *ctx;
    return (ctx = (dactx *) da) == NULL || ctx->size == 0 ? 1 : 0;
}

size_t da_size(dynarray_t da)
{
    dactx *ctx;
    return (ctx = (dactx *) da) == NULL ? 0 : ctx->size;
}

void *da_get(dynarray_t da, size_t index)
{
    dactx *ctx;

    if( (ctx = (dactx *) da) == NULL || index >= ctx->size ) {
	errno = EINVAL;
	return NULL;
    }
    return ((unsigned char *)ctx->ptr) + bytes_size(ctx->elem, index);
}

void *da_front(dynarray_t da)
{
    dactx *ctx;
    return (ctx = (dactx *) da) == NULL || ctx->size == 0 ? NULL : ctx->ptr;
}

void *da_back(dynarray_t da)
{
    dactx *ctx;
    return (ctx = (dactx *) da) == NULL || ctx->size == 0 ? NULL : 
	((unsigned char *)ctx->ptr) + bytes_size(ctx->elem, ctx->size - 1);
}

void da_for_each(dynarray_t da, void *cookie, da_for_cb func)
{
    dactx *ctx;
    size_t i;
    unsigned char *ptr;

    if( (ctx = (dactx *) da) != NULL && ctx->size > 0 ) {
	for( i = 0, ptr = ctx->ptr; i < ctx->size; ++i, ptr+= ctx->elem ) {
	    func(cookie, (void *)ptr);
	}
    }
}

size_t da_count_if(dynarray_t da, void *cookie, da_if_cb func)
{
    dactx *ctx;
    size_t i, c = 0;
    unsigned char *ptr;

    if( (ctx = (dactx *) da) != NULL && ctx->size > 0 ) {
	for( i = 0, ptr = ctx->ptr; i < ctx->size; ++i, ptr+= ctx->elem ) {
	    c += (func(cookie, (void *)ptr)?1:0);
	}
    }
    return c;
}

void *da_find_if(dynarray_t da, void *cookie, da_if_cb func)
{
    dactx *ctx;
    size_t i;
    unsigned char *ptr;

    if( (ctx = (dactx *) da) != NULL && ctx->size > 0 ) {
	for( i = 0, ptr = ctx->ptr; i < ctx->size; ++i, ptr+= ctx->elem ) {
	    if( func(cookie, (void *)ptr) ) {
		return (void *) ptr;
	    }
	}
    }
    return NULL;
}

size_t da_stat(dynarray_t da)
{
    dactx *ctx;
    return (ctx = (dactx *) da) != NULL ? ctx->_reallocs : 0;
}
