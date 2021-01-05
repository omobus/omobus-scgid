/* -*- C -*- */
/* Copyright (c) 2006 - 2021 omobus-scgid authors, see the included COPYRIGHT file. */

#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <string.h>

#include "crc64.h"
#include "xxhash.h"
#include "hashtable.h"

typedef struct _elemctx {
    const char *key;
    const void *value;
} elemctx;

typedef struct _htctx {
    size_t size, ht_size, max_size, collisions, items;
    elemctx *tb;
} htctx;

static size_t granularity = 32, multiplier = 5;

static
size_t position(htctx *ctx, const char *key)
{
//    return crc64(0, key, strlen(key))%ctx->ht_size;
    return XXH64(key, strlen(key), 0)%ctx->ht_size;
}

hashtable_t ht_create(size_t size)
{
    htctx *ctx;
    size_t max_size;

    max_size = ((size_t)(size/granularity+1))*multiplier*granularity;

    if( size == 0 ) {
	errno = EINVAL;
	return NULL;
    }
    if( (ctx = (htctx *) malloc(sizeof(htctx))) == NULL ) {
	return NULL;
    }
    if( (ctx->tb = (elemctx *) malloc(sizeof(elemctx)*max_size)) == NULL ) {
	free(ctx);
	return NULL;
    }
    memset(ctx->tb, 0, sizeof(elemctx)*max_size);
    ctx->size = size;
    ctx->ht_size = max_size - size;
    ctx->max_size = max_size;
    ctx->items = 0;
    return (hashtable_t) ctx;
}

void ht_destroy(hashtable_t ht)
{
    htctx *ctx;
    if( (ctx = (htctx *) ht) != NULL ) {
	free(ctx->tb);
	free(ctx);
    }
}

int ht_set(hashtable_t ht, const char *key, const void *value)
{
    htctx *ctx;
    size_t idx;
    elemctx *ptr;

    if( (ctx = (htctx *) ht) == NULL ) {
	errno = EINVAL;
	return -1;
    }
    if( (idx = position(ctx, key)) >= ctx->ht_size ) {
	errno = EFAULT;
	return -1;
    }
    if( (ptr = ctx->tb+idx)->key == NULL ) {
	ptr->key = key;
	ptr->value = value;
	ctx->items++;
    } else if( strcmp(ptr->key, key) == 0 ) {
	ptr->value = value;
    } else {
	while( (++idx) < ctx->max_size && (ptr = ctx->tb+idx)->key != NULL )
	    ;
	if( idx >= ctx->max_size ) {
	    errno = EFAULT;
	} else {
	    ptr->key = key;
	    ptr->value = value;
	    ctx->collisions++;
	    ctx->items++;
	}
    }
    return idx >= ctx->max_size ? -1 : 0;
}

const void *ht_find(hashtable_t ht, const char *key)
{
    htctx *ctx;
    size_t idx;
    elemctx *ptr;

    if( (ctx = (htctx *) ht) == NULL ) {
	errno = EINVAL;
	return NULL;
    }
    if( (idx = position(ctx, key)) >= ctx->ht_size ) {
	errno = EFAULT;
	return NULL;
    }
    for( ptr = NULL; idx < ctx->max_size && (ptr = ctx->tb+idx) != NULL && ptr->key != NULL && strcmp(ptr->key, key) != 0; idx++ )
	;
    return idx >= ctx->max_size || ptr == NULL || ptr->key == NULL ? NULL : ptr->value;
}

short ht_exist(hashtable_t ht, const char *key)
{
    htctx *ctx;
    size_t idx;
    elemctx *ptr;

    if( (ctx = (htctx *) ht) == NULL ) {
	errno = EINVAL;
	return 0;
    }
    if( (idx = position(ctx, key)) >= ctx->ht_size ) {
	errno = EFAULT;
	return 0;
    }
    for( ptr = NULL; idx < ctx->max_size && (ptr = ctx->tb+idx) != NULL && ptr->key != NULL && strcmp(ptr->key, key) != 0; idx++ )
	;
    return idx >= ctx->max_size || ptr == NULL || ptr->key == NULL ? 0 : 1;
}

size_t ht_collisions(hashtable_t ht)
{
    htctx *ctx;
    return (ctx = (htctx *) ht) == NULL ? 0 : ctx->collisions;
}

size_t ht_size(hashtable_t ht)
{
    htctx *ctx;
    return (ctx = (htctx *) ht) == NULL ? 0 : ctx->items;
}

void ht_for_each(hashtable_t ht, void *cookie, ht_for_each_cb func)
{
    htctx *ctx;
    elemctx *ptr;

    if( (ctx = (htctx *) ht) == NULL ) {
	errno = EINVAL;
    } else if( func != NULL ) {
	for( size_t i = 0; i < ctx->max_size; i++ ) {
	    if( (ptr = ctx->tb+i) != NULL && ptr->key != NULL ) {
		func(cookie, ptr->key, ptr->value);
	    }
	}
    }
}

/*
#include <stdio.h>
int main()
{
    char *ids[] = {
"50545:11437",
"50539-11427",
"50543-11434",
"50530-11415",
"50530-11414",
"50234-10777",
"50551-11445",
"33365-10482",
"35541-11131",
"35541-11132",
"35541-11032sd sdsd",
"35541-11036",
"35541-11037",
"35541-11038",
"35541-11034",
"35541-11039",
"35541-11040",
"35541-11041",
"35541-11033",
"35541-11042",
"35541-11043",
"35541-044",
"35541-11045",
"35541-11035",
"35541-11011",
"35541-11012" };
    hashtable_t ht;
    int i;
// for(i=0;i<26;i++){ // printf("id=%s\n", ids[i]);
// }
    ht = ht_create(26);
    for( i = 0; i < 26; i++ ) {
	ht_set(ht, ids[i], ids[i]);
    }
    ht_set(ht, ids[10], ids[10]);
    for( i = 0; i < 26; i++ ) {
	const char *x = ht_find(ht, ids[i]);
	printf("%s --> %s\n", ids[i], x != NULL && strcmp(ids[i], x) == 0 ? "+" :"FAILED"); 
    }
    printf("Items: %d. Collisions: %d\n", (int)ht_size(ht), (int)ht_collisions(ht));
    ht_destroy(ht);
    return 0; 
}
*/