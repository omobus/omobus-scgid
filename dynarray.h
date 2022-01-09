/* -*- H -*- */
/* Copyright (c) 2006 - 2022 omobus-scgid authors, see the included COPYRIGHT file. */

#ifndef __dynarray_h__
#define __dynarray_h__

#include <stdint.h>

typedef void* dynarray_t;
typedef void (*da_for_cb)(void *cookie, void *ptr);
typedef short (*da_if_cb)(void *cookie, void *ptr);

#ifdef __cplusplus
extern "C" {
#endif

/* Create dynarray object. */
dynarray_t da_create(size_t elem, size_t init, size_t grow);
/* Destroy dynarray object. */
void da_destroy(dynarray_t da);

/* Deletes all items from the dynarray and frees allocated memory. */
void da_clear(dynarray_t da);
/* Shrink dynarray without reallocations to the new size. */
void da_shrink(dynarray_t da, size_t size);
/* Zero internal memory buffer [ = memset(..,0,..) ]*/
void da_zero(dynarray_t da);

/* Push new item to the end of the array. Returns new allocated item. */
void *da_push(dynarray_t da);
void *da_push_z(dynarray_t da); /* push and zero memory */
/* Remove last item from the dynarray. */
void da_pop_back(dynarray_t da);

/* Returns 1 if dynarray is empty otherwise returns 0. */
short da_empty(dynarray_t da);
/* Returns dynarray items count. */
size_t da_size(dynarray_t da);
/* Returns index item. */
void *da_get(dynarray_t da, size_t index);
/* Returns first item. */
void *da_front(dynarray_t da);
/* Returns last item. */
void *da_back(dynarray_t da);

/* Reurns reallocs count. */
size_t da_stat(dynarray_t da);

/* Execute function for each item in the dynarray */
void da_for_each(dynarray_t da, void *cookie, da_for_cb func);
/* Count items */
size_t da_count_if(dynarray_t da, void *cookie, da_if_cb func);
/* Find item */
void *da_find_if(dynarray_t da, void *cookie, da_if_cb func);

#ifdef __cplusplus
}
#endif

#endif //__dynarray_h__
