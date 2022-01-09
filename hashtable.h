/* -*- H -*- */
/* Copyright (c) 2006 - 2022 omobus-scgid authors, see the included COPYRIGHT file. */

#ifndef __hashtable_h__
#define __hashtable_h__

#include <stdint.h>

typedef void* hashtable_t;
typedef void (*ht_for_each_cb)(void *cookie, const char *key, const void *value);

#ifdef __cplusplus
extern "C" {
#endif

/* Creates hashtable object. */
hashtable_t ht_create(size_t size);
/* Destroys hashtable object. */
void ht_destroy(hashtable_t ht);

/* Sets item to the hashtable. */
int ht_set(hashtable_t ht, const char *key, const void *value);
/* Finds item in the hashtable. Returns item, if exists. Otherwise, returns NULL. */
const void *ht_find(hashtable_t ht, const char *key);
/* Checks item exist in the hashtable. */
short ht_exist(hashtable_t ht, const char *key);

/* Total collisions. */
size_t ht_collisions(hashtable_t ht);
/* Total items. */
size_t ht_size(hashtable_t ht);

/* Execute function for each item in the hashtable */
void ht_for_each(hashtable_t ht, void *cookie, ht_for_each_cb func);

#ifdef __cplusplus
}
#endif

#endif //__hashtable_h__
