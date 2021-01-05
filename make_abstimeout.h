/* -*- H -*- */
/* Copyright (c) 2006 - 2021 omobus-scgid authors, see the included COPYRIGHT file. */

#ifndef __make_abstimeout_h__
#define __make_abstimeout_h__

#include <time.h>
#include <inttypes.h>
#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

struct timespec *make_abstimeout(unsigned int timeout, struct timespec *ts);

#endif //__make_abstimeout_h__
