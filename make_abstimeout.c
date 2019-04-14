/* -*- C -*- */
/* Copyright (c) 2006 - 2019 omobus-scgid authors, see the included COPYRIGHT file. */

#include "make_abstimeout.h"

struct timespec *make_abstimeout(unsigned int timeout, struct timespec *ts)
{
    struct timeval nowtime;
    if( gettimeofday(&nowtime, NULL) != -1 ) {
	int64_t tmpVal = nowtime.tv_usec + ((int64_t)timeout) * 1000;
	ts->tv_sec = nowtime.tv_sec + tmpVal / 1000000;
	ts->tv_nsec = tmpVal % 1000000;
	ts->tv_nsec *= 1000;
    }
    return ts;
}

