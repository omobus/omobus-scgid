/* -*- H -*- */
/* Copyright (c) 2006 - 2020 omobus-scgid authors, see the included COPYRIGHT file. */

#ifndef __lsdir_h__
#define __lsdir_h__

#include <sys/stat.h>

typedef short (pf_lsdir_filter)(void *cookie, const char *name);
typedef int (pf_lsdir_setfile)(void *cookie, const char *name, const char *fn, struct stat *st);

#ifdef __cplusplus
extern "C" {
#endif

int lsdir(const char *dir, void *cookie, pf_lsdir_filter filter, pf_lsdir_setfile setfile);

#ifdef __cplusplus
}
#endif

#endif //__lsdir_h__
