/* -*- C -*- */
/* Copyright (c) 2006 - 2020 omobus-scgid authors, see the included COPYRIGHT file. */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include "lsdir.h"
#include "omobus-scgid.h"

int lsdir(const char *dir, void *cookie, pf_lsdir_filter filter, pf_lsdir_setfile setfile)
{
    int rc = OMOBUS_OK, l = 0;
    DIR *dp = NULL;
    struct dirent *d = NULL;
    char *fn = NULL, delim[2] = "";
    struct stat st;

    if( dir == NULL || (l = strlen(dir)) < 2 ) {
	errno = EINVAL;
	return OMOBUS_ERR;
    }
    if( (dp = opendir(dir)) == NULL ) {
	return OMOBUS_ERR;
    }
    if( dir[l-1] != '/' ) {
	delim[0] = '/';
    }
    while( rc == OMOBUS_OK && (d = readdir(dp)) != NULL ) {
	if( strcmp(d->d_name, ".") == 0 || strcmp(d->d_name, "..") == 0 ) {
	    continue;
	}
	if( filter != NULL && !filter(cookie, d->d_name) ) {
	    continue;
	}
	if( asprintf(&fn, "%s%s%s", dir, delim, d->d_name) == -1 || fn == NULL ) {
	    rc = OMOBUS_ERR;
	} else if( stat(fn, &st) == -1 ) {
	    rc = OMOBUS_ERR;
	} else if( setfile != NULL ) {
	    rc = setfile(cookie, d->d_name, fn, &st);
	}
	chk_free(fn);
    }
    (void)closedir(dp);

    return rc;
}
