/* -*- C -*- */
/* Copyright (c) 2006 - 2022 omobus-scgid authors, see the included COPYRIGHT file. */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdarg.h>

#include "setproctitle.h"

#ifndef SPT_BUFSIZE
# define SPT_BUFSIZE     2048
#endif

extern char **environ;
static char **argv0;
static int argv_lth;

void initproctitle(int argc, char **argv)
{
    int i;
    char **envp = environ;

/*
 * Move the environment so we can reuse the memory.
 * (Code borrowed from sendmail.)
 * WARNING: ugly assumptions on memory layout here;
 *          if this ever causes problems, #undef DO_PS_FIDDLING
 */
    for( i = 0; envp[i] != NULL; i++ ) {
		continue;
    }

    if( (environ = (char **) malloc(sizeof(char *) * (i + 1))) == NULL) {
	return;
    }
    for( i = 0; envp[i] != NULL; i++ ) {
	if( (environ[i] = strdup(envp[i])) == NULL ) {
	    return;
	}
    }
    environ[i] = NULL;

    argv0 = argv;
    if( i > 0 ) {
	argv_lth = envp[i-1] + strlen(envp[i-1]) - argv0[0];
    } else {
	argv_lth = argv0[argc-1] + strlen(argv0[argc-1]) - argv0[0];
    }
}

void setproctitle(const char *fmt, ...)
{
    va_list ap;
    int i;
    char buf[SPT_BUFSIZE];

    if( argv0 == NULL ) {
        return;
    }

    va_start(ap, fmt);
    vsnprintf(buf, SPT_BUFSIZE, fmt, ap);
    va_end(ap);

    if( (i = strlen(buf)) > argv_lth - 2) {
        i = argv_lth - 2;
        buf[i] = '\0';
    }
    memset(argv0[0], '\0', argv_lth);       /* clear the memory area */
    strcpy(argv0[0], buf);

    argv0[1] = NULL;
}
