/* -*- C -*- */
/* Copyright (c) 2006 - 2020 omobus-scgid authors, see the included COPYRIGHT file. */

#include <string.h>
#include "strtrim.h"

static
short equal(char a, const char *ch, int size) 
{
    int i;
    for( i = 0; i < size; i++ ) {
	if( a == ch[i] ) {
	    return 1;
	}
    }
    return 0;
}

char *strtrim(char *s, char ch)
{
    return strrtrim(strltrim(s, ch), ch);
}

char *strtrim_multi(char *s, const char *ch, int size)
{
    return strrtrim_multi(strltrim_multi(s, ch, size), ch, size);
}

char *strrtrim(char *s, char ch)
{
    char *t, *tt;

    if( s == NULL || *s == 0 ) {
	return s;
    }

    for( tt = t = s; *t != '\0'; ++t ) {
	if( *t != ch ) {
	    tt = t+1;
	}
    }
    *tt = '\0';

    return s;
}

char *strltrim(char *s, char ch)
{
    char *t;

    if( s == NULL || *s == 0 ) {
	return s;
    }
    for( t = s; *t == ch; ++t ) {
	continue;
    }

    memmove(s, t, strlen(t)+1); /* +1 so that '\0' is moved too */

    return s;
}

char *strrtrim_multi(char *s, const char *ch, int size)
{
    char *t, *tt;

    if( s == NULL || *s == '\0' || ch == NULL || *ch == '\0' || size <= 0 ) {
	return s;
    }
    for( tt = t = s; *t != '\0'; ++t ) {
	if( !equal(*t, ch, size) ) {
	    tt = t+1;
	}
    }
    *tt = '\0';

    return s;
}

char *strltrim_multi(char *s, const char *ch, int size)
{
    char *t;

    if( s == NULL || *s == '\0' || ch == NULL || *ch == '\0' || size <= 0 ) {
	return s;
    }
    for( t = s; equal(*t, ch, size); ++t ) {
	continue;
    }

    memmove(s, t, strlen(t)+1); /* +1 so that '\0' is moved too */

    return s;
}
