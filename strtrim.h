/* -*- H -*- */
/* Copyright (c) 2006 - 2022 omobus-scgid authors, see the included COPYRIGHT file. */

#ifndef __strtrim_h__
#define __strtrim_h__

#ifdef __cplusplus
extern "C" {
#endif

char *strtrim(char *s, char ch);
char *strrtrim(char *s, char ch);
char *strltrim(char *s, char ch);

char *strtrim_multi(char *s, const char *ch, int size);
char *strrtrim_multi(char *s, const char *ch, int size);
char *strltrim_multi(char *s, const char *ch, int size);

#ifdef __cplusplus
} //extern "C"
#endif

#endif //__strtrim_h__
