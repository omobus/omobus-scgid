/* -*- H -*- */
/* Copyright (c) 2006 - 2022 omobus-scgid authors, see the included COPYRIGHT file. */

#ifndef __base64_h__
#define __base64_h__

#ifdef __cplusplus
extern "C" {
#endif

int base64encode_len(int len);
int base64encode(char *coded_dst, const char *plain_src, int len_plain_src);

int base64decode_len(const char *coded_src);
int base64decode(char *plain_dst, const char *coded_src);

#ifdef __cplusplus
}
#endif

#endif //__base64_h__
