/* -*- H -*- */
/* Copyright (c) 2006 - 2021 omobus-scgid authors, see the included COPYRIGHT file. */

#ifndef __ftp_h__
#define __ftp_h__

#include <stdio.h>

typedef void* ftp_ctx_t;
typedef void (*ftp_nlst_cb)(void *cookie, const void *ptr, int len);
typedef void (*ftp_retr_cb)(void *cookie, const void *ptr, int len);
typedef int (*ftp_stor_cb)(void *cookie, void *ptr, int len);

typedef void (*ftp_pull_cb)(void *cookie, const char *name, const char *fn, short complete, int iter, int size);
typedef void (*ftp_move_cb)(void *cookie, const char *name, short complete, int iter, int size);

#ifdef __cplusplus
extern "C" {
#endif

ftp_ctx_t ftp_connect(FILE * log, const char *host, unsigned int port, unsigned int connect_timeout, 
    unsigned int recv_timeout, unsigned int send_timeout, short epsv);
int ftp_disconnect(ftp_ctx_t p);
void ftp_quit(ftp_ctx_t p);
int ftp_login(ftp_ctx_t p, const char *user, const char *pwd);
void ftp_feat(ftp_ctx_t p);
int ftp_cwd(ftp_ctx_t p, const char *dir);
int ftp_nlst(ftp_ctx_t p, ftp_nlst_cb cb, void *cookie);
int ftp_nlst_mem(ftp_ctx_t p, char **buf, int *len);
int ftp_dele(ftp_ctx_t p, const char *fn);
int ftp_retr(ftp_ctx_t p, const char *fn, ftp_retr_cb cb, void *cookie);
int ftp_retr_f(ftp_ctx_t p, const char *fn, const char *l_fn);
int ftp_retr_mem(ftp_ctx_t p, const char *fn, char **buf, size_t *size);
int ftp_stor(ftp_ctx_t p, const char *fn, ftp_stor_cb cb, void *cookie);
int ftp_stor_f(ftp_ctx_t p, const char *f_fn, const char *l_fn);
int ftp_stor_safe(ftp_ctx_t p, const char *fn, ftp_stor_cb cb, void *cookie, int size);
int ftp_stor_f_safe(ftp_ctx_t p, const char *f_fn, const char *l_fn);
int ftp_size(ftp_ctx_t p, const char *fn);
int ftp_rename(ftp_ctx_t p, const char *fn_from, const char *fn_to);

/* rfc4217: Securing FTP with TLS */
int ftp_authtls(ftp_ctx_t p, short noverifycert, short allowexpired, short noverifyname, 
    const char *ca_file, const char *ciphers); /* AUTH TLS */
int ftp_ccc(ftp_ctx_t p); /* Clear Command Channel */
int ftp_prot(ftp_ctx_t p); /* Protected Data Channel */
int ftp_cdc(ftp_ctx_t p); /* Clear Data Channel */

#ifdef __cplusplus
} //extern "C"
#endif

#endif //__ftp_h__
