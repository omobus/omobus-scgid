/* -*- H -*- */
/* Copyright (c) 2006 - 2022 omobus-scgid authors, see the included COPYRIGHT file. */

#ifndef __tls_h__
#define __tls_h__

#include <stddef.h>
#include <stdint.h>

#define TLS_PROTOCOL_TLSv1_0	0x01
#define TLS_PROTOCOL_TLSv1_1	0x02
#define TLS_PROTOCOL_TLSv1_2	0x04
#if (OPENSSL_VERSION_NUMBER >= 0x10101000L)
# define TLS_PROTOCOL_TLSv1_3	0x08
# define TLS_PROTOCOL_TLSv1	(TLS_PROTOCOL_TLSv1_0|TLS_PROTOCOL_TLSv1_1|TLS_PROTOCOL_TLSv1_2|TLS_PROTOCOL_TLSv1_3)
# define TLS_PROTOCOLS_DEFAULT	(TLS_PROTOCOL_TLSv1_2|TLS_PROTOCOL_TLSv1_3)
#else
# define TLS_PROTOCOL_TLSv1	(TLS_PROTOCOL_TLSv1_0|TLS_PROTOCOL_TLSv1_1|TLS_PROTOCOL_TLSv1_2)
# define TLS_PROTOCOLS_DEFAULT	TLS_PROTOCOL_TLSv1_2
#endif //OPENSSL_VERSION_NUMBER >= 0x10101000L
#define TLS_PROTOCOLS_ALL 	TLS_PROTOCOL_TLSv1

#ifdef __cplusplus
extern "C" {
#endif

typedef void* tls_t;
typedef void* tls_config_t;

void tls_init();

uint32_t tls_parse_protocols(const char *protostr);

tls_config_t tls_config_new();
void tls_config_free(tls_config_t config);
void tls_config_set_ca_file(tls_config_t config, const char *ca_file);

void tls_config_set_ciphers(tls_config_t _config, const char *ciphers);
void tls_config_set_protocols(tls_config_t config, uint32_t protocols);
void tls_config_set_verify_depth(tls_config_t config, int verify_depth);
void tls_config_insecure_noverifycert(tls_config_t config);
void tls_config_insecure_noverifyname(tls_config_t config);
void tls_config_insecure_allowexpired(tls_config_t config);
void tls_config_verify(tls_config_t config);

tls_t tls_new(tls_config_t config);
void tls_free(tls_t ses);
void tls_reset(tls_t ses);
void tls_configure(tls_t ses, tls_config_t config);

int tls_connect(tls_t ses, int sock, const char *servername);
int tls_connect_reuse_session(tls_t ses, int sock, const char *servername, tls_t exist);
int tls_read(tls_t ses, void *buf, size_t buflen, size_t *outlen);
int tls_write(tls_t ses, const void *buf, size_t buflen, size_t *outlen);
ssize_t tls_recv(tls_t ses, void *buf, size_t len);
ssize_t tls_send(tls_t ses, const void *buf, size_t len);
int tls_close(tls_t ses);
const char *tls_protocol(tls_t ses);
const char *tls_ciphername(tls_t ses);
int tls_cipherbits(tls_t ses);
short tls_connected(tls_t ses);

#ifdef __cplusplus
} //extern "C"
#endif

#endif //__tls_h__
