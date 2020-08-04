/* -*- C -*- */
/* Copyright (c) 2006 - 2020 omobus-scgid authors, see the included COPYRIGHT file. */

#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/asn1.h>

#include "tls.h"
#include "memdup.h"
#include "omobus-scgid.h"

#if OPENSSL_VERSION_NUMBER<0x10100000L
# define ASN1_STRING_get0_data 	ASN1_STRING_data
#endif

#define JPREFIX 		OMOBUS_JPREFIX
#if (OPENSSL_VERSION_NUMBER >= 0x10101000L)
# define TLS_CIPHERS_DEFAULT	"TLSv1.3:TLSv1.2+ECDHE:TLSv1.2+DHE"
#else
# define TLS_CIPHERS_DEFAULT	"TLSv1.2+ECDHE:TLSv1.2+DHE"
#endif //OPENSSL_VERSION_NUMBER >= 0x10101000L
#define TLS_CIPHERS_COMPAT	"HIGH:!aNULL"
#define TLS_CIPHERS_LEGACY	"HIGH:MEDIUM:!aNULL"
#define TLS_CIPHERS_ALL		"ALL:!aNULL:!eNULL"


typedef struct _tls_config_ctx {
    char ca_file[PATH_MAX+1];
    void *ca_mem;
    size_t ca_size;
    char *ciphers;
    uint32_t protocols;
    short verify_cert;
    int verify_depth;
    short verify_name;
    short expired;
} tls_config_ctx;

typedef struct _tls_ctx {
    tls_config_ctx *config;
    int socket;
    SSL *ssl_conn;
    SSL_CTX *ssl_ctx;
    SSL_SESSION *session;
    short connected;
} tls_ctx;


void tls_init()
{
    static int tls_initialised = 0;

    if( !tls_initialised ) {
	SSL_load_error_strings();
	SSL_library_init();
	tls_initialised = 1;
    }
}

tls_config_t tls_config_new()
{
    tls_config_ctx *config;

    if( (config = (tls_config_ctx *) malloc(sizeof(tls_config_ctx))) == NULL ) {
	allocate_memory_error(strerror(errno));
	return NULL;
    }
    memset(config, 0, sizeof(tls_config_ctx));
    /* Default configuration. */
    tls_config_set_ciphers(config, "secure");
    tls_config_set_protocols(config, TLS_PROTOCOLS_DEFAULT);
    tls_config_set_verify_depth(config, 6);
    tls_config_verify(config);

    return (tls_config_t) config;
}

void tls_config_free(tls_config_t ptr)
{
    tls_config_ctx *config;

    if( (config = (tls_config_ctx *) ptr) != NULL ) {
	chk_free(config->ca_mem);
	chk_free(config->ciphers);
	free(config);
    }
}

void tls_config_set_ca_file(tls_config_t ptr, const char *ca_file)
{
    tls_config_ctx *config;
    if( (config = (tls_config_ctx *) ptr) != NULL ) {
	strncpy(config->ca_file, ca_file, PATH_MAX);
    }
}

void tls_config_set_ca_mem(tls_config_t ptr, const void *ca, size_t size)
{
    tls_config_ctx *config;
    if( (config = (tls_config_ctx *) ptr) != NULL && size <= INT_MAX ) {
	chk_free(config->ca_mem);
	config->ca_size = 0;
	if( ca != NULL && size > 0 && size <= INT_MAX ) {
	    if( (config->ca_mem = memdup(ca, size)) != NULL ) {
		config->ca_size = size;
	    }
	}
    }
}

void tls_config_set_ciphers(tls_config_t ptr, const char *ciphers)
{
    tls_config_ctx *config;
    if( (config = (tls_config_ctx *) ptr) != NULL ) {
	if (ciphers == NULL || strcasecmp(ciphers, "default") == 0 || strcasecmp(ciphers, "secure") == 0) {
	    ciphers = TLS_CIPHERS_DEFAULT;
	} else if (strcasecmp(ciphers, "compat") == 0 ) {
	    ciphers = TLS_CIPHERS_COMPAT;
	} else if (strcasecmp(ciphers, "legacy") == 0) {
	    ciphers = TLS_CIPHERS_LEGACY;
	} else if (strcasecmp(ciphers, "all") == 0 || strcasecmp(ciphers, "insecure") == 0) {
	    ciphers = TLS_CIPHERS_ALL;
	}
	chk_free(config->ciphers);
	config->ciphers = strdup(ciphers);
    }
}

void tls_config_set_protocols(tls_config_t ptr, uint32_t protocols)
{
    tls_config_ctx *config;
    if( (config = (tls_config_ctx *) ptr) != NULL ) {
	config->protocols = protocols;
    }
}

void tls_config_set_verify_depth(tls_config_t ptr, int verify_depth)
{
    tls_config_ctx *config;
    if( (config = (tls_config_ctx *) ptr) != NULL ) {
	config->verify_depth = verify_depth;
    }
}

void tls_config_insecure_noverifycert(tls_config_t ptr)
{
    tls_config_ctx *config;
    if( (config = (tls_config_ctx *) ptr) != NULL ) {
	config->verify_cert = 0;
    }
}

void tls_config_insecure_noverifyname(tls_config_t ptr)
{
    tls_config_ctx *config;
    if( (config = (tls_config_ctx *) ptr) != NULL ) {
	config->verify_name = 0;
    }
}

void tls_config_insecure_allowexpired(tls_config_t ptr)
{
    tls_config_ctx *config;
    if( (config = (tls_config_ctx *) ptr) != NULL ) {
	config->expired = 1;
    }
}

void tls_config_verify(tls_config_t ptr)
{
    tls_config_ctx *config;
    if( (config = (tls_config_ctx *) ptr) != NULL ) {
	config->verify_cert = 1;
	config->verify_name = 1;
    }
}

uint32_t tls_parse_protocols(const char *protostr)
{
    uint32_t proto, protos = 0;
    char *s, *p, *q;
    int negate;

    if( (s = strdup(protostr)) == NULL ) {
	return 0;
    }
    q = s;
    while( (p = strsep(&q, ",:")) != NULL ) {
	while (*p == ' ' || *p == '\t') {
	    p++;
	}
	negate = 0;
	if( *p == '!' ) {
	    negate = 1;
	    p++;
	}
	if( negate && protos == 0 ) {
	    protos = TLS_PROTOCOLS_ALL;
	}
	proto = 0;
	if( strcasecmp(p, "all") == 0 || strcasecmp(p, "legacy") == 0 ) {
	    proto = TLS_PROTOCOLS_ALL;
	} else if( strcasecmp(p, "default") == 0 || strcasecmp(p, "secure") == 0 ) {
	    proto = TLS_PROTOCOLS_DEFAULT;
	} else if( strcasecmp(p, "tlsv1") == 0 ) {
	    proto = TLS_PROTOCOL_TLSv1;
	} else if( strcasecmp(p, "tlsv1.0") == 0 ) {
	    proto = TLS_PROTOCOL_TLSv1_0;
	} else if(strcasecmp(p, "tlsv1.1" ) == 0 ) {
	    proto = TLS_PROTOCOL_TLSv1_1;
	} else if( strcasecmp(p, "tlsv1.2") == 0 ) {
	    proto = TLS_PROTOCOL_TLSv1_2;
#if (OPENSSL_VERSION_NUMBER >= 0x10101000L)
	} else if( strcasecmp(p, "tlsv1.3") == 0 ) {
	    proto = TLS_PROTOCOL_TLSv1_3;
#endif //OPENSSL_VERSION_NUMBER >= 0x10101000L
	}
	if (proto == 0) {
	    free(s);
	    return 0;
	}
	if( negate ) {
	    protos &= ~proto;
	} else {
	    protos |= proto;
	}
    }

    free(s);

    return protos;
}

tls_t tls_new(tls_config_t config)
{
    tls_ctx *ctx;

    if( config == NULL ) {
	return NULL;
    }
    if( (ctx = (tls_ctx *) malloc(sizeof(tls_ctx))) == NULL ) {
	allocate_memory_error(strerror(errno));
    } else {
	memset(ctx, 0, sizeof(tls_ctx));
	tls_configure(ctx, config);
	tls_reset(ctx);
    }

    return (tls_t) ctx;
}

void tls_free(tls_t ses)
{
    tls_ctx *ctx;
    if( (ctx = (tls_ctx *) ses) != NULL ) {
	tls_reset(ctx);
	free(ctx);
    }
}

void tls_configure(tls_t ses, tls_config_t config)
{
    tls_ctx *ctx;
    if( (ctx = (tls_ctx *) ses) != NULL && config != NULL ) {
	ctx->config = (tls_config_ctx *) config;
    }
}

void tls_reset(tls_t ses)
{
    tls_ctx *ctx;
    if( (ctx = (tls_ctx *) ses) != NULL ) {
	if( ctx->ssl_ctx != NULL ) {
	    SSL_CTX_free(ctx->ssl_ctx);
	}
	if( ctx->ssl_conn != NULL ) {
	    SSL_free(ctx->ssl_conn);
	}
	if( ctx->session != NULL ) {
	    SSL_SESSION_free(ctx->session);
	}
	ctx->ssl_conn = NULL;
	ctx->ssl_ctx = NULL;
	ctx->session = NULL;
	ctx->socket = -1;
	ctx->connected = 0;
    }
}

static
int tls_configure_ssl(tls_t ses)
{
    tls_ctx *ctx = NULL;
    int rc = OMOBUS_OK;

    if( (ctx = (tls_ctx *) ses) == NULL ) {
	return OMOBUS_ERR;
    }

    SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_SSLv2);
    SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_SSLv3);

    SSL_CTX_clear_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1);
    SSL_CTX_clear_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1_1);
    SSL_CTX_clear_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1_2);
#if (OPENSSL_VERSION_NUMBER >= 0x10101000L)
    SSL_CTX_clear_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1_3);
#endif //OPENSSL_VERSION_NUMBER >= 0x10101000L

    if( (ctx->config->protocols & TLS_PROTOCOL_TLSv1_0) == 0 ) {
	SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1);
    }
    if( (ctx->config->protocols & TLS_PROTOCOL_TLSv1_1) == 0 ) {
	SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1_1);
    }
    if( (ctx->config->protocols & TLS_PROTOCOL_TLSv1_2) == 0 ) {
	SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1_2);
    }
#if (OPENSSL_VERSION_NUMBER >= 0x10101000L)
    if( (ctx->config->protocols & TLS_PROTOCOL_TLSv1_3) == 0 ) {
	SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1_3);
    }
#endif //OPENSSL_VERSION_NUMBER >= 0x10101000L

    if( ctx->config->ciphers != NULL ) {
	if( SSL_CTX_set_cipher_list(ctx->ssl_ctx, ctx->config->ciphers) != 1 ) {
	    logmsg_e(JPREFIX "failed to set ciphers: %s.", ctx->config->ciphers);
	    rc = OMOBUS_ERR;
	}
    }

    return rc;
}

static
int tls_match_name(const char *cert_name, const char *name)
{
    const char *cert_domain, *domain, *next_dot;

    if (strcasecmp(cert_name, name) == 0) {
	return 0;
    }
    /* Wildcard match? */
    if( cert_name[0] == '*' ) {
	/*
	 * Valid wildcards:
	 * - "*.domain.tld"
	 * - "*.sub.domain.tld"
	 * - etc.
	 * Reject "*.tld".
	 * No attempt to prevent the use of eg. "*.co.uk".
	 */
	cert_domain = &cert_name[1];
	/* Disallow "*"  */
	if( cert_domain[0] == '\0' )
	    return -1;
	/* Disallow "*foo" */
	if( cert_domain[0] != '.' )
	    return -1;
	/* Disallow "*.." */
	if( cert_domain[1] == '.' )
	    return -1;
	next_dot = strchr(&cert_domain[1], '.');
	/* Disallow "*.bar" */
	if( next_dot == NULL )
	    return -1;
	/* Disallow "*.bar.." */
	if( next_dot[1] == '.' )
	    return -1;

	domain = strchr(name, '.');

	/* No wildcard match against a name with no domain part. */
	if( domain == NULL || strlen(domain) == 1 )
	    return -1;
	if( strcasecmp(cert_domain, domain) == 0 )
	    return 0;
    }

    return -1;
}

/* See RFC 5280 section 4.2.1.6 for SubjectAltName details. */
static
int tls_check_subject_altname(tls_ctx *ctx, X509 *cert, const char *name)
{
    STACK_OF(GENERAL_NAME) *altname_stack = NULL;
    union { struct in_addr ip4; struct in6_addr ip6; } addrbuf;
    int addrlen, type;
    int count, i;
    int rv = -1;

    if( (altname_stack = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL)) == NULL ) {
	return -1;
    }
    if( inet_pton(AF_INET, name, &addrbuf) == 1 ) {
	type = GEN_IPADD;
	addrlen = 4;
    } else if( inet_pton(AF_INET6, name, &addrbuf) == 1 ) {
	type = GEN_IPADD;
	addrlen = 16;
    } else {
	type = GEN_DNS;
	addrlen = 0;
    }

    count = sk_GENERAL_NAME_num(altname_stack);
    for( i = 0; i < count; i++ ) {
	GENERAL_NAME *altname = sk_GENERAL_NAME_value(altname_stack, i);
	if( altname->type != type ) {
	    continue;
	}
	if (type == GEN_DNS) {
	    const char *data;
	    int format, len;
	    format = ASN1_STRING_type(altname->d.dNSName);
	    if( format == V_ASN1_IA5STRING ) {
		data = (const char *) ASN1_STRING_get0_data(altname->d.dNSName);
		len = ASN1_STRING_length(altname->d.dNSName);
		if( len < 0 || len != strlen((const char *)data) ) {
		    logmsg_e(JPREFIX 
			"error verifying name '%s': NUL byte in subjectAltName, probably a malicious certificate.",
			name);
		    rv = -2;
		    break;
		}
		/*
		 * Per RFC 5280 section 4.2.1.6:
		 * " " is a legal domain name, but that
		 * dNSName must be rejected.
		 */
		if( strcmp((const char *)data, " ") == 0 ) {
		    logmsg_e(
			JPREFIX "error verifying name '%s': a dNSName of \" \" must not be used.", 
			name);
		    rv = -2;
		    break;
		}
		if( tls_match_name((const char *)data, name) == 0 ) {
		    rv = 0;
		    break;
		}
	    } else {
		logmsg_w(
		    JPREFIX "unhandled subjectAltName dNSName encoding (format=%d).", 
		    format);
	    }
	} else if( type == GEN_IPADD ) {
	    const char *data = (const char *) ASN1_STRING_get0_data(altname->d.iPAddress);
	    int datalen = ASN1_STRING_length(altname->d.iPAddress);
	    if( datalen < 0 ) {
		logmsg_e(
		    JPREFIX "Unexpected negative length for an IP address: %d", datalen);
		rv = -2;
		break;
	    }
	    /*
	     * Per RFC 5280 section 4.2.1.6:
	     * IPv4 must use 4 octets and IPv6 must use 16 octets.
	     */
	    if( datalen == addrlen && memcmp(data, &addrbuf, addrlen) == 0 ) {
		rv = 0;
		break;
	    }
	}
    }

    sk_GENERAL_NAME_pop_free(altname_stack, GENERAL_NAME_free);
    return rv;
}

static
int tls_check_common_name(tls_ctx *ctx, X509 *cert, const char *name)
{
    X509_NAME *subject_name;
    char *common_name = NULL;
    int common_name_len;
    int rv = -1;
    union { struct in_addr ip4; struct in6_addr ip6; } addrbuf;

    if( (subject_name = X509_get_subject_name(cert)) == NULL ) {
	goto out;
    }
    if( (common_name_len = X509_NAME_get_text_by_NID(subject_name, NID_commonName, NULL, 0)) < 0 ) {
	goto out;
    }
    if( (common_name = calloc(common_name_len + 1, 1)) == NULL ) {
	goto out;
    }
    X509_NAME_get_text_by_NID(subject_name, NID_commonName, common_name, common_name_len + 1);
    /* NUL bytes in CN? */
    if( common_name_len != strlen(common_name) ) {
	logmsg_e(JPREFIX 
	    "error verifying name '%s': NUL byte in Common Name field, probably a malicious certificate", 
	    name);
	rv = -2;
	goto out;
    }
    if( inet_pton(AF_INET,  name, &addrbuf) == 1 || inet_pton(AF_INET6, name, &addrbuf) == 1) {
	/*
	 * We don't want to attempt wildcard matching against IP
	 * addresses, so perform a simple comparison here.
	 */
	if( strcmp(common_name, name) == 0 ) {
	    rv = 0;
	} else {
	    rv = -1;
	}
	goto out;
    }
    if( tls_match_name(common_name, name) == 0 ) {
	rv = 0;
    }

out:
    free(common_name);
    return rv;
}

static
int tls_check_servername(tls_ctx *ctx, X509 *cert, const char *servername)
{
    int rv = tls_check_subject_altname(ctx, cert, servername);
    return (rv == 0 || rv == -2) ? rv : tls_check_common_name(ctx, cert, servername);
}

static 
int _trace_verification(int ok, X509_STORE_CTX *ctx)
{
    char buf[256];
    int err;
    if( !ok ) {
	err = X509_STORE_CTX_get_error(ctx);
	memset(buf, 0, sizeof(char)*256);
	X509_NAME_oneline(X509_get_subject_name(X509_STORE_CTX_get_current_cert(ctx)), buf, 255);
	logmsg_w(JPREFIX "verify error:num=%d:%s:%s.", 
	    err, X509_verify_cert_error_string(err), buf);
    }
    return ok;
}

int _tls_shutdown(SSL *conn)
{
    int r, rc = OMOBUS_OK;
    if( (r = SSL_shutdown(conn)) < 0 ) {
	logmsg_e(JPREFIX "failed to shutdown tls session: %s.", 
	    ERR_reason_error_string(SSL_get_error(conn, r)));
	rc = OMOBUS_ERR;
    } else if( r == 0 ) {
	SSL_shutdown(conn);
    }
    return rc;
}

static
int tls_connect_fds(tls_ctx *ctx, int fd_read, int fd_write, const char *servername)
{
    union { struct in_addr ip4; struct in6_addr ip6; } addrbuf;
    X509 *cert = NULL;
    int ret;

    if( ctx->connected ) {
	return OMOBUS_OK;
    }
    if( fd_read < 0 || fd_write < 0 ) {
	logmsg_e(JPREFIX "invalid file descriptors.");
	return OMOBUS_ERR;
    }
    if( ctx->ssl_ctx == NULL ) {
	if( (ctx->ssl_ctx = SSL_CTX_new(SSLv23_client_method())) == NULL ) {
	    logmsg_e(JPREFIX "TLS context failure.");
	    return OMOBUS_ERR;
	}
	if( tls_configure_ssl(ctx) != 0 ) {
	    tls_reset(ctx);
	    return OMOBUS_ERR;
	}
	if( ctx->config->verify_name ) {
	    if( servername == NULL || servername[0] == '\0' ) {
		logmsg_e(JPREFIX "server name not specified.");
		tls_reset(ctx);
		return OMOBUS_ERR;
	    }
	}

	SSL_CTX_set_verify(ctx->ssl_ctx, (ctx->config->verify_cert&&(!ctx->config->expired)) ? 
	    SSL_VERIFY_PEER : SSL_VERIFY_NONE, _trace_verification);
	ret = -1;
	if( ctx->config->ca_mem != NULL ) {
#ifdef LIBRESSL_VERSION_NUMBER
	    ret = SSL_CTX_load_verify_mem(ctx->ssl_ctx, ctx->config->ca_mem, ctx->config->ca_size);
#endif //LIBRESSL_VERSION_NUMBER
	} else if( ctx->config->ca_file[0] != '\0' ) {
	    ret = SSL_CTX_load_verify_locations(ctx->ssl_ctx, ctx->config->ca_file, NULL);
	}
	if( ret != 1 && ctx->config->verify_cert ) {
	    logmsg_e(JPREFIX "unable to setup TLS verification procedure.");
	    tls_reset(ctx);
	    return OMOBUS_ERR;
	}
	if( ctx->config->verify_depth >= 0 ) {
	    SSL_CTX_set_verify_depth(ctx->ssl_ctx, ctx->config->verify_depth);
	}
    }
    if( ctx->ssl_conn == NULL ) {
	if( (ctx->ssl_conn = SSL_new(ctx->ssl_ctx)) == NULL ) {
	    logmsg_e(JPREFIX "unable to create TLS connection instance.");
	    tls_reset(ctx);
	    return OMOBUS_ERR;
	}
	if( SSL_set_rfd(ctx->ssl_conn, fd_read) != 1 || SSL_set_wfd(ctx->ssl_conn, fd_write) != 1 ) {
	    logmsg_e(JPREFIX "unable to set file descriptor.");
	    tls_reset(ctx);
	    return OMOBUS_ERR;
	}
	if( ctx->session != NULL ) {
	    SSL_set_session(ctx->ssl_conn, ctx->session);
	}
	/*
	 * RFC4366 (SNI): Literal IPv4 and IPv6 addresses are not
	 * permitted in "HostName".
	 */
	if( servername != NULL &&
	    inet_pton(AF_INET, servername, &addrbuf) != 1 &&
	    inet_pton(AF_INET6, servername, &addrbuf) != 1) {
	    if( SSL_set_tlsext_host_name(ctx->ssl_conn, servername) == 0 ) {
		logmsg_e(JPREFIX "server name indication failure.");
		tls_reset(ctx);
		return OMOBUS_ERR;
	    }
	}
    }
    if( (ret = SSL_connect(ctx->ssl_conn)) != 1 ) {
	logmsg_e(JPREFIX "TLS handshake error:num=%d.", 
	    SSL_get_error(ctx->ssl_conn, ret));
	tls_reset(ctx);
	return OMOBUS_ERR;
    }
    if( ctx->config->verify_cert && (ret = SSL_get_verify_result(ctx->ssl_conn)) != X509_V_OK ) {
	if( !(ctx->config->expired && ret == X509_V_ERR_CERT_HAS_EXPIRED) ) {
	    logmsg_e(JPREFIX "unable to verify server certificate error:num=%d:%s.",
		ret, X509_verify_cert_error_string(ret));
	    _tls_shutdown(ctx->ssl_conn);
	    tls_reset(ctx);
	    return OMOBUS_ERR;
	}
    }
    if( ctx->config->verify_cert && ctx->config->verify_name ) {
	if( (cert = SSL_get_peer_certificate(ctx->ssl_conn)) == NULL ) {
	    logmsg_e(JPREFIX "no server certificate.");
	    _tls_shutdown(ctx->ssl_conn);
	    tls_reset(ctx);
	    return OMOBUS_ERR;
	}
	ret = tls_check_servername(ctx, cert, servername);
	X509_free(cert);
	if( ret != 0 ) {
	    if( ret != -2 ) {
		logmsg_e(JPREFIX "name `%s' not present in server certificate.", 
		    servername);
	    }
	    _tls_shutdown(ctx->ssl_conn);
	    tls_reset(ctx);
	    return OMOBUS_ERR;
	}
    }

    ctx->connected = 1;

    return OMOBUS_OK;
}

int tls_connect(tls_t ses, int sock, const char *servername)
{
    tls_ctx *ctx; int rc = OMOBUS_ERR;
    if( (ctx = (tls_ctx *) ses) != NULL ) {
	ctx->socket = sock;
	rc = tls_connect_fds(ctx, sock, sock, servername);
    }
    return rc;
}

int tls_connect_reuse_session(tls_t ses, int sock, const char *servername, tls_t exist)
{
    tls_ctx *ctx; int rc = OMOBUS_ERR;
    if( (ctx = (tls_ctx *) ses) != NULL ) {
	ctx->socket = sock;
	ctx->session = exist == NULL ? NULL : SSL_get1_session(((tls_ctx *) exist)->ssl_conn);
	rc = tls_connect_fds(ctx, sock, sock, servername);
    }
    return rc;
}

int tls_read(tls_t ses, void *buf, size_t buflen, size_t *outlen)
{
    tls_ctx *ctx; int r = -1;
    if( buflen > INT_MAX ) {
	logmsg_e(JPREFIX "input buffer too long.");
	return OMOBUS_ERR;
    }
    if( (ctx = (tls_ctx *) ses) != NULL ) {
	if( (r = SSL_read(ctx->ssl_conn, buf, buflen)) >= 0) {
	    *outlen = (size_t) r;
	} else {
	    int err = SSL_get_error(ctx->ssl_conn, r);
	    logmsg_e(JPREFIX "failed to read tls data; error:num=%u:%s.", 
		err, ERR_reason_error_string(err));
	}
    }
    return r >= 0 ? OMOBUS_OK : OMOBUS_ERR;
}

int tls_write(tls_t ses, const void *buf, size_t buflen, size_t *outlen)
{
    tls_ctx *ctx; int r = -1;
    if( buflen > INT_MAX ) {
	logmsg_e(JPREFIX "input buffer too long.");
	return OMOBUS_ERR;
    }
    if( (ctx = (tls_ctx *) ses) != NULL ) {
	if( (r = SSL_write(ctx->ssl_conn, buf, buflen)) > 0 ) {
	    *outlen = (size_t) r;
	} else {
	    int err = SSL_get_error(ctx->ssl_conn, r);
	    logmsg_e(JPREFIX "failed to write tls data; error:num=%u:%s.",
		err, ERR_reason_error_string(err));
	}
    }
    return r > 0 ? OMOBUS_OK : OMOBUS_ERR;
}

ssize_t tls_recv(tls_t ses, void *buf, size_t len)
{
    size_t x = 0;
    return (ssize_t) (tls_read(ses, buf, len, &x) == OMOBUS_OK ? x : -1);
}

ssize_t tls_send(tls_t ses, const void *buf, size_t len)
{
    size_t x = 0;
    return (ssize_t) (tls_write(ses, buf, len, &x) == OMOBUS_OK ? x : -1);
}

int tls_close(tls_t ses)
{
    tls_ctx *ctx; int rc = OMOBUS_OK;
    if( (ctx = (tls_ctx *) ses) != NULL ) {
	if( ctx->ssl_conn != NULL && ctx->connected ) {
	    rc = _tls_shutdown(ctx->ssl_conn);
	}
	ctx->connected = 0;
    }
    return rc;
}

const char *tls_protocol(tls_t ses)
{
    return ses != NULL ? SSL_get_version(((tls_ctx *) ses)->ssl_conn) : NULL;
}

const char *tls_ciphername(tls_t ses)
{
    return SSL_CIPHER_get_name(ses != NULL ? SSL_get_current_cipher(((tls_ctx *) ses)->ssl_conn) : NULL);
}

int tls_cipherbits(tls_t ses)
{
    return SSL_CIPHER_get_bits(ses != NULL ? SSL_get_current_cipher(((tls_ctx *) ses)->ssl_conn) : NULL, NULL);
}

short tls_connected(tls_t ses)
{
    return ses != NULL ? ((tls_ctx *) ses)->connected : 0;
}

