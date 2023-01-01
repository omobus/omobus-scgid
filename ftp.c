/* -*- C -*- */
/* Copyright (c) 2006 - 2022 omobus-scgid authors, see the included COPYRIGHT file. */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <memory.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <unistd.h>

#include "connect_timed.h"
#include "lsdir.h"
#include "dynarray.h"
#include "hashtable.h"
#include "fwrite_safe.h"
#include "tls.h"

#include "ftp.h"
#include "omobus-scgid.h"

#define JPREFIX 		OMOBUS_JPREFIX
#define ETIMEOUTMSG		"The timeout expired before data was sent."

#define FTP_MAX_DATA_LENGTH	16384 /*16K*/
#define FTP_MAX_MSG_LENGTH	1024 /*1K*/
#define FTP_END_LINE		"\r\n"
#define NLST_MAX_MEM		4194304 /*4M*/

#define ftp_msg(msg)		(msg FTP_END_LINE)

typedef struct _ftp_sock_t {
    int sockfd;
    tls_t tlsses;
} ftp_sock_t;

typedef struct _ftp_ctx {
    struct sockaddr_in srv_addr;
    tls_config_t tls_config;
    ftp_sock_t sock;
    char *buf;
    /* ftp server params */
    char *host;
    unsigned int port, connect_timeout, send_timeout, recv_timeout;
    short epsv;
    FILE *log;
    /* user params */
    char *user;
    /* flags */
    short connected, ascii, tr_err, pdc /* Protect Data Channel */;
} ftp_ctx;

typedef struct _nlst_cookie_t {
    char *ptr;
    int len, offset;
    short err;
} nlst_cookie_t;

typedef struct _retr_cookie_t {
    FILE *f;
    short err;
} retr_cookie_t;


static
void retr_cb(void *cookie, const void *ptr, int size) {
    retr_cookie_t *m;
    if( (m = (retr_cookie_t *)cookie) != NULL && ptr != NULL && size > 0 && m->err == 0) {
	if( fwrite_safe(m->f, ptr, size) != OMOBUS_OK ) {
	    logmsg_e(JPREFIX "unable to write data to the file: %s",
		strerror(errno));
	    m->err = 1;
	}
    }
}

static
void nlst_cb(void *cookie, const void *ptr, int len) {
    nlst_cookie_t *m;
    const char *p;
    int i;
    if( (m = (nlst_cookie_t *)cookie) != NULL && (p = (const char *)ptr) != NULL && len > 0 ) {
	for( i = 0; i < len && m->len > m->offset; i++ ) {
	    if( !(p[i] == '\r' || p[i] == '\t') ) {
		m->ptr[m->offset] = p[i];
		m->offset++;
	    }
	}
	if( m->offset >= m->len && m->err == 0 ) {
	    logmsg_e(JPREFIX
		"Unable to write NLST data. NLST buffer does not contain enough memory. Current buffer length: %d bytes.",
		m->len);
	    m->err = 1;
	}
    }
}

static
int stor_cb(void *cookie, void *ptr, int len)
{
    FILE *f;
    if( (f = (FILE *)cookie) == NULL || ptr == NULL || len == 0 ) {
	return -1;
    }
    return (int)fread(ptr, 1, len, f);
}

#ifdef FTP_TRACE
static 
void ftptrace_begin(FILE *log, const char *host, int port) {
}

static 
void ftptrace_end(FILE *log, const char *host, int port) {
}

static 
void ftptrace(FILE *log, char side, const char *buf) {
}
#else
# define ftptrace_begin(log, host, port)
# define ftptrace_end(log, host, port)
# define ftptrace(log, side, buf)
#endif //FTP_TRACE

inline static
int sock_send(ftp_sock_t *p, const void *buf, size_t len) {
    return p->tlsses && tls_connected(p->tlsses) ? tls_send(p->tlsses, buf, len) : send(p->sockfd, buf, len, 0);
}

inline static
int sock_recv(ftp_sock_t *p, void *buf, size_t len) {
    return p->tlsses && tls_connected(p->tlsses) ? tls_recv(p->tlsses, buf, len) : recv(p->sockfd, buf, len, 0);
}

static
int ftp_send(ftp_ctx *ctx, const char *msg, size_t size)
{
    ssize_t sent;
    const char *t = msg;

    if( ctx == NULL || ctx->sock.sockfd == -1 || msg == NULL || size == 0 ) {
	errno = EINVAL;
	return OMOBUS_ERR;
    }
    while( size > 0 && (sent = sock_send(&ctx->sock, t, size)) > 0 ) {
	t += (size_t)sent; size -= (size_t)sent;
    }
    if( sent < 0 ) {
	logmsg_e(JPREFIX "Unable to send data: %s",
	    sock_errno()==EWOULDBLOCK?ETIMEOUTMSG:strerror(sock_errno()));
	ctx->tr_err = 1;
    } else {
	ftptrace(ctx->log, 'C', msg);
    }

    return sent < 0 ? OMOBUS_ERR : OMOBUS_OK;
}

static
int ftp_vsendarg(ftp_ctx *ctx, const char *fmt, va_list ap)
{
    char msg[FTP_MAX_MSG_LENGTH];
    int l;
    return (l = vsnprintf(msg, FTP_MAX_MSG_LENGTH, fmt, ap)) <= 0 ? OMOBUS_ERR : 
	ftp_send(ctx, msg, l);
}

static
int ftp_sendarg(ftp_ctx *ctx, const char *fmt, ...)
{
    int rc;
    va_list ap;
    va_start(ap, fmt);
    rc = ftp_vsendarg(ctx, fmt, ap);
    va_end(ap);
    return rc;
}

static
int ftp_recv_1(ftp_ctx *ctx)
{
    ssize_t r;

    if( ctx == NULL || ctx->sock.sockfd == -1 || ctx->buf == NULL ) {
	errno = EINVAL;
	return OMOBUS_ERR;
    }
    if( (r = sock_recv(&ctx->sock, ctx->buf, (FTP_MAX_DATA_LENGTH-1)*sizeof(char))) != -1 ) {
	ctx->buf[r] = '\0';
	ftptrace(ctx->log, 'S', ctx->buf);
    } else {
	logmsg_e(JPREFIX "Unable to receive data: %s",
	    sock_errno()==EWOULDBLOCK?ETIMEOUTMSG:strerror(sock_errno()));
	ctx->buf[0] = '\0';
	ctx->tr_err = 1;
    }

    return r < 0 ? OMOBUS_ERR : OMOBUS_OK;
}

static
short ftp_more(ftp_ctx *ctx)
{
    char *ptr = NULL, *r, *buf_s;
    short rc = 0;

    if( (buf_s = strdupa(ctx->buf)) == NULL ) {
	return rc;
    }
    while( (r = strtok_r(ptr == NULL ? buf_s : NULL, FTP_END_LINE, &ptr)) != NULL ) {
	if( strlen(r) >= 4 ) {
	    if( r[3] == '-' ) {
		rc = 1;
	    } else if( r[3] == ' ' ) {
		rc = 0;
		break;
	    }
	}
    }

    return rc;
}

static
int ftp_recv(ftp_ctx *ctx)
{
    int rc;
    while( (rc = ftp_recv_1(ctx)) == OMOBUS_OK && ftp_more(ctx) )
	;
    return rc;
}

static
int ftp_cmd(ftp_ctx *ctx, const char *fmt, ...)
{
    va_list ap;
    int rc;
    va_start(ap, fmt);
    rc = (ftp_vsendarg(ctx, fmt, ap) == OMOBUS_ERR || ftp_recv(ctx) == OMOBUS_ERR) ? 
	OMOBUS_ERR : OMOBUS_OK;
    va_end(ap);
    return rc;
}

static
int ftp_code2(ftp_ctx *ctx, int *code2)
{
    char *ptr = NULL, *r, *buf_s;
    int rc = 0, i = 0;

    if( (buf_s = strdupa(ctx->buf)) == NULL ) {
	return rc;
    }
    while( (r = strtok_r(ptr == NULL ? buf_s : NULL, FTP_END_LINE, &ptr)) != NULL ) {
	if( strlen(r) >= 4 ) {
	    if( r[3] == ' ' ) {
		if( i == 0 ) {
		    rc = atoi(r);
		    if( code2 == NULL ) {
			break;
		    }
		} else if( code2 != NULL ) {
		    *code2 = atoi(r);
		}
		i++;
	    }
	}
    }

    return rc;
}

static inline
int ftp_code(ftp_ctx *ctx) {
    return ftp_code2(ctx, NULL);
}

static
const char *ftp_text(ftp_ctx *ctx)
{
    return strlen(ctx->buf) >= 4 ? ctx->buf + 4 : ctx->buf;
}

static
void ftp_disconnect_passive(FILE *log, ftp_sock_t *sock)
{
    if( sock->tlsses != NULL ) {
	tls_close(sock->tlsses);
	tls_free(sock->tlsses);
	sock->tlsses = NULL;
    }
    if( sock->sockfd != SOCKET_ERROR ) {
	shutdown(sock->sockfd, SHUT_RDWR);
	closesocket(sock->sockfd);
	sock->sockfd = SOCKET_ERROR;
    }
#ifdef FTP_TRACE
    if( log != NULL ) {
	fprintf(log, "*: passive connection closed\n");
    }
#endif //FTP_TRACE
}

static
int ftp_connect_passive(ftp_ctx_t p, unsigned int port)
{
    ftp_ctx *ctx;
    int sockfd;
    struct sockaddr_in addr;
    struct timeval tval;

    if( (ctx = (ftp_ctx *) p) == NULL ) {
	return OMOBUS_ERR;
    }
    if( (sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == SOCKET_ERROR ) {
	logmsg_e(JPREFIX "passive: unable to create ftp socket: %s",
	    strerror(sock_errno()));
	return SOCKET_ERROR;
    }

    tval.tv_sec = ctx->recv_timeout;
    tval.tv_usec = 0;
    if( setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tval, sizeof(tval)) == -1 ) {
	logmsg_w(JPREFIX "passive: unable to set passive socket recv timeout=%u: %s",
	    ctx->recv_timeout, strerror(sock_errno()));
    }

    tval.tv_sec = ctx->send_timeout;
    tval.tv_usec = 0;
    if( setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tval, sizeof(tval)) == -1 ) {
	logmsg_w(JPREFIX "passive: unable to set passive socket send timeout=%u: %s",
	    ctx->send_timeout, strerror(sock_errno()));
    }

    memcpy(&addr, &ctx->srv_addr, sizeof(addr));
    addr.sin_port = htons(port);
    if( connect_timed(sockfd, (struct sockaddr*)&addr, sizeof(addr), ctx->connect_timeout) == SOCKET_ERROR ) {
	logmsg_e( JPREFIX "passive: unable to connect to the %s:%u: %s",
	    ctx->host, port, strerror(sock_errno()));
	closesocket(sockfd);
	sockfd = SOCKET_ERROR;
    }
#ifdef FTP_TRACE
    if( sockfd != SOCKET_ERROR && ctx->log != NULL ) {
	fprintf(ctx->log, "*: passive connection to the %s:%u\n", ctx->host, port);
    }
#endif //FTP_TRACE

    return sockfd;
}

ftp_ctx_t ftp_connect(FILE *log, const char *host, unsigned int port, unsigned int connect_timeout, 
    unsigned int recv_timeout, unsigned int send_timeout, short epsv)
{
    struct sockaddr_in addr;
    struct timeval tval;
    struct hostent *ent;
    ftp_ctx *ctx;

    if( host == NULL || port == 0 ) {
	return NULL;
    }
    if( (ctx = (ftp_ctx *) malloc(sizeof(ftp_ctx))) == NULL ) {
	allocate_memory_error(strerror(errno));
	return NULL;
    }
    memset(ctx, 0, sizeof(ftp_ctx));
    ctx->log = log;
    ctx->sock.sockfd = SOCKET_ERROR;
    ctx->port = port;
    ctx->connect_timeout = connect_timeout;
    ctx->recv_timeout = recv_timeout;
    ctx->send_timeout = send_timeout;
    ctx->epsv = epsv;
    ctx->ascii = -1;

    if( (ctx->host = strdup(host)) == NULL ) {
	allocate_memory_error(strerror(errno));
	ftp_disconnect(ctx);
	return NULL;
    }
    if( (ctx->buf = (char *) malloc(sizeof(char)*(FTP_MAX_DATA_LENGTH+1))) == NULL ) {
	allocate_memory_error(strerror(errno));
	ftp_disconnect(ctx);
	return NULL;
    }
    if( (ctx->sock.sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == SOCKET_ERROR ) {
	logmsg_e(JPREFIX "Unable to create ftp socket: %s", 
	    strerror(sock_errno()));
	ftp_disconnect(ctx);
	return NULL;
    }

    tval.tv_sec = recv_timeout;
    tval.tv_usec = 0;
    if( setsockopt(ctx->sock.sockfd, SOL_SOCKET, SO_RCVTIMEO, &tval, sizeof(tval)) == -1 ) {
	logmsg_w(JPREFIX "Unable to set socket recv timeout=%u: %s", 
	    recv_timeout, strerror(sock_errno()));
    }

    tval.tv_sec = send_timeout;
    tval.tv_usec = 0;
    if( setsockopt(ctx->sock.sockfd, SOL_SOCKET, SO_SNDTIMEO, &tval, sizeof(tval)) == -1 ) {
	logmsg_w(JPREFIX "Unable to set socket send timeout=%u: %s", 
	    send_timeout, strerror(sock_errno()));
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(host);
    if( addr.sin_addr.s_addr == INADDR_NONE ) {
	if( (ent = gethostbyname(host)) == NULL ) {
	    static const char _HOST_NOT_FOUND[] = "The specified host is unknown";
	    static const char _NO_DATA[] = "The requested name is valid but does not have an IP address";
	    static const char _NO_RECOVERY[] = "A nonrecoverable name server error occurred";
	    static const char _TRY_AGAIN[] = "A temporary error occurred on an authoritative name server";
	    static const char _UNKNOWN_ERROR[] = "Unexpected error";
	    const char *t = _UNKNOWN_ERROR;
	    if( h_errno == HOST_NOT_FOUND ) {
		t = _HOST_NOT_FOUND;
	    } else if( h_errno == NO_DATA ) {
		t = _NO_DATA;
	    } else if( h_errno == NO_RECOVERY ) {
		t = _NO_RECOVERY;
	    } else if( h_errno == TRY_AGAIN ) {
		t = _TRY_AGAIN;
	    }
	    logmsg_e(JPREFIX "Unable to get network host entry using [gethostbyname] for %s: %s.", 
		host, t);
	    ftp_disconnect(ctx);
	    return NULL;
	} else {
	    memcpy(&addr.sin_addr, ent->h_addr_list[0], ent->h_length);
	}
    }
    if( connect_timed(ctx->sock.sockfd, (struct sockaddr*)&addr, sizeof(addr), connect_timeout) == SOCKET_ERROR ) {
	logmsg_e(JPREFIX "Unable to connect to the %s:%u: %s", 
	    host, port, strerror(sock_errno()));
	ftp_disconnect(ctx);
	return NULL;
    }

    ftptrace_begin(log, host, port);

    if( !(ftp_recv(ctx) == OMOBUS_OK && ftp_code(ctx) == 220) ) {
	logmsg_e(JPREFIX "%s:%u is not a correct FTP-server", 
	    host, port);
	ftp_disconnect(ctx);
	return NULL;
    }

    ctx->connected = 1;
    memcpy(&ctx->srv_addr, &addr, sizeof(ctx->srv_addr));
    ctx->srv_addr.sin_port = 0;

    return ctx;
}

int ftp_disconnect(ftp_ctx_t p)
{
    ftp_ctx *ctx;

    if( (ctx = (ftp_ctx *) p) == NULL ) {
	return OMOBUS_ERR;
    }
    if( ctx->sock.tlsses != NULL ) {
	tls_close(ctx->sock.tlsses);
	tls_free(ctx->sock.tlsses);
	ctx->sock.tlsses = NULL;
    }
    if( ctx->sock.sockfd != SOCKET_ERROR ) {
	shutdown(ctx->sock.sockfd, SHUT_RDWR);
	closesocket(ctx->sock.sockfd);
    }
    if( ctx->connected && ctx->host != NULL && ctx->port > 0 ) {
	ftptrace_end(ctx->log, ctx->host, ctx->port);
    }
    tls_config_free(ctx->tls_config);
    ctx->tls_config = NULL;
    chk_free(ctx->buf);
    chk_free(ctx->host);
    chk_free(ctx->user);
    free(ctx);
    return OMOBUS_OK;
}

int ftp_login(ftp_ctx_t p, const char *user, const char *pwd)
{
    ftp_ctx *ctx = NULL;
    int rc = OMOBUS_ERR;

    if( (ctx = (ftp_ctx *) p) == NULL || user == NULL || pwd == NULL || ctx->tr_err ) {
	return rc;
    }

    chk_free(ctx->user);
    if( ftp_cmd(ctx, ftp_msg("USER %s"), user) == OMOBUS_ERR || ftp_code(ctx) != 331 ) {
	logmsg_e(JPREFIX "%s@%s:%u invalid user name.", 
	    user, ctx->host, ctx->port);
    } else if( ftp_cmd(ctx, ftp_msg("PASS %s"), pwd) == OMOBUS_ERR || ftp_code(ctx) != 230 ) {
	logmsg_e(JPREFIX "%s@%s:%u user name or password is incorrect.", 
	    user, ctx->host, ctx->port);
    } else {
	ctx->user = strdup(user);
	rc = OMOBUS_OK;
    }

    return rc;
}

void ftp_quit(ftp_ctx_t p)
{
    ftp_ctx *ctx;
    if( (ctx = (ftp_ctx *) p) != NULL && !ctx->tr_err ) {
	ftp_cmd(ctx, ftp_msg("QUIT"));
	chk_free(ctx->user);
    }
}

void ftp_feat(ftp_ctx_t p)
{
    ftp_ctx *ctx = NULL;
    if( !((ctx = (ftp_ctx *) p) == NULL || ctx->tr_err) ) {
	ftp_cmd(ctx, ftp_msg("FEAT"));
    }
}

int ftp_cwd(ftp_ctx_t p, const char *dir)
{
    ftp_ctx *ctx = NULL;
    int rc = OMOBUS_ERR;

    if( (ctx = (ftp_ctx *) p) == NULL || dir == NULL || ctx->tr_err ) {
	return rc;
    }
    if( ftp_cmd(ctx, ftp_msg("CWD %s"), dir) == OMOBUS_ERR ) {
	logmsg_e(JPREFIX "%s@%s:%u unable to change directory to %s.", 
	    ctx->user, ctx->host, ctx->port, dir);
    } else if( ftp_code(ctx) == 250 ) {
	rc = OMOBUS_OK;
    } else if( ftp_cmd(ctx, ftp_msg("MKD %s"), dir) == OMOBUS_ERR || ftp_code(ctx) != 257 ) {
	logmsg_e(JPREFIX "%s@%s:%u unable to create directory to %s.", 
	    ctx->user, ctx->host, ctx->port, dir);
    } else if( ftp_cmd(ctx, ftp_msg("CWD %s"), dir) == OMOBUS_ERR || ftp_code(ctx) != 250 ) {
	logmsg_e(JPREFIX "%s@%s:%u unable to change directory to %s.", 
	    ctx->user, ctx->host, ctx->port, dir);
    } else {
	rc = OMOBUS_OK;
    }

    return rc;
}

static
unsigned short ftp_pasv(ftp_ctx_t p)
{
    ftp_ctx *ctx;
    unsigned short port = 0;
    int ip[4], v[2];
    char *str;

    if( (ctx = (ftp_ctx *) p) == NULL || ctx->tr_err ) {
	return port;
    }
/* PASV is RFC959, expect:
 * 227 Entering Passive Mode (a1,a2,a3,a4,p1,p2)
 */
    if( ftp_cmd(ctx, ftp_msg("PASV")) == OMOBUS_ERR || ftp_code(ctx) != 227 ) {
	logmsg_e(JPREFIX "%s@%s:%u PASV mode is not available.", 
	    ctx->user, ctx->host, ctx->port);
    } else {
	str = ctx->buf;
	while( *str ) {
	    if( 6 == sscanf(str, "%d,%d,%d,%d,%d,%d", &ip[0], &ip[1], &ip[2], &ip[3], &v[0], &v[1]) ) {
		port = (unsigned short)(((v[0]<<8) + v[1]) & 0xffff);
		break;
	    }
	    str++;
	}
	if( port == 0 ) {
	    logmsg_e(JPREFIX "%s@%s:%u Weirdly formatted PASV reply.", 
		ctx->user, ctx->host, ctx->port);
	}
    }

    return port;
}

static
unsigned short ftp_epsv(ftp_ctx_t p)
{
    ftp_ctx *ctx;
    unsigned int num, i, resp;
    unsigned short port = 0;
    char *ptr, sep[4];

    if( (ctx = (ftp_ctx *) p) == NULL || ctx->tr_err ) {
	return port;
    }
/* EPSV is RFC2428, expect:
 * 229 Entering Extended Passive Mode (|||port|)
 */
    if( ftp_cmd(ctx, ftp_msg("EPSV")) == OMOBUS_ERR ) {
	logmsg_e(JPREFIX "%s@%s:%u unable to execute EPSV command.", 
	    ctx->user, ctx->host, ctx->port);
    } else if( (resp = ftp_code(ctx)) == 500 ) {
	port = ftp_pasv(ctx);
    } else if( resp != 229 ) {
	logmsg_e(JPREFIX "%s@%s:%u unable to enter to the EPSV mode.", 
	    ctx->user, ctx->host, ctx->port);
    } else {
	if( (ptr = strchr(ctx->buf, '(')) != NULL ) {
	    ptr++;
	    if( 5  == sscanf(ptr, "%c%c%c%u%c", &sep[0], &sep[1], &sep[2], &num, &sep[3])) {
		/* The four separators should be identical, or else this is an oddly
		   formatted reply and we bail out immediately. */
		for( i = 0; i < 4; i++ ) {
		    if( sep[0] != sep[i] ) {
			ptr = NULL;
			break;
		    }
		}
	    }
	    if( ptr != NULL ) {
		port = (unsigned short)(num & 0xffff);
	    }
	}
	if( port == 0 ) {
	    logmsg_e(JPREFIX "%s@%s:%u weirdly formatted EPSV reply.", 
		ctx->user, ctx->host, ctx->port);
	}
    }

    return port;
}

int ftp_nlst(ftp_ctx_t p, ftp_nlst_cb cb, void *cookie)
{
    ftp_ctx *ctx;
    unsigned int newport;
    int r, a = 0;
    char tmp[2048];
    ftp_sock_t sock;

    memset(&sock, 0, sizeof(ftp_sock_t));
    sock.sockfd = SOCKET_ERROR;

    if( (ctx = (ftp_ctx *) p) == NULL || ctx->tr_err ) {
	return OMOBUS_ERR;
    }
    if( (newport = ctx->epsv?ftp_epsv(p):ftp_pasv(p)) == 0 ) {
	logmsg_e(JPREFIX "%s@%s:%u unable to enter to the passive mode.", 
	    ctx->user, ctx->host, ctx->port);
	return OMOBUS_ERR;
    }
    if( ctx->ascii != 1 ) {
	if( ftp_cmd(ctx, ftp_msg("TYPE A")) == OMOBUS_ERR || ftp_code(ctx) != 200 ) {
	    logmsg_e(JPREFIX "%s@%s:%u unable to switch result type to the ASCII mode.", 
		ctx->user, ctx->host, ctx->port);
	    return OMOBUS_ERR;
	}
	ctx->ascii = 1;
    }
    if( ftp_sendarg(ctx, ftp_msg("NLST")) == OMOBUS_ERR ) {
	logmsg_e(JPREFIX "%s@%s:%u unable to send NLST request.", 
	    ctx->user, ctx->host, ctx->port);
	return OMOBUS_ERR;
    }
    if( (sock.sockfd = ftp_connect_passive(ctx, newport)) == SOCKET_ERROR ) {
	logmsg_e(JPREFIX "%s@%s:%u unable to create passive connection. newport: %u", 
	    ctx->user, ctx->host, ctx->port, newport);
	return OMOBUS_ERR;
    }
    if( ftp_recv(ctx) == OMOBUS_ERR || ftp_code2(ctx, &a) != 150 ) {
	logmsg_e(JPREFIX "%s@%s:%u unable to get NLST response (data channel at %u port).", 
	    ctx->user, ctx->host, ctx->port, newport);
	ftp_disconnect_passive(ctx->log, &sock);
	return OMOBUS_ERR;
    }
    if( ctx->pdc ) {
	if( (sock.tlsses = tls_new(ctx->tls_config)) == NULL || 
	    tls_connect_reuse_session(sock.tlsses, sock.sockfd, ctx->host, ctx->sock.tlsses) != OMOBUS_OK ) 
	{
	    ftp_disconnect_passive(ctx->log, &sock);
	    ctx->tr_err = 1;
	    return OMOBUS_ERR;
	}
#ifdef FTP_TRACE
	if( ctx->log != NULL ) {
	    fprintf(ctx->log, "*: protected data channel %s with %s, %u secret bits cipher\n",
		tls_protocol(ctx->sock.tlsses), tls_ciphername(ctx->sock.tlsses), tls_cipherbits(ctx->sock.tlsses));
	}
#endif //FTP_TRACE
    }

    memset(tmp, 0, sizeof(tmp));
    while( (r = sock_recv(&sock, tmp, sizeof(tmp)-sizeof(char))) > 0 ) {
	if( cb != NULL ) {
	    cb(cookie, tmp, r);
	}
	memset(tmp, 0, sizeof(tmp));
    }
    ftp_disconnect_passive(ctx->log, &sock);

    if( r < 0 ) {
	logmsg_e(JPREFIX "%s@%s:%u unable to receive file list from the server.", 
	    ctx->user, ctx->host, newport);
	return OMOBUS_ERR;
    }
    if( a == 0 ) {
	if( ftp_recv(ctx) == OMOBUS_OK ) {
	    a = ftp_code(ctx);
	}
    }
    if( a != 226 ) {
	logmsg_e(JPREFIX "%s@%s:%u invalid NLST response (after receiving data).", 
	    ctx->user, ctx->host, ctx->port);
	return OMOBUS_ERR;
    }

    return OMOBUS_OK;
}

int ftp_nlst_mem(ftp_ctx_t ctx, char **buf, int *len)
{
    int rc = OMOBUS_OK;
    nlst_cookie_t nlst_mem;

    if( buf == NULL || len == NULL ) {
	return OMOBUS_ERR;
    }

    memset(&nlst_mem, 0, sizeof(nlst_mem));
    nlst_mem.len = NLST_MAX_MEM;

    if( (nlst_mem.ptr = malloc(sizeof(char)*nlst_mem.len)) == NULL ) {
	logmsg_e(JPREFIX "Unable to open memory stream for the NLST data: %s",
	    strerror(errno));
	return OMOBUS_ERR;
    }
    memset(nlst_mem.ptr, 0, sizeof(char)*nlst_mem.len);
    if( (rc = ftp_nlst(ctx, nlst_cb, &nlst_mem)) == OMOBUS_OK ) {
	if( nlst_mem.err == 1 ) {
	    rc = OMOBUS_ERR;
	} else {
	    *buf = nlst_mem.ptr;
	    *len = nlst_mem.offset;
	}
    }
    return rc;
}

int ftp_dele(ftp_ctx_t p, const char *fn)
{
    ftp_ctx *ctx = NULL;
    int rc = OMOBUS_ERR;

    if( (ctx = (ftp_ctx *) p) == NULL || ctx->tr_err || fn == NULL ) {
	return rc;
    }
    if( ftp_cmd(ctx, ftp_msg("DELE %s"), fn) == OMOBUS_ERR || ftp_code(ctx) != 250 ) {
	logmsg_e(JPREFIX "%s@%s:%u unable to delete file %s.", 
	    ctx->user, ctx->host, ctx->port, fn);
    } else {
	rc = OMOBUS_OK;
    }

    return rc;
}

int ftp_retr(ftp_ctx_t p, const char *fn, ftp_retr_cb cb, void *cookie)
{
    ftp_ctx *ctx;
    unsigned int newport;
    int r, a = 0;
    char tmp[1024*16];
    ftp_sock_t sock;

    memset(&sock, 0, sizeof(ftp_sock_t));
    sock.sockfd = SOCKET_ERROR;

    if( (ctx = (ftp_ctx *) p) == NULL || ctx->tr_err ) {
	return OMOBUS_ERR;
    }
    if( (newport = ctx->epsv?ftp_epsv(p):ftp_pasv(p)) == 0 ) {
	logmsg_e(JPREFIX "%s@%s:%u unable to enter to the passive mode.", 
	    ctx->user, ctx->host, ctx->port);
	return OMOBUS_ERR;
    }
    if( ctx->ascii != 0 ) {
	if( ftp_cmd(ctx, ftp_msg("TYPE I")) == OMOBUS_ERR || ftp_code(ctx) != 200 ) {
	    logmsg_e(JPREFIX "%s@%s:%u unable to switch result type to the binnary mode.", 
		ctx->user, ctx->host, ctx->port);
	    return OMOBUS_ERR;
	}
	ctx->ascii = 0;
    }
    if( ftp_sendarg(ctx, ftp_msg("RETR %s"), fn) == OMOBUS_ERR ) {
	logmsg_e(JPREFIX "%s@%s:%u unable to send RETR request.", 
	    ctx->user, ctx->host, ctx->port);
	return OMOBUS_ERR;
    }
    if( (sock.sockfd = ftp_connect_passive(ctx, newport)) == SOCKET_ERROR ) {
	logmsg_e(JPREFIX "%s@%s:%u unable to create passive connection.", 
	    ctx->user, ctx->host, newport);
	return OMOBUS_ERR;
    }
    if( ftp_recv(ctx) == OMOBUS_ERR || ftp_code2(ctx, &a) != 150 ) {
	logmsg_e(JPREFIX "%s@%s:%u unable to get RETR response (data channel at %u port).", 
	    ctx->user, ctx->host, ctx->port, newport);
	ftp_disconnect_passive(ctx->log, &sock);
	return OMOBUS_ERR;
    }
    if( ctx->pdc ) {
	if( (sock.tlsses = tls_new(ctx->tls_config)) == NULL || 
	    tls_connect_reuse_session(sock.tlsses, sock.sockfd, ctx->host, ctx->sock.tlsses) != OMOBUS_OK ) 
	{
	    ftp_disconnect_passive(ctx->log, &sock);
	    ctx->tr_err = 1;
	    return OMOBUS_ERR;
	}
#ifdef FTP_TRACE
	if( ctx->log != NULL ) {
	    fprintf(ctx->log, "*: protected data channel %s with %s, %u secret bits cipher\n",
		tls_protocol(ctx->sock.tlsses), tls_ciphername(ctx->sock.tlsses), tls_cipherbits(ctx->sock.tlsses));
	}
#endif //FTP_TRACE
    }

    memset(tmp, 0, sizeof(tmp));
    while( (r = sock_recv(&sock, tmp, sizeof(tmp))) > 0 ) {
	if( cb != NULL ) {
	    cb(cookie, tmp, r);
	}
	memset(tmp, 0, sizeof(tmp));
    }
    ftp_disconnect_passive(ctx->log, &sock);

    if( r < 0 ) {
	logmsg_e(JPREFIX "%s@%s:%u unable to receive %s file from the server.", 
	    ctx->user, ctx->host, newport, fn);
	return OMOBUS_ERR;
    }
    if( a == 0 ) {
	if( ftp_recv(ctx) == OMOBUS_OK ) {
	    a = ftp_code(ctx);
	}
    }
    if( a != 226 ) {
	logmsg_e(JPREFIX "%s@%s:%u invalid RETR response (after receiving data).", 
	    ctx->user, ctx->host, ctx->port);
	return OMOBUS_ERR;
    }

    return OMOBUS_OK;
}

int ftp_retr_f(ftp_ctx_t p, const char *fn, const char *l_fn)
{
    int rc = OMOBUS_OK;
    char *tmp_fn = NULL, *mark = NULL;
    ftp_ctx *ctx;
    retr_cookie_t retr_ctx;
#ifdef FTP_TRACE
    struct stat st;
#endif //FTP_TRACE

    memset(&retr_ctx, 0, sizeof(retr_ctx));

    if( (ctx = (ftp_ctx *) p) == NULL || ctx->tr_err ||  fn == NULL || l_fn == NULL ) {
	return OMOBUS_ERR;
    }
    if( asprintf(&tmp_fn, "%s.t", l_fn) == -1 || tmp_fn == NULL ) {
	logmsg_e(JPREFIX "Unable to allocate memory: %s",
	    strerror(errno));
	return OMOBUS_ERR;
    }
    if( (mark = strrchr(tmp_fn, '/')) != NULL ) {
	*(mark++) = '.';
    }
    if( (retr_ctx.f = fopen(tmp_fn, "wb")) == NULL ) {
	logmsg_e(JPREFIX "Unable to open file '%s': %s",
	    tmp_fn, strerror(errno));
	rc = OMOBUS_ERR;
    } else if( (rc = ftp_retr(p, fn, retr_cb, &retr_ctx)) == OMOBUS_OK && retr_ctx.err == 1 ) {
	logmsg_e(JPREFIX "Unable to download file '%s'",
	    fn);
	rc = OMOBUS_ERR;
    } else {
	fflush(retr_ctx.f);
    }
    if( (rc == OMOBUS_ERR ? unlink(tmp_fn) : rename(tmp_fn, l_fn)) == -1 ) {
	logmsg_e(JPREFIX "Unable to %s file: %s",
	    rc == OMOBUS_ERR ? "unlink" : "rename", strerror(errno));
    } else {
#ifdef FTP_TRACE
	if( ctx->log != NULL ) {
	    fstat(fileno(retr_ctx.f), &st);
	    fprintf(ctx->log, "*: created file %s. Size: %u bytes.\n",
		l_fn, (unsigned int) st.st_size);
	}
#endif //FTP_TRACE
    }
    chk_free(tmp_fn);
    chk_fclose(retr_ctx.f);

    return rc;
}

int ftp_retr_mem(ftp_ctx_t p, const char *fn, char **buf, size_t *size)
{
    int rc = OMOBUS_OK;
    ftp_ctx *ctx;
    retr_cookie_t retr_ctx;

    memset(&retr_ctx, 0, sizeof(retr_ctx));

    if( (ctx = (ftp_ctx *) p) == NULL || ctx->tr_err || buf == NULL || size == NULL ) {
	return OMOBUS_ERR;
    }
    if( (retr_ctx.f = open_memstream(buf, size)) == NULL ) {
	logmsg_e(JPREFIX "Unable to open memory stream: %s", strerror(errno));
	rc = OMOBUS_ERR;
    } else if( (rc = ftp_retr(p, fn, retr_cb, &retr_ctx)) == OMOBUS_OK && retr_ctx.err == 1 ) {
	logmsg_e(JPREFIX "Unable to download file '%s'", fn);
	rc = OMOBUS_ERR;
    }
    chk_fclose(retr_ctx.f);

    return rc;
}

int ftp_stor(ftp_ctx_t p, const char *fn, ftp_stor_cb cb, void *cookie)
{
    ftp_ctx *ctx;
    unsigned short newport;
    int r, s, a = 0;
    char buf[1024*16], *ptr;
    ftp_sock_t sock;

    memset(&sock, 0, sizeof(ftp_sock_t));
    sock.sockfd = SOCKET_ERROR;

    if( (ctx = (ftp_ctx *) p) == NULL || fn == NULL || ctx->tr_err ) {
	return OMOBUS_ERR;
    }
    if( (newport = ctx->epsv?ftp_epsv(p):ftp_pasv(p)) == 0 ) {
	logmsg_e(JPREFIX "%s@%s:%u unable to enter to the passive mode.", 
	    ctx->user, ctx->host, ctx->port);
	return OMOBUS_ERR;
    }
    if( ctx->ascii != 0 ) {
	if( ftp_cmd(ctx, ftp_msg("TYPE I")) == OMOBUS_ERR || ftp_code(ctx) != 200 ) {
	    logmsg_e(JPREFIX "%s@%s:%u unable to switch result type to the binnary mode.", 
		ctx->user, ctx->host, ctx->port);
	    return OMOBUS_ERR;
	}
	ctx->ascii = 0;
    }
    if( ftp_sendarg(ctx, ftp_msg("STOR %s"), fn) == OMOBUS_ERR ) {
	logmsg_e(JPREFIX "%s@%s:%u unable to send STOR request.", 
	    ctx->user, ctx->host, ctx->port);
	return OMOBUS_ERR;
    }
    if( (sock.sockfd = ftp_connect_passive(ctx, newport)) == SOCKET_ERROR ) {
	logmsg_e(JPREFIX "%s@%s:%u unable to create passive connection.", 
	    ctx->user, ctx->host, newport);
	return OMOBUS_ERR;
    }
    if( ftp_recv(ctx) == OMOBUS_ERR || ftp_code2(ctx, &a) != 150 ) {
	logmsg_e(JPREFIX "%s@%s:%u unable to get STOR response (data channel at %u port).", 
	    ctx->user, ctx->host, ctx->port, newport);
	ftp_disconnect_passive(ctx->log, &sock);
	return OMOBUS_ERR;
    }
    if( ctx->pdc ) {
	if( (sock.tlsses = tls_new(ctx->tls_config)) == NULL || 
	    tls_connect_reuse_session(sock.tlsses, sock.sockfd, ctx->host, ctx->sock.tlsses) != OMOBUS_OK ) 
	{
	    ftp_disconnect_passive(ctx->log, &sock);
	    ctx->tr_err = 1;
	    return OMOBUS_ERR;
	}
#ifdef FTP_TRACE
	if( ctx->log != NULL ) {
	    fprintf(ctx->log, "*: protected data channel %s with %s, %u secret bits cipher\n",
		tls_protocol(ctx->sock.tlsses), tls_ciphername(ctx->sock.tlsses), tls_cipherbits(ctx->sock.tlsses));
	}
#endif //FTP_TRACE
    }

    memset(buf, 0, sizeof(buf));
    while( cb != NULL && (r = cb(cookie, buf, sizeof(buf))) > 0 ) {
	ptr = buf;
	while( r > 0 && (s = sock_send(&sock, ptr, r)) > 0 ) {
	    r -= s; ptr += s;
	}
	memset(buf, 0, sizeof(buf));
	if( s < 0 || r != 0 ) {
	    logmsg_e(JPREFIX "%s:%u unable to send %s file to the server.", 
		ctx->host, newport, fn);
	    ftp_disconnect_passive(ctx->log, &sock);
	    return OMOBUS_ERR;
	}
    }
    ftp_disconnect_passive(ctx->log, &sock);

    if( a == 0 ) {
	if( ftp_recv(ctx) == OMOBUS_OK ) {
	    a = ftp_code(ctx);
	}
    }
    if( a != 226 ) {
	logmsg_e(JPREFIX "%s@%s:%u invalid STOR response (after sending data).", 
	    ctx->user, ctx->host, ctx->port);
	return OMOBUS_ERR;
    }

    return OMOBUS_OK;
}

int ftp_stor_mem(ftp_ctx_t p, const char *fn, const char *buf, int size)
{
    ftp_ctx *ctx;
    unsigned short newport;
    int r, s, a = 0, chunk = 1024*16, z, x = size;
    const char *ptr, *ref = buf;
    ftp_sock_t sock;

    memset(&sock, 0, sizeof(ftp_sock_t));
    sock.sockfd = SOCKET_ERROR;

    if( (ctx = (ftp_ctx *) p) == NULL || fn == NULL || ctx->tr_err ) {
	return OMOBUS_ERR;
    }
    if( (newport = ctx->epsv?ftp_epsv(p):ftp_pasv(p)) == 0 ) {
	logmsg_e(JPREFIX "%s@%s:%u unable to enter to the passive mode.", 
	    ctx->user, ctx->host, ctx->port);
	return OMOBUS_ERR;
    }
    if( ctx->ascii != 0 ) {
	if( ftp_cmd(ctx, ftp_msg("TYPE I")) == OMOBUS_ERR || ftp_code(ctx) != 200 ) {
	    logmsg_e(JPREFIX "%s@%s:%u unable to switch result type to the binnary mode.", 
		ctx->user, ctx->host, ctx->port);
	    return OMOBUS_ERR;
	}
	ctx->ascii = 0;
    }
    if( ftp_sendarg(ctx, ftp_msg("STOR %s"), fn) == OMOBUS_ERR ) {
	logmsg_e(JPREFIX "%s@%s:%u unable to send STOR request.", 
	    ctx->user, ctx->host, ctx->port);
	return OMOBUS_ERR;
    }
    if( (sock.sockfd = ftp_connect_passive(ctx, newport)) == SOCKET_ERROR ) {
	logmsg_e(JPREFIX "%s@%s:%u unable to create passive connection.", 
	    ctx->user, ctx->host, newport);
	return OMOBUS_ERR;
    }
    if( ftp_recv(ctx) == OMOBUS_ERR || ftp_code2(ctx, &a) != 150 ) {
	logmsg_e(JPREFIX "%s@%s:%u unable to get STOR response (data channel at %u port).", 
	    ctx->user, ctx->host, ctx->port, newport);
	ftp_disconnect_passive(ctx->log, &sock);
	return OMOBUS_ERR;
    }
    if( ctx->pdc ) {
	if( (sock.tlsses = tls_new(ctx->tls_config)) == NULL || 
	    tls_connect_reuse_session(sock.tlsses, sock.sockfd, ctx->host, ctx->sock.tlsses) != OMOBUS_OK ) 
	{
	    ftp_disconnect_passive(ctx->log, &sock);
	    ctx->tr_err = 1;
	    return OMOBUS_ERR;
	}
#ifdef FTP_TRACE
	if( ctx->log != NULL ) {
	    fprintf(ctx->log, "*: protected data channel %s with %s, %u secret bits cipher\n",
		tls_protocol(ctx->sock.tlsses), tls_ciphername(ctx->sock.tlsses), tls_cipherbits(ctx->sock.tlsses));
	}
#endif //FTP_TRACE
    }

    if( buf != NULL && size > 0 ) {
	while( x > 0 ) {
	    ptr = ref; z = r = MIN(chunk, x);
	    while( r > 0 && (s = sock_send(&sock, ptr, r)) > 0 ) {
		r -= s; ptr += s;
	    }
	    if( s < 0 || r != 0 ) {
		logmsg_e(JPREFIX "%s:%u unable to send %s file to the server.", 
		    ctx->host, newport, fn);
		ftp_disconnect_passive(ctx->log, &sock);
		return OMOBUS_ERR;
	    }
	    ref += z; x -= z;
	}
    }
    ftp_disconnect_passive(ctx->log, &sock);

    if( a == 0 ) {
	if( ftp_recv(ctx) == OMOBUS_OK ) {
	    a = ftp_code(ctx);
	}
    }
    if( a != 226 ) {
	logmsg_e(JPREFIX "%s@%s:%u invalid STOR response (after sending data).", 
	    ctx->user, ctx->host, ctx->port);
	return OMOBUS_ERR;
    }

    return OMOBUS_OK;
}

int ftp_stor_f(ftp_ctx_t p, const char *f_fn, const char *l_fn)
{
    FILE *f = NULL;
    int rc = OMOBUS_OK;

    if( l_fn == NULL ) {
	return OMOBUS_ERR;
    }
    if( f_fn == NULL ) {
	if( (f_fn = strrchr(l_fn, '/')) != NULL ) {
	    f_fn++;
	}
    }
    if( f_fn == NULL ) {
	return OMOBUS_ERR;
    }
    if( (f = fopen(l_fn, "rb")) == NULL ) {
	logmsg_e(JPREFIX "Unable to open '%s': %s", 
	    l_fn, strerror(errno));
	return OMOBUS_ERR;
    }

    rc = ftp_stor(p, f_fn, stor_cb, f);
    chk_fclose(f);

    return rc;
}

int ftp_stor_safe(ftp_ctx_t p, const char *fn, ftp_stor_cb cb, void *cookie, int size)
{
    ftp_ctx *ctx = NULL;
    char *t_fn = NULL;
    int rc = OMOBUS_ERR, x = OMOBUS_ERR;

    if( (ctx = (ftp_ctx *) p) == NULL || fn == NULL || size < 0 || ctx->tr_err ) {
	return rc;
    }
    if( asprintf(&t_fn, "%s.t", fn) == -1 || t_fn == NULL ) {
	allocate_memory_error(strerror(errno));
	return rc;
    }
    if( ftp_stor(p, t_fn, cb, cookie) == OMOBUS_ERR ) {
	logmsg_e(JPREFIX "Unable to store file '%s'.", 
	    t_fn);
    } else if( (x = ftp_size(p, t_fn)) < 0 ) {
	logmsg_e(JPREFIX "Unable to get stored file size. Original: %d bytes. File: %s",
	    size, t_fn);
    } else if( size != x ) {
	logmsg_e(JPREFIX "Ugly stored file size. Original: %d bytes. Server: %d bytes. File: %s", 
	    size, x, t_fn);
    } else if( ftp_rename(p, t_fn, fn) == OMOBUS_ERR ) {
	logmsg_e(JPREFIX "Unable to rename file: %s %s.", 
	    t_fn, fn);
    } else {
	rc = OMOBUS_OK;
    }

    chk_free(t_fn);

    return rc;
}

int ftp_stor_f_safe(ftp_ctx_t p, const char *f_fn, const char *l_fn)
{
    FILE *f = NULL;
    int rc = OMOBUS_ERR;
    struct stat st;

    if( l_fn == NULL ) {
	return rc;
    }
    if( f_fn == NULL ) {
	if( (f_fn = strrchr(l_fn, '/')) != NULL ) {
	    f_fn++;
	}
    }
    if( f_fn == NULL ) {
	return rc;
    }
    if( (f = fopen(l_fn, "rb")) == NULL ) {
	logmsg_e(JPREFIX "Unable to open '%s': %s", 
	    l_fn, strerror(errno));
	return rc;
    }

    memset(&st, 0, sizeof(st));
    if( stat(l_fn, &st) == -1 ) {
	logmsg_e(JPREFIX "Unable to get file size '%s': %s", 
	    l_fn, strerror(errno));
    } else {
	rc = ftp_stor_safe(p, f_fn, stor_cb, f, (int) st.st_size);
    }
    chk_fclose(f);

    return rc;
}

int ftp_stor_mem_safe(ftp_ctx_t p, const char *fn, const char *buf, int size)
{
    ftp_ctx *ctx = NULL;
    char *t_fn = NULL;
    int rc = OMOBUS_ERR, x = OMOBUS_ERR;

    if( (ctx = (ftp_ctx *) p) == NULL || fn == NULL || size < 0 || ctx->tr_err ) {
	return rc;
    }
    if( asprintf(&t_fn, "%s.t", fn) == -1 || t_fn == NULL ) {
	allocate_memory_error(strerror(errno));
	return rc;
    }
    if( ftp_stor_mem(p, t_fn, buf, size) == OMOBUS_ERR ) {
	logmsg_e(JPREFIX "Unable to store file '%s'.", 
	    t_fn);
    } else if( (x = ftp_size(p, t_fn)) < 0 ) {
	logmsg_e(JPREFIX "Unable to get stored file size. Original: %d bytes. File: %s",
	    size, t_fn);
    } else if( size != x ) {
	logmsg_e(JPREFIX "Ugly stored file size. Original: %d bytes. Server: %d bytes. File: %s", 
	    size, x, t_fn);
    } else if( ftp_rename(p, t_fn, fn) == OMOBUS_ERR ) {
	logmsg_e(JPREFIX "Unable to rename file: %s %s.", 
	    t_fn, fn);
    } else {
	rc = OMOBUS_OK;
    }

    chk_free(t_fn);

    return rc;
}

int ftp_size(ftp_ctx_t p, const char *fn)
{
    ftp_ctx *ctx = NULL;
    int rc = OMOBUS_ERR;

    if( (ctx = (ftp_ctx *) p) == NULL || ctx->tr_err || fn == NULL ) {
	return rc;
    }
    if( ftp_cmd(ctx, ftp_msg("SIZE %s"), fn) == OMOBUS_ERR ) {
	logmsg_e(JPREFIX "%s@%s:%u unable to get file size %s.", 
	    ctx->user, ctx->host, ctx->port, fn);
    } else if( ftp_code(ctx) == 213 ) {
	rc = atoi(ftp_text(ctx));
    }

    return rc;
}

int ftp_rename(ftp_ctx_t p, const char *fn_from, const char *fn_to)
{
    ftp_ctx *ctx = NULL;
    int rc = OMOBUS_ERR;

    if( (ctx = (ftp_ctx *) p) == NULL || ctx->tr_err || fn_from == NULL || fn_to == NULL ) {
	return rc;
    }
    if( ftp_cmd(ctx, ftp_msg("RNFR %s"), fn_from) == OMOBUS_ERR || ftp_code(ctx) != 350 ) {
	logmsg_e(JPREFIX "%s@%s:%u unable rename file %s to %s (RNFR).", 
	    ctx->user, ctx->host, ctx->port, fn_from, fn_to);
    } else if( ftp_cmd(ctx, ftp_msg("RNTO %s"), fn_to) == OMOBUS_ERR || ftp_code(ctx) != 250 ) {
	logmsg_e(JPREFIX "%s@%s:%u unable rename file %s to %s (RNTO).", 
	    ctx->user, ctx->host, ctx->port, fn_from, fn_to);
    } else {
	rc = OMOBUS_OK;
    }

    return rc;
}

int ftp_authtls(ftp_ctx_t p, short noverifycert, short allowexpired, short noverifyname, const char *ca_file, const char *ciphers)
{
    ftp_ctx *ctx = NULL;

    if( (ctx = (ftp_ctx *) p) == NULL || ctx->sock.tlsses != NULL || ctx->tr_err ) {
	return OMOBUS_ERR;
    }
    if( ftp_cmd(ctx, ftp_msg("AUTH TLS")) == OMOBUS_ERR || ftp_code(ctx) != 234 ) {
	logmsg_e(JPREFIX "%s:%u server doesn't support explicit TLS session.", 
	    ctx->host, ctx->port);
	return OMOBUS_ERR;
    }
    if( (ctx->tls_config = tls_config_new()) == NULL || (ctx->sock.tlsses = tls_new(ctx->tls_config)) == NULL ) {
	tls_config_free(ctx->tls_config);
	ctx->tls_config = NULL;
	allocate_memory_error(strerror(errno));
	return OMOBUS_ERR;
    }
    if( noverifycert ) {
	tls_config_insecure_noverifycert(ctx->tls_config);
    }
    if( allowexpired ) {
	tls_config_insecure_allowexpired(ctx->tls_config);
    }
    if( noverifyname ) {
	tls_config_insecure_noverifyname(ctx->tls_config);
    }
    if( ca_file != NULL ) {
	tls_config_set_ca_file(ctx->tls_config, ca_file);
    }
    if( ciphers != NULL ) {
	tls_config_set_ciphers(ctx->tls_config, ciphers);
    }
//    if( protocols != NULL ) {
//	tls_config_set_protocols(ctx->tls_config, protocols);
//    }
    if( tls_connect(ctx->sock.tlsses, ctx->sock.sockfd, ctx->host) != OMOBUS_OK ) {
	logmsg_e(JPREFIX "%s:%u unable to start TLS session.", 
	    ctx->host, ctx->port);
	tls_free(ctx->sock.tlsses);
	ctx->sock.tlsses = NULL;
	return OMOBUS_ERR;
    }
#ifdef FTP_TRACE
    if( ctx->log != NULL ) {
	fprintf(ctx->log, "*: protected command channel with %s, %u secret bits cipher\n",
	    tls_ciphername(ctx->sock.tlsses), tls_cipherbits(ctx->sock.tlsses));
    }
#endif //FTP_TRACE

    return OMOBUS_OK;
}

int ftp_ccc(ftp_ctx_t p)
{
    ftp_ctx *ctx = NULL;
    int rc = OMOBUS_ERR;

    if( (ctx = (ftp_ctx *) p) == NULL || ctx->sock.tlsses == NULL || ctx->tr_err ) {
	return rc;
    }
    if( ftp_cmd(ctx, ftp_msg("CCC")) == OMOBUS_ERR || ftp_code(ctx) != 200 ) {
	logmsg_e(JPREFIX "%s@%s:%u unable to switch to Clear Command Channel.", 
	    ctx->user, ctx->host, ctx->port);
    } else {
	tls_close(ctx->sock.tlsses);
	rc = OMOBUS_OK;
#ifdef FTP_TRACE
	if( ctx->log != NULL ) {
	    fprintf(ctx->log, "*: unprotected command channel\n");
	}
#endif //FTP_TRACE
    }

    return rc;
}

int ftp_prot(ftp_ctx_t p)
{
    ftp_ctx *ctx = NULL;
    int rc = OMOBUS_ERR;

    if( (ctx = (ftp_ctx *) p) == NULL || ctx->tr_err ) {
	return rc;
    }
    if( ftp_cmd(ctx, ftp_msg("PBSZ 0")) == OMOBUS_ERR || ftp_code(ctx) != 200 ) {
	logmsg_e(JPREFIX "%s@%s:%u unable to set protection buffer size.", 
	    ctx->user, ctx->host, ctx->port);
    } else if( ftp_cmd(ctx, ftp_msg("PROT P")) == OMOBUS_ERR || ftp_code(ctx) != 200 ) {
	logmsg_e(JPREFIX "%s@%s:%u unable to define protection data channel.", 
	    ctx->user, ctx->host, ctx->port);
    } else {
	ctx->pdc = 1;
	rc = OMOBUS_OK;
#ifdef FTP_TRACE
	if( ctx->log != NULL ) {
	    fprintf(ctx->log, "*: protected data channel\n");
	}
#endif //FTP_TRACE
    }

    return rc;
}

int ftp_cdc(ftp_ctx_t p)
{
    ftp_ctx *ctx = NULL;
    int rc = OMOBUS_ERR;


    if( (ctx = (ftp_ctx *) p) == NULL || ctx->tr_err ) {
	return rc;
    }
    if( ftp_cmd(ctx, ftp_msg("PROT C")) == OMOBUS_ERR || ftp_code(ctx) != 200 ) {
	logmsg_e(JPREFIX "%s@%s:%u unable to define clear (unprotected) data channel.", 
	    ctx->user, ctx->host, ctx->port);
    } else {
	ctx->pdc = 0;
	rc = OMOBUS_OK;
#ifdef FTP_TRACE
	if( ctx->log != NULL ) {
	    fprintf(ctx->log, "*: unprotected data channel\n");
	}
#endif //FTP_TRACE
    }

    return rc;
}

/* utility functions */

int ftp_lockdir(ftp_ctx_t p)
{
    return ftp_dele(p, OMOBUS_FF_UNLOCKED);
}

int ftp_unlockdir(ftp_ctx_t p)
{
    return ftp_stor(p, OMOBUS_FF_UNLOCKED, NULL, NULL);
}
