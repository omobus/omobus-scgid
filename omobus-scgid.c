/* -*- C -*- */
/* Copyright (c) 2006 - 2022 omobus-scgid authors, see the included COPYRIGHT file. */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/signalfd.h>
#include <sys/wait.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <inttypes.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <semaphore.h>

#include "omobus-scgid.h"
#include "setproctitle.h"
#include "make_abstimeout.h"
#include "package_params.h"

#include "lua.h"
#include "luaaux.h"

#define JPREFIX		OMOBUS_JPREFIX

typedef struct _scgi_param_t {
    const char *name, *value;
    void *next;
} scgi_param_t;

typedef struct _scgi_request_t {
    size_t header_length, before_header_length, after_header_length;
    size_t content_length;
    size_t bufsize, params_count;
    char *buf;
    const char *content;
    scgi_param_t *params;
} scgi_request_t;


LUAMOD_API int luaopen_base(lua_State *L);
LUAMOD_API int luaopen_coroutine(lua_State *L);
LUAMOD_API int luaopen_table(lua_State *L);
LUAMOD_API int luaopen_os(lua_State *L);
LUAMOD_API int luaopen_string(lua_State *L);
LUAMOD_API int luaopen_utf8(lua_State *L);
LUAMOD_API int luaopen_math(lua_State *L);
LUAMOD_API int luaopen_debug(lua_State *L);
LUAMOD_API int luaopen_package(lua_State *L);

LUAMOD_API int luaopen_base64(lua_State *L);
LUAMOD_API int luaopen_hash(lua_State *L);
LUAMOD_API int luaopen_ftp(lua_State *L);
LUAMOD_API int luaopen_iconv(lua_State *L);
LUAMOD_API int luaopen_zlib(lua_State *L);
LUAMOD_API int luaopen_bzlib(lua_State *L);
LUAMOD_API int luaopen_json(lua_State *L);
LUAMOD_API int luaopen_json_safe(lua_State *L);
LUAMOD_API int luaopen_sock(lua_State *L);

static const luaL_Reg loadedlibs[] = {
    { "_G", luaopen_base },
    { "package", luaopen_package },
    { "coroutine", luaopen_coroutine },
    { "table", luaopen_table },
    { "os", luaopen_os },
    { "string", luaopen_string },
    { "utf8", luaopen_utf8 },
    { "math", luaopen_math },
    { "debug", luaopen_debug },
    { "base64", luaopen_base64 },
    { "hash", luaopen_hash },
    { "json", luaopen_json },
    { "json_safe", luaopen_json_safe },
    { "ftp", luaopen_ftp },
    { "sock", luaopen_sock },
    { NULL, NULL }
};

static const luaL_Reg preloadedlibs[] = {
    { "iconv", luaopen_iconv },
    { "zlib", luaopen_zlib },
    { "bzlib", luaopen_bzlib },
    { NULL, NULL }
};

static short _gc_stop_flag = 0;
static sem_t *_gc_sem = NULL;

static
void print_usage() {
    fprintf(stdout,
	PACKAGE_NAME " " PACKAGE_VERSION "\n"
	PACKAGE_COPYRIGHT "\n"
	PACKAGE_AUTHOR "\n\n"
	"Usage: " PACKAGE_NAME " [OPTIONS] -s unixsock script\n"
	"  -s unixsock - Unix socket name;\n"
	"  script      - Lua script;\n\n"
	"OPTIONS:\n"
	"  -c jaildir  - chroot directory for request handlers;\n"
	"  -d          - debug mode (without daemonize; redirect logs to the stdout);\n"
	"  -x          - systemd service (without daemonize);\n"
	"  -g group    - group (id or name) to run as;\n"
	"  -n evname   - GC semaphore name;\n"
	"  -p pidfile  - pid-file name;\n"
	"  -t timeout  - GC execute timeout in minutes;\n"
	"  -u user     - user (id or name) to run as;\n"
	"  -V          - print version and compile options.\n\n"
	"Report bugs to <" PACKAGE_BUGREPORT ">.\n"
    );
}

static 
void print_version() {
    fprintf(stdout,
	PACKAGE_NAME " " PACKAGE_VERSION "\n"
	PACKAGE_COPYRIGHT "\n"
	PACKAGE_AUTHOR "\n\n"
	"Execute environment:\n"
	"  script engine      - " LUA_RELEASE "\n"
	"  server libraties   - " LIB_PATH "\n"
	"  Lua libraries      - " LIBEXEC_PATH "\n"
	"  Lua bindings       - " LIBEXEC_PATH "\n"
    );
}

static
short strempty(const char *s)
{
    return (s == NULL || *s == '\0') ? 1 : 0;
}

static
char prioritytext(int priority)
{
    switch( priority ) {
    case LOG_CRIT:
    case LOG_ERR:	return 'E';
    case LOG_WARNING:	return 'W';
    case LOG_NOTICE:	return 'N';
    case LOG_INFO:	return 'I';
    case LOG_DEBUG:	return 'D';
    };
    return '?';
}

static
void vlogmsg(int priority, const char *fmt, va_list ap)
{
    char *format;
    if( stdout == NULL || stderr == NULL ) {
	vsyslog(priority, fmt, ap);
    } else {
	format = NULL;
	if( asprintf(&format, "%c/%s\n", prioritytext(priority), fmt) != -1 && format != NULL ) {
	    if( vfprintf(priority == LOG_ERR ? stderr : stdout, format, ap) > 0 ) {
		fflush(priority == LOG_ERR ? stderr : stdout);
	    }
	    free(format);
	}
    }
}

#define logmsg_x(priority)	va_list ap;va_start(ap, fmt);vlogmsg(priority, fmt, ap);va_end(ap);

void logmsg_e(const char *fmt, ...) {
    logmsg_x(LOG_ERR);
}

void logmsg_w(const char *fmt, ...) {
    logmsg_x(LOG_WARNING);
}

static
void logmsg_i(const char *fmt, ...) {
    logmsg_x(LOG_INFO);
}

static
void logmsg_d(const char *fmt, ...) {
#ifdef _DEBUG
    logmsg_x(LOG_DEBUG);
#endif //_DEBUG
}

static
int setident(uid_t uid, gid_t gid)
{
    int rc = 0;

    if( gid > 0 ) {
	if( setgid(gid) || setegid(gid) ) {
	    rc = -1;
	}
    }
    if( uid > 0 ) {
	if( setuid(uid) || seteuid(uid) ) {
	    rc = -1;
	}
    }

    return rc;
}

static
int strcheck(const char *ptr, size_t size)
{
    size_t i;
    for( i = 0; i < size; ++i, ++ptr ) {
	if( *ptr == '\0' ) {
	    return 0;
	}
    }
    return -1;
}

static
int sendbuf(int sockfd, const char *buf, size_t size)
{
    ssize_t s;
    char *ptr;

    if( (ptr = (char *)buf) == NULL || size == 0 ) {
	errno = EINVAL;
	return -1;
    }

    while( size > 0 && (s = send(sockfd, ptr, size, 0)) != -1 && s < size ) {
	ptr += s; size -= s;
    }

    return s == -1 ? -1 : 0;
}

static
int writebuf(FILE *f, const char *buf, size_t size)
{
    size_t s;
    char *ptr;

    if( (ptr = (char *)buf) == NULL || size == 0 ) {
	errno = EINVAL;
	return -1;
    }

    while( size > 0 && (s = fwrite(ptr, 1, size, f)) > 0 && s < size ) {
	ptr += s; size -= s;
    }

    return ferror(f) ? -1 : 0;
}

static
void http_server_error(int sockfd)
{
    static const char response_header[] = "Status: 500\r\n\r\n";
    sendbuf(sockfd, response_header, strlen(response_header));
}

static
int signalfd_create()
{
    sigset_t sigmask;
    int sigfd;

    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGINT);
    sigaddset(&sigmask, SIGQUIT);
    sigaddset(&sigmask, SIGTERM);
    sigaddset(&sigmask, SIGUSR1);
/* POSIX.1-2001: automaticaly collects zombie process
    sigaddset(&sigmask, SIGCHLD);
*/
    /* http://www.microhowto.info/howto/reap_zombie_processes_using_a_sigchld_handler.html */
    if( signal(SIGCHLD, SIG_IGN) == SIG_ERR ) {
	logmsg_e(JPREFIX "unable to set SIG_IGN for SIGCHLD signal: %s", strerror(errno));
	return -1;
    }
    if( sigprocmask(SIG_BLOCK, &sigmask, NULL) == -1 ) {
	logmsg_e(JPREFIX "unable to drop signal handlers: %s", strerror(errno));
	return -1;
    }
    if( (sigfd = signalfd(-1, &sigmask, SFD_NONBLOCK)) == -1 ) {
	logmsg_e(JPREFIX "unable to set signal handler: %s", strerror(errno));
	return -1;
    }

    return sigfd;
}

static
void signalfd_close(int fd)
{
    if( fd != -1 ) {
	close(fd);
    }
}

static
int socketfd_create(const char *unixsock)
{
    int sockfd;
    struct sockaddr_un addr;

    if( (sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1 ) {
	logmsg_e(JPREFIX "unable to create socket: %s", strerror(errno));
	return -1;
    }

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, unixsock, sizeof(addr.sun_path) - 1);

    if( bind(sockfd, (struct sockaddr *) &addr, sizeof(struct sockaddr_un)) == -1) {
	close(sockfd);
	logmsg_e(JPREFIX "unable to bind socket: %s", strerror(errno));
	return -1;
    }
    if( listen(sockfd, 64/*backlog*/) == -1 ) {
	close(sockfd);
	logmsg_e(JPREFIX "unable to listen socket: %s", strerror(errno));
	return -1;
    }

    fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) | O_NONBLOCK);
    chmod(unixsock, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);

    return sockfd;
}

static
void socketfd_close(int sockfd)
{
    if( sockfd != -1 ) {
	shutdown(sockfd, SHUT_RDWR);
	close(sockfd);
    }
}

static
scgi_param_t *scgi_param_create(const char *name, const char *value)
{
    scgi_param_t *p;

    if( (p = (scgi_param_t *) malloc(sizeof(scgi_param_t))) != NULL ) {
	memset(p, 0, sizeof(scgi_param_t));
	p->name = name;
	p->value = value;
    }

    return p;
}

static
void scgi_param_cleanup(scgi_param_t *param)
{
    scgi_param_t *next;
    while( param != NULL ) {
	next = param->next;
	free(param);
	param = next;
    }
}

static
int scgi_content_length(const char *buf, size_t size, size_t *content_length)
{
    char *endptr = NULL;
    /* "CONTENT_LENGTH" <00> "0" <00> */
    /*        14          1  >=1  1   */
    if( size < 17 || strncmp(buf, "CONTENT_LENGTH", 14) || *(buf += 14) != '\0' || strcheck(++buf, size) == -1 ) {
	return -1;
    }
    *content_length = strtoul(buf, &endptr, 0);
    return *endptr == '\0' ? 0 : -1;
}

static
scgi_param_t *scgi_parse_params(const char *buf, size_t header_length, size_t *params_count)
{
    scgi_param_t *param, *cur, *rc;
    size_t i, count;
    char *t, *ptr;

    ptr = (char *) buf;
    rc = cur = param = NULL;
    t = ptr; 
    i = count = 0;

    for( ; i < header_length; ++i, ++t ) {
	if( *t == '\0' ) {
	    if( param == NULL ) {
		if( (param = scgi_param_create(ptr, NULL)) == NULL ) {
		    allocate_memory_error(strerror(errno));
		    scgi_param_cleanup(rc);
		    return NULL;
		}
	    } else {
		param->value = ptr;
		if( rc == NULL ) {
		     rc = param;
		} else if( rc->next == NULL ) {
		    rc->next = param;
		} else if( cur != NULL ) {
		    cur->next = param;
		}
		cur = param;
		param = NULL;
		count++;
	    }
	    ptr = t + 1;
	}
    }

    if( param != NULL ) {
	free(param);
	scgi_param_cleanup(rc);
	rc = NULL;
    }
    if( rc != NULL ) {
	(*params_count) = count;
    }

    return rc;
}

static
void scgi_cleanup(scgi_request_t *scgi)
{
    if( scgi != NULL ) {
	chk_free(scgi->buf);
	scgi_param_cleanup(scgi->params);
	free(scgi);
    }
}

static
scgi_request_t *scgi_create()
{
    static const size_t minbufsize = 4096;
    scgi_request_t *scgi;

    if( (scgi = (scgi_request_t *) malloc(sizeof(scgi_request_t))) == NULL ) {
	allocate_memory_error(strerror(errno));
	return NULL;
    }

    memset(scgi, 0, sizeof(scgi_request_t));

    if( (scgi->buf = (char *) malloc(minbufsize)) == NULL ) {
	allocate_memory_error(strerror(errno));
	scgi_cleanup(scgi);
	return NULL;
    }

    memset(scgi->buf, 0, minbufsize);
    scgi->bufsize = minbufsize;

    return scgi;
}

static
int scgi_read(scgi_request_t *scgi, int sockfd)
{
    ssize_t r, x, bufsize;
    char *ptr, *tmp;

    if( scgi == NULL || scgi->buf == NULL ) {
	errno = EINVAL;
	return -1;
    }
    if( (r = recv(sockfd, scgi->buf, scgi->bufsize, 0)) == -1 ) {
	logmsg_w(JPREFIX "recv() failed: %s", strerror(errno));
	return -1;
    }

    scgi->bufsize = (size_t) r;
    ptr = NULL;

/**
 ** SCGI request:
 ** "56:"
 **   "CONTENT_LENGTH" <00> "5" <00>
 **   ...
 ** ","
 ** "Hello"
 **/

    if( r == 0 || !isdigit(*(scgi->buf)) || (scgi->header_length = strtoul(scgi->buf, &ptr, 0)) == 0 || *ptr != ':' ) {
	logmsg_w(JPREFIX "invalid SCGI request: first parameter should be a decimal value");
	errno = EINVAL;
	return -1;
    }

    ptr++;
    scgi->before_header_length = ptr - scgi->buf;
    scgi->after_header_length = 1;

    if( scgi_content_length(ptr, scgi->bufsize - scgi->before_header_length, &scgi->content_length) == -1 ) {
	logmsg_w(JPREFIX "invalid SCGI request: the first parameter should be 'CONTENT_LENGTH'");
	return -1;
    }
    if( (bufsize = scgi->before_header_length + scgi->header_length + scgi->after_header_length + scgi->content_length) > scgi->bufsize ) {
	if( (scgi->buf = (char *) realloc(scgi->buf, bufsize)) == NULL ) {
	    allocate_memory_error(strerror(errno));
	    return -1;
	}
	x = bufsize - scgi->bufsize;
	tmp = scgi->buf + scgi->bufsize;
	ptr = scgi->buf + scgi->before_header_length;
	scgi->bufsize = bufsize;
	memset(tmp, 0, x);
	while( x > 0 && (r = recv(sockfd, tmp, x, 0)) != -1 ) {
	    x -= r; tmp += r;
	}
	if( r == -1 || x != 0 ) {
	    logmsg_w(JPREFIX "recv() failed: %s", strerror(errno));
	    return -1;
	}
    }
    if( (scgi->params = scgi_parse_params(ptr, scgi->header_length, &scgi->params_count)) == NULL ) {
	logmsg_w(JPREFIX "invalid SCGI request: ugly formated header");
	return -1;
    }
    if( scgi->content_length > 0 ) {
	scgi->content = ptr + scgi->header_length + scgi->after_header_length;
    }

    return 0;
}

static
const char *scgi_find(scgi_request_t *scgi, const char *key)
{
    scgi_param_t *p;

    for( p = scgi->params; p != NULL; p = p->next ) {
	if( strcmp(key, p->name) == 0 ) {
	    return p->value;
	}
    }

    return NULL;
}

static
void scgi_echo(FILE *f, scgi_request_t *scgi)
{
    static const char response_header[] = "Status: 200 OK\r\nContent-Type: text/plain\r\n\r\n";
    scgi_param_t *p;

    fputs(response_header, f);
    if( scgi != NULL ) {
	for( p = scgi->params; p != NULL; p = p->next ) {
	    fprintf(f, "%s=%s\n", p->name, p->value);
	}
	if( scgi->content != NULL ) {
	    writebuf(f, scgi->content, scgi->content_length);
	}
    }
}

static
int lua_responseTruncate(lua_State *ctx)
{
    FILE *f;
    int rc = 0;

    if( lua_isnoneornil(ctx, 1) || !lua_islightuserdata(ctx, 1) ) {
	rc = luaL_argerror(ctx, 1, lua_pushfstring(ctx, "userdata expected, got %s", lua_typename(ctx, 1)));
    } else if( (f = (FILE *) lua_topointer(ctx, 1)) == NULL ) {
	rc = luaL_argerror(ctx, 1, lua_pushstring(ctx, "invalid stream pointer"));
    } else {
	rewind(f);
    }

    return rc;
}

static
int lua_responseWrite(lua_State *ctx)
{
    const char *s;
    size_t l;
    FILE *f;
    int rc = 0;

    if( lua_isnoneornil(ctx, 1) || !lua_islightuserdata(ctx, 1) ) {
	rc = luaL_argerror(ctx, 1, lua_pushfstring(ctx, "userdata expected, got %s", lua_typename(ctx, 1)));
    } else if( (f = (FILE *) lua_topointer(ctx, 1)) == NULL ) {
	rc = luaL_argerror(ctx, 1, lua_pushstring(ctx, "invalid stream pointer"));
    } else if( (s = luaL_checklstring(ctx, 2, &l)) != NULL && l > 0 ) {
	if( writebuf(f, s, l) == -1 ) {
	    rc = luaL_error(ctx, "unable to write data to the stream");
        }
    }

    return rc;
}

static
int lua_setprocname(lua_State *ctx)
{
    const char *s;
    size_t l;

    if( (s = luaL_checklstring(ctx, 1, &l)) != NULL && l > 0 ) {
	setproctitle(PACKAGE_NAME ": %s", s);
    }
    return 0;
}

static
int lua_logerror(lua_State *ctx) {
    logmsg_e("%s", luaL_checkstring(ctx, 1));
    return 0;
}

static
int lua_logwarn(lua_State *ctx) {
    logmsg_w("%s", luaL_checkstring(ctx, 1));
    return 0;
}

static
int lua_logmsg(lua_State *ctx) {
    logmsg_i("%s", luaL_checkstring(ctx, 1));
    return 0;
}

static
int lua_logdebug(lua_State *ctx) {
    logmsg_d("%s", luaL_checkstring(ctx, 1));
    return 0;
}

static
void lua_setpath(lua_State *ctx, const char *name, const char *str)
{
    char *path = NULL;

    lua_getglobal(ctx, "package" );
    lua_getfield(ctx, -1, name );
    if( asprintf(&path, "%s;%s", str, lua_tostring(ctx, -1)) == -1 || path == NULL ) {
	allocate_memory_error(strerror(errno));
    } else {
	lua_pop(ctx, 1);
	lua_pushstring(ctx, path);
	lua_setfield(ctx, -2, name);
	lua_pop(ctx, 1);
	free(path);
    }
}

static
int lua_onpanic(lua_State *ctx)
{
    logmsg_e(JPREFIX "unprotected error in call to Lua API: %s", lua_tostring(ctx, -1));
    return 0;
}

static
lua_State *luaengine_create(const char *filename, const char *homedir)
{
    static const char *websvc_main = "websvc_main";
    lua_State *ctx;
    const luaL_Reg *lib;
    char path[2048];

    if( (ctx = luaL_newstate()) == NULL ) {
	logmsg_e(JPREFIX "unable to create lua context.");
	return NULL;
    }

    lua_atpanic(ctx, lua_onpanic);
    /* Register build-in libraries */
    for( lib = loadedlibs; lib->func; lib++ ) {
	luaL_requiref(ctx, lib->name, lib->func, 1);
	lua_pop(ctx, 1);  /* remove lib */
    }
    luaL_getsubtable(ctx, LUA_REGISTRYINDEX, "_PRELOAD");
    for( lib = preloadedlibs; lib->func; lib++ ) {
	lua_pushcfunction(ctx, lib->func);
	lua_setfield(ctx, -2, lib->name);
    }
    lua_pop(ctx, 1);  /* remove _PRELOAD table */
    /* Register build-in functions */
    lua_register(ctx, "responseWrite", lua_responseWrite);
    lua_register(ctx, "responseTruncate", lua_responseTruncate);
    lua_register(ctx, "setprocname", lua_setprocname);
    lua_register(ctx, "log_msg", lua_logmsg);
    lua_register(ctx, "log_warn", lua_logwarn);
    lua_register(ctx, "log_error", lua_logerror);
    lua_register(ctx, "print", lua_logdebug);

    snprintf(path, charbufsize(path), "%s/?.lua;" LIBEXEC_PATH "/?.lua", homedir);
    lua_setpath(ctx, "path", path);
    snprintf(path, charbufsize(path), "%s/?.so;" LIBEXEC_PATH "/?.so", homedir);
    lua_setpath(ctx, "cpath", path);

    if( luaL_loadfile(ctx, filename) != LUA_OK ) {
	logmsg_e(JPREFIX "corrupted script /load/: %s.", lua_isnil(ctx, -1) ? filename : lua_tostring(ctx, -1));
	lua_close(ctx);
	return NULL;
    }

    if( lua_pcall(ctx, 0, 0, 0) != LUA_OK ) {
	logmsg_e(JPREFIX "corrupted script /pcall/: %s.", lua_isnil(ctx, -1) ? filename : lua_tostring(ctx, -1));
	lua_close(ctx);
	return NULL;
    }

    lua_getglobal(ctx, websvc_main);
    if( lua_isnoneornil(ctx, -1) || !lua_isfunction(ctx, -1) ) {
	logmsg_e(JPREFIX "entry point %s() does not exist", websvc_main);
	lua_close(ctx);
	return NULL;
    }

    if( lua_pcall(ctx, 0, 1, 0) != LUA_OK ) {
	logmsg_e(JPREFIX "%s execution error: %s", websvc_main, lua_isnil(ctx, -1) ? "" : lua_tostring(ctx, -1));
	lua_close(ctx);
	return NULL;
    }
    if( lua_isnoneornil(ctx, -1) ) {
	logmsg_e(JPREFIX "%s execution aborded", websvc_main);
	lua_close(ctx);
	return NULL;
    }
    if( !lua_istable(ctx, -1) ) {
	logmsg_e(JPREFIX "%s should return function table", websvc_main);
	lua_close(ctx);
	return NULL;
    }

    return ctx;
}

static
void luaengine_destroy(lua_State *ctx)
{
    if( ctx != NULL ) {
	lua_close(ctx);
    }
}

static
int luaengine_execute_rh(lua_State *ctx, scgi_request_t *scgi, FILE *f)
{
    scgi_param_t *p;

    if( ctx == NULL ) {
	return -1;
    }

    lua_getfield(ctx, -1, "request_handler");

    if( lua_isnoneornil(ctx, -1) || !lua_isfunction(ctx, -1) ) {
	logmsg_e(JPREFIX "request handler entry point function does not exist");
	return -1;
    }

    lua_newtable(ctx);
    for( p = scgi->params; p != NULL; p = p->next ) {
	lua_pushstring(ctx, p->name);
	lua_pushstring(ctx, p->value);
	lua_settable(ctx, -3);
    }
    lua_pushinteger(ctx, scgi->content_length);
    if( scgi->content_length == 0 || scgi->content == NULL ) {
	lua_pushnil(ctx);
    } else {
	lua_pushlstring(ctx, scgi->content, scgi->content_length);
    }
    lua_pushlightuserdata(ctx, f);

    if( lua_pcall(ctx, 4, 1, 0) != LUA_OK ) {
	logmsg_e(JPREFIX "request handler execution error: %s", lua_isnil(ctx, -1) ? "" : lua_tostring(ctx, -1));
	return -1;
    }

    return lua_isnoneornil(ctx, -1) ? 0 : lua_tonumber(ctx, -1);
}

static
int luaengine_execute_gc(lua_State *ctx)
{
    if( ctx == NULL ) {
	return -1;
    }

    lua_getfield(ctx, -1, "gc");

    if( lua_isnoneornil(ctx, -1) || !lua_isfunction(ctx, -1) ) {
	logmsg_e(JPREFIX "GC entry point function does not exist");
	return -1;
    }
    if( lua_pcall(ctx, 0, 0, 0) != LUA_OK ) {
	logmsg_e(JPREFIX "GC execution error: %s", lua_isnil(ctx, -1) ? "" : lua_tostring(ctx, -1));
	return -1;
    }

    return 0;
}

static 
void gc_stop_handler(int sig)
{
    if( _gc_sem != NULL ) {
	_gc_stop_flag = 1;
	sem_post(_gc_sem);
    }
}

static
int gc_loop(lua_State *ctx, uid_t uid, gid_t gid, const char *jaildir, const char *gc_evname, unsigned int gc_timeout)
{
    int rc;
    struct sigaction sa;
    struct timespec ts;
    uint32_t timeout = -1;
    char semname[255];

    rc = 0;
    sa.sa_flags = 0;
    sa.sa_handler = gc_stop_handler;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGINT);
    sigaddset(&sa.sa_mask, SIGQUIT);
    sigaddset(&sa.sa_mask, SIGTERM);
    sigaddset(&sa.sa_mask, SIGUSR1);
    memset(&ts, 0, sizeof(ts));
    timeout = gc_timeout == 0 ? -1 : gc_timeout*60*1000;

    if( !strempty(gc_evname) ) {
	snprintf(semname, charbufsize(semname), OMOBUS_IPCSEM_NAME, gc_evname);
	if( (_gc_sem = sem_open(semname, O_CREAT, S_IRUSR|S_IWUSR, 0)) == SEM_FAILED ) {
	    logmsg_w(JPREFIX "(GC) sem_open(%s): %s", semname, strerror(errno));
	    _exit(-1);
	}
    } else {
	if( (_gc_sem = (sem_t *) alloca(sizeof(sem_t))) == NULL || (rc = sem_init(_gc_sem, 0, 0)) == -1 ) {
	    logmsg_w(JPREFIX "(GC) sem_init(): %s", strerror(errno));
	    _exit(-1);
	}
    }
    if( jaildir != NULL && *jaildir != '\0' ) {
	if( chroot(jaildir) == -1 || chdir("/") == -1 ) {
	    logmsg_w(JPREFIX "(GC) chroot(%s) faild: %s", jaildir, strerror(errno));
	    _exit(-1);
	}
    }
    if( setident(uid, gid) == -1 ) {
	logmsg_w(JPREFIX "(GC) unable to change user or group: %s", strerror(errno));
	_exit(-1);
    }

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);

    logmsg_i("GC semaphore=%s, timeout=%dm started.", strempty(gc_evname) ? "(internal)" : gc_evname, gc_timeout);
    while( _gc_stop_flag == 0 && rc == 0 ) {
	make_abstimeout(0, &ts);
	// Drop semaphore count to nil.
	while( sem_timedwait(_gc_sem, &ts) == 0 )
	    ;
	// Waiting for external event.
	make_abstimeout(timeout, &ts);
	if( (rc = sem_timedwait(_gc_sem, &ts)) == 0 || errno == ETIMEDOUT ) {
	    if( _gc_stop_flag == 0 ) {
		logmsg_d(JPREFIX "(GC) garbage collection is launched.");
		rc = luaengine_execute_gc(ctx);
		logmsg_d(JPREFIX "(GC) garbage collection is %s.", rc >= 0 ? "accomplished" : "failed");
	    } else {
		rc = 0;
	    }
	} else if( errno == EINTR /*interrupted by a signal handler*/ ) {
	    rc = 0;
	} else {
	    logmsg_e(JPREFIX "(GC) sem_timedwait(): %s", strerror(errno));
	}
    }
    if( gc_evname != NULL && *gc_evname != '\0' ) {
	sem_close(_gc_sem);
	//sem_unlink(semname);
    } else {
	sem_destroy(_gc_sem);
    }
    _gc_sem = NULL;
    luaengine_destroy(ctx);

    return rc;
}

static
int child_loop(lua_State *ctx, int sockfd, uid_t uid, gid_t gid, const char *jaildir)
{
    scgi_request_t *scgi;
    FILE *f;
    const char *path_info;
    char *memptr;
    size_t memsize;
    int rc;

    if( jaildir != NULL && *jaildir != '\0' ) {
	if( chroot(jaildir) == -1 || chdir("/") == -1 ) {
	    logmsg_w(JPREFIX "chroot(%s) faild: %s", jaildir, strerror(errno));
	    http_server_error(sockfd);
	    return -1;
	}
    }
    if( setident(uid, gid) == -1 ) {
	logmsg_w(JPREFIX "unable to change user or group: %s", strerror(errno));
	http_server_error(sockfd);
	return -1;
    }
    if( (scgi = scgi_create()) == NULL ) {
	logmsg_w(JPREFIX "unable to create scgi parser");
	http_server_error(sockfd);
	return -1;
    }
    if( scgi_read(scgi, sockfd) == -1 ) {
	scgi_cleanup(scgi);
	logmsg_w(JPREFIX "unable to parse scgi request");
	http_server_error(sockfd);
	return -1;
    }

    rc = 0;
    memptr = NULL;
    memsize = 0;
    path_info = scgi_find(scgi, "PATH_INFO");

    if( (f = open_memstream(&memptr, &memsize)) == NULL ) {
	logmsg_w(JPREFIX "unable to open memory stream for the response data: %s", strerror(errno));
	http_server_error(sockfd);
	rc = -1;
    } else {
	/** internal request: begin **/
	if( path_info != NULL && strcmp(path_info, "/about:echo") == 0 ) {
	    scgi_echo(f, scgi);
	}
	/** internal request: end **/
	else {
	    rc = luaengine_execute_rh(ctx, scgi, f);
	    luaengine_destroy(ctx);
	}
	if( rc != -1 ) {
	    fflush(f);
	    if( sendbuf(sockfd, memptr, memsize) == -1 ) {
		logmsg_w(JPREFIX "unable to send (%d bytes) response data", memsize);
		rc = -1;
	    }
	} else {
	    http_server_error(sockfd);
	}

	fclose(f);
	chk_free(memptr)
	memsize = 0;;
    }

    scgi_cleanup(scgi);

    return rc;
}

static
int main_loop(const char *script, lua_State *ctx, const char *unixsock, uid_t uid, gid_t gid, const char *jaildir, int gc_pid)
{
    short stopflag;
    int sigfd, sockfd, clifd, rc, i, pid/*, status*/;
    struct pollfd fds[2];
    struct signalfd_siginfo fdsi;
    struct sockaddr_un cliaddr;
    struct timespec start, stop;
    socklen_t cliaddr_size;

    sigfd = sockfd = clifd = -1;
    stopflag = 0;
    rc = -1;
    memset(fds, 0, sizeof(fds));
    logmsg_i("%s %s unixsock=%s, script=%s starting up.", PACKAGE_NAME, PACKAGE_VERSION, unixsock, script);

    if( (sigfd = signalfd_create()) != -1 && (sockfd = socketfd_create(unixsock)) != -1 ) {
	fds[0].fd = sockfd;
	fds[0].events = POLLIN;
	fds[1].fd = sigfd;
	fds[1].events = POLLIN;

	logmsg_i("%s %s unixsock=%s, script=%s started.", PACKAGE_NAME, PACKAGE_VERSION, unixsock, script);
	while( stopflag == 0 && (rc = poll(fds, 2, -1)) >= 0 ) {
	    for( i = 0; i < 2; i++ ) {
		if(fds[i].revents == POLLIN ) {
		    if(fds[i].fd == sockfd ) {
			cliaddr_size = sizeof(struct sockaddr_un);
			while( stopflag == 0 && (clifd = accept(sockfd, (struct sockaddr *)&cliaddr, &cliaddr_size)) > 0 ) {
			    if( (pid = fork()) < 0 ) {
				logmsg_e(JPREFIX "unable to fork: %s", strerror(errno));
			    } else if( pid == 0 ) {
				pid = getpid();
				setproctitle(PACKAGE_NAME ": %s", "request handler");
				logmsg_d(JPREFIX "request handler process (pid=%d) has been started", pid);
				close(sockfd);
				close(sigfd);
				clock_gettime(CLOCK_REALTIME, &start);
				rc = child_loop(ctx, clifd, uid, gid, jaildir);
				clock_gettime(CLOCK_REALTIME, &stop);
				logmsg_i("request handler process (pid=%d) execution duration: %.03f sec.", 
				    pid, ((double)(stop.tv_sec - start.tv_sec)) + ((double)(stop.tv_nsec - start.tv_nsec))/1000000000);
				shutdown(clifd, SHUT_RDWR);
				close(clifd);
				logmsg_d(JPREFIX "request handler process (pid=%d) has been stopped", pid);
				_exit(rc);
			    } else {
				close(clifd);
			    }
			    cliaddr_size = sizeof(struct sockaddr_un);
			}
			if( clifd == -1 && !(errno == EAGAIN || errno == EWOULDBLOCK) ) {
			    logmsg_e(JPREFIX "unable to accept client connection: %s", strerror(errno));
			}
		    } else if(fds[i].fd == sigfd ) {
			while( stopflag == 0 && read(sigfd, &fdsi, sizeof(struct signalfd_siginfo)) == sizeof(struct signalfd_siginfo) ) {
			    switch(fdsi.ssi_signo) {
			    case SIGINT:
			    case SIGQUIT:
			    case SIGTERM:
			    case SIGUSR1:
				stopflag = 1;
				break;
/* POSIX.1-2001: automaticaly collects zombie process
			    case SIGCHLD:
				status = 0;
				//logmsg_d(JPREFIX "SIGCHLD (pid=%d)", fdsi.ssi_pid);
				if( waitpid(fdsi.ssi_pid, &status, WNOHANG) < 0 ) {
				    logmsg_w(JPREFIX "unable to waitpid(pid=%d): %s", fdsi.ssi_pid, strerror(errno));
				} else if( WIFEXITED(status) ) {
				    logmsg(WCOREDUMP(status) || WEXITSTATUS(status) != 0 ? LOG_WARNING : LOG_DEBUG, 
					JPREFIX "%s process (pid=%d) exited%s with status %d",
					fdsi.ssi_pid == gc_pid ? "GC" : "request handler",
					fdsi.ssi_pid, 
					WCOREDUMP(status) ? " and dumped core" : "", 
					WEXITSTATUS(status));
				} else if( WIFSTOPPED(status) ) {
				    logmsg_w(JPREFIX "%s process (pid=%d) stopped by signal %d",
					fdsi.ssi_pid == gc_pid ? "GC" : "request handler",
					fdsi.ssi_pid, WSTOPSIG(status));
				} else if( WIFSIGNALED(status) ) {
				    logmsg_w(JPREFIX "%s process (pid=%d) signalled by signal %d",
					fdsi.ssi_pid == gc_pid ? "GC" : "request handler",
					fdsi.ssi_pid, WTERMSIG(status));
				}
				break;
*/
			    }
			}
		    }
		}
	    }
	}
	if( rc < 0 ) {
	    logmsg_e(JPREFIX "poll() failed : %s", strerror(errno));
	}
	logmsg_i("%s %s unixsock=%s, script=%s stopped.", PACKAGE_NAME, PACKAGE_VERSION, unixsock, script);
    }

    unlink(unixsock);
    signalfd_close(sigfd);
    socketfd_close(sockfd);

    return rc < 0 ? rc : 0;
}


static
int gc(lua_State *ctx, uid_t uid, gid_t gid, const char *jaildir, const char *gc_evname, unsigned int gc_timeout, int *gc_pid)
{
    int pid, rc;
    const char *evname;

    rc = 0;
    if( !strempty(gc_evname) || gc_timeout > 0 ) {
	if( (pid = fork()) < 0 ) {
	    logmsg_e(JPREFIX "(GC) unable to fork: %s", strerror(errno));
	    rc = -1;
	} else if( pid == 0 ) {
	    pid = getpid();
	    evname = strempty(gc_evname) ? "(internal)" : gc_evname;
	    setproctitle(PACKAGE_NAME ": GC semaphore=%s, timeout=%dm", evname, gc_timeout);
	    logmsg_i("GC semaphore=%s, timeout=%dm starting up.", evname, gc_timeout);
	    rc = gc_loop(ctx, uid, gid, jaildir, gc_evname, gc_timeout);
	    logmsg_i("GC semaphore=%s, timeout=%dm stopped.", evname, gc_timeout);
	    _exit(rc);
	} else {
	    if( gc_pid != NULL ) {
		*gc_pid = pid;
	    }
	}
    }

    return rc;
}

static
int server_init(short daemonize, const char *pidfile, const char *syslog_ident, const char *homedir, short debug)
{
    sigset_t sigmask;
    int fd;
    pid_t pid, sid;
    char pidmsg[64];

    fd = -1;
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGINT);
    sigaddset(&sigmask, SIGQUIT);
    sigaddset(&sigmask, SIGTTIN);
    sigaddset(&sigmask, SIGTTOU);
    sigaddset(&sigmask, SIGHUP);

    if( daemonize ) {
	if( (pid = fork()) != 0 ) {
	    exit(pid < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
	}
	if( (sid = setsid()) < 0 ) {
	    exit(EXIT_FAILURE);
	}
    }
    if( sigprocmask(SIG_BLOCK, &sigmask, NULL) == -1 ) {
	exit(EXIT_FAILURE);
    }
    if( daemonize ) {
	if( (pid = fork()) != 0 ) {
	    exit(pid < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
	}
    }

    openlog(syslog_ident, LOG_PID, LOG_DAEMON);

    if( chdir(homedir) < 0 ) {
	logmsg_e(JPREFIX "chdir(%s) failed: %s.", homedir, strerror(errno));
	exit(EXIT_FAILURE);
    }

    // restrict file creation mode to 750 
    umask(027);
    // and close input stream
    fclose(stdin); stdin = NULL;

    if( !debug ) {
	//stdout = freopen("/dev/null", "wb", stdout);
	//stderr = freopen("/dev/null", "wb", stderr);
	fclose(stdout); stdout = NULL;
	fclose(stderr); stderr = NULL;
    }
    if( pidfile != NULL ) {
	if( (fd = open(pidfile, O_EXCL|O_CREAT|O_WRONLY|O_TRUNC|O_NOFOLLOW, (mode_t) 0644)) == -1) {
	    logmsg_e(JPREFIX "unable to create pidfile '%s': %s.", pidfile, strerror(errno));
	    exit(EXIT_FAILURE);
	}
	snprintf(pidmsg, charbufsize(pidmsg), "%d\n", getpid());
	if( (size_t) write(fd, pidmsg, strlen(pidmsg)) != strlen(pidmsg) ) {
	    logmsg_e(JPREFIX "unable to write data to the pidfile '%s': %s", pidfile, strerror(errno));
	    close(fd);
	    unlink(pidfile);
	    exit(EXIT_FAILURE);
	}
    }

    return fd;
}

static
void server_cleanup(short daemonize, int fd, const char *pidfile)
{
    if( fd != -1 ) {
	if( ftruncate(fd, 0) == -1 ) {
	    logmsg_w(JPREFIX "unable to truncate pidfile '%s': %s", pidfile, strerror(errno));
	}
	close(fd);
	unlink(pidfile);
    }
    closelog();
}

static
uid_t getuid_n(const char *n)
{
    int i = 0, digit = 1;
    struct passwd pw, *pwp = NULL;
    char buf[4096] = "\0";
    uid_t rc = -1;

    if( n == NULL || n[i] == '\0' ) {
	return rc;
    }

    memset(&pw, 0, sizeof(pw));
    for( i = 0; n[i] != 0; i++ ) {
	if( !isdigit(n[i]) ) {
	    digit = 0;
	    break;
	}
    }

    if( digit ) {
	return (uid_t) atoi(n);
    }

    setpwent();
    while( getpwent_r(&pw, buf, charbufsize(buf), &pwp) == 0 ) {
	if( strcmp(n, pwp->pw_name) == 0 ) {
	    rc = pwp->pw_uid;
	    break;
	}
    }
    endpwent();

    return rc;
}

static
gid_t getgid_n(const char *n) 
{
    int i = 0, digit = 1;
    struct group gr, *grp = NULL;
    char buf[4096] = "\0";
    gid_t rc = -1;

    if( n == NULL || n[i] == '\0' ) {
	return rc;
    }

    memset(&gr, 0, sizeof(gr));
    for( i = 0; n[i] != 0; i++ ) {
	if( !isdigit(n[i]) ) {
	    digit = 0;
	    break;
	}
    }

    if( digit ) {
	return (gid_t) atoi(n);
    }

    setgrent();
    while( getgrent_r(&gr, buf, charbufsize(buf), &grp) == 0 ) {
	if( strcmp(n, grp->gr_name) == 0 ) {
	    rc = grp->gr_gid;
	    break;
	}
    }
    endgrent();

    return rc;
}

static
const char *getswd(const char *script, char *buf, size_t size)
{
    const char *ptr;
    if( (ptr = strrchr(script, '/')) == NULL ) {
	return NULL;
    }
    snprintf(buf, size, "%s", strndupa(script, ptr - script));
    return buf;
}

int main(int argc, char**argv)
{
    char unixsock[108] = "", pidfile[255] = "", script[255] = "", jaildir[255] = "", 
	homedir[255] = "", gc_evname[255] = "";
    short daemonize = 1, debug = 0;
    int opt = -1, fd = -1, rc = 0, gc_pid = -1;
    unsigned int gc_timeout = 0;
    uid_t uid = 0;
    gid_t gid = 0;
    lua_State *ctx = NULL;

    if( argc > 1 ) {
	while( (opt = getopt (argc, argv, "c:dxg:n:p:s:t:u:Vh?")) != -1) {
	    if( opt == 'c' ) {
		snprintf(jaildir, charbufsize(jaildir), "%s", optarg);
	    } else if( opt == 'd' ) {
		daemonize = 0;
		debug = 1;
	    } else if( opt == 'x' ) {
		daemonize = 0;
	    } else if( opt == 'g' ) {
		if( (gid = getgid_n(optarg)) == (gid_t) -1 ) {
		    fprintf(stderr, "Unknown group: %s\n", optarg);
		    exit(-1);
		}
	    } else if( opt == 'u' ) {
		if( (uid = getuid_n(optarg)) == (uid_t) -1 ) {
		    fprintf(stderr, "Unknown user: %s\n", optarg);
		    exit(-1);
		}
	    } else if( opt == 's' ) {
		snprintf(unixsock, charbufsize(unixsock), "%s", optarg);
	    } else if( opt == 'p' ) {
		snprintf(pidfile, charbufsize(pidfile), "%s", optarg);
	    } else if( opt == 'n' ) {
		snprintf(gc_evname, charbufsize(gc_evname), "%s", optarg);
	    } else if( opt == 't' ) {
		gc_timeout = strtoul(optarg, NULL, 0);
	    } else if( opt == 'V' ) {
		print_version();
		exit(0);
	    } else if( opt == 'h' || opt == '?' ) {
		print_usage();
		exit(0);
	    }
	}
	if( optind < argc ) {
	    snprintf(script, charbufsize(script), "%s", argv[optind]);
	}
    }
    if( strempty(script) || strempty(unixsock) ) {
	print_usage();
	exit(-1);
    }
    if( getswd(script, homedir, charbufsize(homedir)) == NULL ) {
	fprintf(stderr, "Please, specify the full path to the script.\n");
	exit(-1);
    }

    fd = server_init(daemonize, pidfile, PACKAGE_NAME, strempty(jaildir) ? homedir : jaildir, debug);
    if( (ctx = luaengine_create(script, homedir)) == NULL ) {
	rc = -1;
    } else {
	initproctitle(argc, argv);
	setproctitle(PACKAGE_NAME ": unixsock=%s, script=%s", unixsock, script);
	if( (rc = gc(ctx, uid, gid, jaildir, gc_evname, gc_timeout, &gc_pid)) != -1 ) {
	    rc = main_loop(script, ctx, unixsock, uid, gid, jaildir, gc_pid);
	    if( gc_pid > 0 ) {
		kill(gc_pid, SIGUSR1);
	    }
	}
	luaengine_destroy(ctx);
    }
    server_cleanup(daemonize, fd, pidfile);

    return rc;
}
