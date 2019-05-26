/* -*- C -*- */
/* Copyright (c) 2006 - 2019 omobus-scgid authors, see the included COPYRIGHT file. */

#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "omobus-scgid.h"
#include "connect_timed.h"
#include "tls.h"

#define LUA_LIB
#include "lua.h"
#include "luaaux.h"

#define SOCK_METATABLE		"sock:tcp"
#define ESOCK()			luaL_error(L, "socket is already cleanup or uninitialized")

typedef struct _sockctx_t {
    int sock, port;
    char hostname[64];
    tls_config_t config;
    tls_t ses;
} sockctx_t;

static int sock_connect(lua_State *L)
{
    struct sockaddr_in addr;
    struct timeval tval;
    struct hostent *host;
    int sock, port;
    const char *hostname;
    sockctx_t *ctx;

    if( (sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == SOCKET_ERROR ) {
	lua_pushnil(L);
	lua_pushfstring(L, "unable to create tcp socket: %s", strerror(errno));
	return 2;
    }

    hostname = luaL_checkstring(L, 1);
    port = luaL_checkinteger(L, 2);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(hostname);
    if( addr.sin_addr.s_addr == INADDR_NONE ) {
	if( (host = gethostbyname(hostname)) == NULL ) {
	    lua_pushnil(L);
	    lua_pushfstring(L, "unable to get host by name %s.", hostname);
	    closesocket(sock);
	    return 2;
	}
        memcpy(&addr.sin_addr, host->h_addr_list[0], host->h_length);
    }
    if( connect_timed(sock, (struct sockaddr*)&addr, sizeof(addr), luaL_optinteger(L, 3, 60)) 
	    == SOCKET_ERROR ) {
	lua_pushnil(L);
	lua_pushfstring(L, "unable to connect to the %s:%d: %s", hostname, port, strerror(errno));
	closesocket(sock);
	return 2;
    }
    if( !lua_isnoneornil(L, 4) && lua_istable(L, 4) ) {
	lua_getfield(L, 4, "rcvtimeo");
	if( !lua_isnoneornil(L, -1) && lua_isnumber(L, -1) ) {
	    tval.tv_sec = (int)lua_tointeger(L, -1);
	    tval.tv_usec = 0;
	    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tval, sizeof(tval));
	}
	lua_getfield(L, 4, "sndtimeo");
	if( !lua_isnoneornil(L, -1) && lua_isnumber(L, -1) ) {
	    tval.tv_sec = (int)lua_tointeger(L, -1);
	    tval.tv_usec = 0;
	    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tval, sizeof(tval));
	}
    }

    ctx = (sockctx_t *) lua_newuserdata(L, sizeof(sockctx_t));
    ctx->sock = sock;
    ctx->port = port;
    ctx->config = NULL;
    ctx->ses = NULL;
    strncpy(ctx->hostname, hostname, charbufsize(ctx->hostname));
    luaL_getmetatable(L, SOCK_METATABLE);
    lua_setmetatable(L, -2);

    return 1;
}

static int sock_closesocket(lua_State *L)
{
    sockctx_t *ctx;

    if( (ctx = (sockctx_t *)luaL_checkudata(L, 1, SOCK_METATABLE)) != NULL ) {
	if( ctx->ses != NULL ) {
	    tls_close(ctx->ses);
	    tls_free(ctx->ses);
	    ctx->ses = NULL;
	}
	if( ctx->sock != SOCKET_ERROR ) {
	    shutdown(ctx->sock, SHUT_RDWR);
	    closesocket(ctx->sock);
	    ctx->sock = SOCKET_ERROR;
	}
	if( ctx->config != NULL ) {
	    tls_config_free(ctx->config); 
	    ctx->config = NULL;
	}
    }

    return 0;
}

static int sock_send(lua_State *L)
{
    sockctx_t *ctx;
    int rc = 0;
    const char *byteptr;
    size_t len = 0, t = 0;
    ssize_t sent = 0;

    if( (ctx = (sockctx_t *)luaL_checkudata(L, 1, SOCK_METATABLE)) == NULL || ctx->sock == SOCKET_ERROR ) {
	return ESOCK();
    }
    if( (byteptr = luaL_checklstring(L, 2, &len)) != NULL && len > 0 ) {
	while( len > 0 && (sent = (ctx->ses?tls_send(ctx->ses, byteptr, len):send(ctx->sock, byteptr, len, 0))) > 0 ) {
	    byteptr += sent;
	    len -= sent;
	    t += sent;
	}
	if( sent == -1 ) {
	    lua_pushnil(L);
	    lua_pushfstring(L, "unable to send %d bytes to the %s:%d: %s", 
		len, ctx->hostname, ctx->port, strerror(errno));
	    rc = 2;
	} else {
	    lua_pushinteger(L, t);
	    rc = 1;
	}
    }

    return rc;
}

static int sock_recv(lua_State *L)
{
    sockctx_t *ctx;
    int rc;
    char buf[4096];
    ssize_t r;

    if( (ctx = (sockctx_t *)luaL_checkudata(L, 1, SOCK_METATABLE)) == NULL || ctx->sock == SOCKET_ERROR ) {
	return ESOCK();
    }
    if( (r = (ctx->ses?tls_recv(ctx->ses, buf, sizeof(buf)):recv(ctx->sock, buf, sizeof(buf), 0))) == -1 ) {
	lua_pushnil(L);
	lua_pushfstring(L, "unable to recv %d bytes from the %s:%d: %s", 
	    sizeof(buf), ctx->hostname, ctx->port, strerror(errno));
	rc = 2;
    } else {
	lua_pushlstring(L, buf, r);
	rc = 1;
    }

    return rc;
}

static int sock_starttls(lua_State *L)
{
    sockctx_t *ctx;
    int rc = 0;

    if( (ctx = (sockctx_t *)luaL_checkudata(L, 1, SOCK_METATABLE)) == NULL || ctx->sock == SOCKET_ERROR ) {
	return ESOCK();
    }
    if( (ctx->config = tls_config_new()) == NULL ) {
	lua_pushnil(L);
	lua_pushstring(L, "failed to create TLS configuration context");
	rc = 2;
    } else if( !lua_isnoneornil(L, 2) && lua_istable(L, 2) ) {
	lua_getfield(L, 2, "noverifycert");
	if( !lua_isnoneornil(L, -1) && lua_isboolean(L, -1) && lua_toboolean(L, -1) ) {
	    tls_config_insecure_noverifycert(ctx->config);
	}
	lua_getfield(L, 2, "allowexpired");
	if( !lua_isnoneornil(L, -1) && lua_isboolean(L, -1) && lua_toboolean(L, -1) ) {
	    tls_config_insecure_allowexpired(ctx->config);
	}
	lua_getfield(L, 2, "noverifyname");
	if( !lua_isnoneornil(L, -1) && lua_isboolean(L, -1) && lua_toboolean(L, -1) ) {
	    tls_config_insecure_noverifyname(ctx->config);
	}
	lua_getfield(L, 2, "ca_file");
	if( !lua_isnoneornil(L, -1) && lua_isstring(L, -1) ) {
	    tls_config_set_ca_file(ctx->config, lua_tostring(L, -1));
	}
	lua_getfield(L, 2, "ciphers");
	if( !lua_isnoneornil(L, -1) && lua_isstring(L, -1) ) {
	    tls_config_set_ciphers(ctx->config, lua_tostring(L, -1));
	}
	lua_getfield(L, 2, "protocols");
	if( !lua_isnoneornil(L, -1) && lua_isstring(L, -1) ) {
	    tls_config_set_protocols(ctx->config, tls_parse_protocols(lua_tostring(L, -1)));
	}
	if( (ctx->ses = tls_new(ctx->config)) == NULL || tls_connect(ctx->ses, ctx->sock, ctx->hostname) != OMOBUS_OK ) {
	    if( ctx->ses != NULL ) {
		tls_free(ctx->ses);
		ctx->ses = NULL;
	    }
	    tls_config_free(ctx->config);
	    ctx->config = NULL;
	    lua_pushnil(L);
	    lua_pushfstring(L, "failed to create TLS session with %s:%d", ctx->hostname, ctx->port);
	    rc = 2;
	} else {
	    lua_pushboolean(L, 1);
	    rc = 1;
	}
    }

    return rc;
}

static int sock_stoptls(lua_State *L)
{
    sockctx_t *ctx;

    if( (ctx = (sockctx_t *)luaL_checkudata(L, 1, SOCK_METATABLE)) != NULL ) {
	if( ctx->ses != NULL ) {
	    tls_close(ctx->ses);
	    tls_free(ctx->ses);
	    ctx->ses = NULL;
	}
	if( ctx->config != NULL ) {
	    tls_config_free(ctx->config); 
	    ctx->config = NULL;
	}
    }

    return 0;
}


static const luaL_Reg sock_funcs[] = {
    { "connect", sock_connect },
    { NULL, NULL }
};

static const luaL_Reg tcp_funcs[] = {
    { "start_tls", sock_starttls },
    { "stop_tls", sock_stoptls },
    { "recv", sock_recv },
    { "send", sock_send },
    { "close", sock_closesocket },
    { "__gc", sock_closesocket },
    { NULL, NULL }
};

static void createmeta(lua_State *L, const char *name, const luaL_Reg *funcs) {
    luaL_newmetatable(L, name);
    lua_pushvalue(L, -1);  /* push metatable */
    lua_setfield(L, -2, "__index");  /* metatable.__index = metatable */
    luaL_setfuncs(L, funcs, 0);  /* add file methods to new metatable */
    lua_pop(L, 1);  /* pop new metatable */
}

LUAMOD_API int luaopen_sock(lua_State *L)
{
    luaL_newlib(L, sock_funcs);
    createmeta(L, SOCK_METATABLE, tcp_funcs);
    return 1;
}
