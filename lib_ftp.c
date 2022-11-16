/* -*- C -*- */
/* Copyright (c) 2006 - 2022 omobus-scgid authors, see the included COPYRIGHT file. */

#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <unistd.h>
#include "ftp.h"
#include "omobus-scgid.h"

#define LUA_LIB
#include "lua.h"
#include "luaaux.h"

#define FTP_METATABLE		"sock:ftp"


static int luaftp_connect(lua_State *L)
{
    ftp_ctx_t ctx, *data;
    if( (ctx = ftp_connect(NULL, luaL_checkstring(L, 1), luaL_checkinteger(L, 2), luaL_optinteger(L, 3, 30), 
	    luaL_optinteger(L, 4, 25), luaL_optinteger(L, 5, 25), luaL_optboolean(L, 6, 1))) != NULL ) {
	data = (ftp_ctx_t *) lua_newuserdata(L, sizeof(ftp_ctx_t *));
	*data = ctx;
	luaL_getmetatable(L, FTP_METATABLE);
	lua_setmetatable(L, -2);
    } else {
	lua_pushnil(L);
    }

    return 1;
}

static int luaftp_disconnect(lua_State *L)
{
    ftp_ctx_t *data;
    if( (data = (ftp_ctx_t *) luaL_checkudata(L, 1, FTP_METATABLE)) != NULL && *data != NULL ) {
	ftp_disconnect(*data);
	*data = NULL;
    }
    return 0;
}

static int luaftp_quit(lua_State *L)
{
    ftp_ctx_t *data;
    if( (data = (ftp_ctx_t *) luaL_checkudata(L, 1, FTP_METATABLE)) != NULL && *data != NULL ) {
	ftp_quit(*data);
    }
    return 0;
}

static int luaftp_login(lua_State *L)
{
    ftp_ctx_t *data;
    if( (data = (ftp_ctx_t *) luaL_checkudata(L, 1, FTP_METATABLE)) != NULL && *data != NULL && 
	ftp_login(*data, luaL_checkstring(L, 2), luaL_checkstring(L, 3)) == OMOBUS_OK ) {
	lua_pushboolean(L, 1);
    } else {
	lua_pushboolean(L, 0);
    }
    return 1;
}

static int luaftp_feat(lua_State *L)
{
    ftp_ctx_t *data;
    if( (data = (ftp_ctx_t *) luaL_checkudata(L, 1, FTP_METATABLE)) != NULL && *data != NULL ) {
	ftp_feat(*data);
    }
    return 0;
}

static int luaftp_cwd(lua_State *L)
{
    ftp_ctx_t *data;
    if( (data = (ftp_ctx_t *) luaL_checkudata(L, 1, FTP_METATABLE)) != NULL && *data != NULL && 
	ftp_cwd(*data, luaL_checkstring(L, 2)) == OMOBUS_OK ) {
	lua_pushboolean(L, 1);
    } else {
	lua_pushboolean(L, 0);
    }
    return 1;
}

static int luaftp_nlst(lua_State *L)
{
    ftp_ctx_t *data; char *buf = NULL; int len = 0;
    if( (data = (ftp_ctx_t *) luaL_checkudata(L, 1, FTP_METATABLE)) != NULL && *data != NULL && 
	ftp_nlst_mem(*data, &buf, &len) == OMOBUS_OK && buf != NULL ) {
	lua_pushlstring(L, buf, len);
	lua_pushboolean(L, 0); //err = false
	free(buf);
    } else {
	lua_pushnil(L);
	lua_pushboolean(L, 1); //err = true
    }
    return 2;
}

static int luaftp_size(lua_State *L)
{
    ftp_ctx_t *data; int size;
    if( (data = (ftp_ctx_t *) luaL_checkudata(L, 1, FTP_METATABLE)) != NULL && *data != NULL && 
	(size = ftp_size(*data, luaL_checkstring(L, 2))) >= 0 ) {
	lua_pushinteger(L, size);
	lua_pushboolean(L, 0); // err = false
    } else {
	lua_pushnil(L);
	lua_pushboolean(L, 1); // err = true
    }
    return 2;
}

static int luaftp_retr(lua_State *L)
{
    ftp_ctx_t *data; char *buf = NULL; size_t size = 0;
    if( (data = (ftp_ctx_t *) luaL_checkudata(L, 1, FTP_METATABLE)) != NULL && *data != NULL && 
	ftp_retr_mem(*data, luaL_checkstring(L, 2), &buf, &size) == OMOBUS_OK && buf != NULL ) {
	lua_pushlstring(L, buf, (int) size);
	lua_pushboolean(L, 0); // err = false
	free(buf);
    } else {
	lua_pushnil(L);
	lua_pushboolean(L, 1); // err = true
    }
    return 2;
}

static int luaftp_stor(lua_State *L)
{
    ftp_ctx_t *data;
    if( (data = (ftp_ctx_t *) luaL_checkudata(L, 1, FTP_METATABLE)) != NULL && *data != NULL &&
	ftp_stor_mem_safe(*data, luaL_checkstring(L, 2), (const char *) luaL_checkstring(L, 3), 
	    (int) lua_rawlen(L, 3)) == OMOBUS_OK ) {
	lua_pushboolean(L, 0); // err = false
    } else {
	lua_pushboolean(L, 1); // err = true
    }
    return 1;
}

static int luaftp_authtls(lua_State *L)
{
    ftp_ctx_t *data;
    if( (data = (ftp_ctx_t *) luaL_checkudata(L, 1, FTP_METATABLE)) != NULL && *data != NULL && 
	ftp_authtls(*data, luaL_checkboolean(L, 2), luaL_checkboolean(L, 3), luaL_checkboolean(L, 4), 
	    luaL_checkstring(L, 5), luaL_checkstring(L, 6)) == OMOBUS_OK ) {
	lua_pushboolean(L, 1);
    } else {
	lua_pushboolean(L, 0);
    }
    return 1;
}

static int luaftp_ccc(lua_State *L)
{
    ftp_ctx_t *data;
    if( (data = (ftp_ctx_t *) luaL_checkudata(L, 1, FTP_METATABLE)) != NULL && *data != NULL && 
	ftp_ccc(*data) == OMOBUS_OK ) {
	lua_pushboolean(L, 1);
    } else {
	lua_pushboolean(L, 0);
    }
    return 1;
}

static int luaftp_prot(lua_State *L)
{
    ftp_ctx_t *data;
    if( (data = (ftp_ctx_t *) luaL_checkudata(L, 1, FTP_METATABLE)) != NULL && *data != NULL && 
	ftp_prot(*data) == OMOBUS_OK ) {
	lua_pushboolean(L, 1);
    } else {
	lua_pushboolean(L, 0);
    }
    return 1;
}

static int luaftp_cdc(lua_State *L)
{
    ftp_ctx_t *data;
    if( (data = (ftp_ctx_t *) luaL_checkudata(L, 1, FTP_METATABLE)) != NULL && *data != NULL && 
	ftp_cdc(*data) == OMOBUS_OK ) {
	lua_pushboolean(L, 1);
    } else {
	lua_pushboolean(L, 0);
    }
    return 1;
}

static const luaL_Reg ftp_funcs[] = {
    { "connect", luaftp_connect },
    { NULL, NULL }
};

static const luaL_Reg ftp_funcs2[] = {
    { "quit", luaftp_quit },
    { "login", luaftp_login },
    { "feat", luaftp_feat },
    { "cwd", luaftp_cwd },
    { "nlst", luaftp_nlst },
    { "size", luaftp_size },
    { "retr", luaftp_retr },
    { "stor", luaftp_stor },
    { "authtls", luaftp_authtls },
    { "ccc", luaftp_ccc },
    { "prot", luaftp_prot },
    { "cdc", luaftp_cdc },
    { "disconnect", luaftp_disconnect },
    { "__gc", luaftp_disconnect },
    { NULL, NULL }
};

static void createmeta(lua_State *L, const char *name, const luaL_Reg *funcs) {
    luaL_newmetatable(L, name);
    lua_pushvalue(L, -1);  /* push metatable */
    lua_setfield(L, -2, "__index");  /* metatable.__index = metatable */
    luaL_setfuncs(L, funcs, 0);  /* add file methods to new metatable */
    lua_pop(L, 1);  /* pop new metatable */
}

LUAMOD_API int luaopen_ftp(lua_State *L)
{
    luaL_newlib(L, ftp_funcs);
    createmeta(L, FTP_METATABLE, ftp_funcs2);
    return 1;
}
