/* -*- C -*- */
/* Copyright (c) 2006 - 2020 omobus-scgid authors, see the included COPYRIGHT file. */

#include <stdlib.h>
#include <iconv.h>
#include <errno.h>
#include <string.h>

#define LUA_LIB
#include "lua.h"
#include "luaaux.h"

/* Original code created by Alexandre Erwin Ittner <alexandre@ittner.com.br>
 * https://github.com/ittner/lua-iconv
 */

#define ICONV_METATABLE   "iconv_t"

/* Set a integer constant. Assumes a table in the top of the stack */
#define TBL_SET_INT_CONST(L, c) {   \
    lua_pushliteral(L, #c);         \
    lua_pushnumber(L, c);           \
    lua_settable(L, -3);            \
}

#define ERROR_NO_MEMORY     1
#define ERROR_INVALID       2
#define ERROR_INCOMPLETE    3
#define ERROR_UNKNOWN       4
#define ERROR_FINALIZED     5

#define CONV_BUF_SIZE       256


static iconv_t get_iconv_t(lua_State *L, int narg) 
{
    iconv_t cd = (iconv_t) -1;
    if (luaL_checkudata(L, narg, ICONV_METATABLE) != NULL ) {
	cd = *((iconv_t *)lua_touserdata(L, narg));
    } else {
	luaL_argerror(L, narg, lua_pushfstring(L, ICONV_METATABLE " expected, got %s",
	    luaL_typename(L, narg)));
    }
    return cd;
}

static int Liconv_open(lua_State *L) 
{
    const char *tocode, *fromcode;
    iconv_t cd, *ptr;

    tocode = luaL_checkstring(L, 1);
    fromcode = luaL_checkstring(L, 2);
    if( (cd = iconv_open(tocode, fromcode)) != (iconv_t)(-1) ) {
	ptr = (iconv_t *) lua_newuserdata(L, sizeof(iconv_t));
	*ptr = cd;
	luaL_getmetatable(L, ICONV_METATABLE);
	lua_setmetatable(L, -2);
    } else {
	lua_pushnil(L);
    }
    return 1;
}

static int Liconv(lua_State *L) 
{
    iconv_t cd;
    size_t ibleft, obsize, obleft, ret = -1;
    char *inbuf, *outbuf, *outbufs;
    int hasone = 0;

    ibleft = lua_rawlen(L, 2);
    inbuf = (char*) luaL_checkstring(L, 2);
    obsize = (ibleft > CONV_BUF_SIZE) ? ibleft : CONV_BUF_SIZE; 
    obleft = obsize;

    if( (cd = get_iconv_t(L, 1)) == (iconv_t)-1 ) {
	lua_pushnil(L);
	lua_pushnumber(L, ERROR_FINALIZED);
	return 2;
    }
    if( (outbuf = (char*) malloc(obsize * sizeof(char))) == NULL ) {
	lua_pushnil(L);
	lua_pushnumber(L, ERROR_NO_MEMORY);
	return 2;
    }

    outbufs = outbuf;
    do {
	if( (ret = iconv(cd, &inbuf, &ibleft, &outbuf, &obleft)) == (size_t)(-1) ) {
	    lua_pushlstring(L, outbufs, obsize - obleft);
	    if( hasone == 1 ) {
		lua_concat(L, 2);
	    }
	    hasone = 1;
	    if( errno == EILSEQ ) {
		lua_pushnumber(L, ERROR_INVALID);
		free(outbufs);
		return 2;   /* Invalid character sequence */
	    } else if (errno == EINVAL) {
		lua_pushnumber(L, ERROR_INCOMPLETE);
		free(outbufs);
		return 2;   /* Incomplete character sequence */
	    } else if (errno == E2BIG) {
		obleft = obsize;
		outbuf = outbufs;
	    } else {
		lua_pushnumber(L, ERROR_UNKNOWN);
		free(outbufs);
		return 2; /* Unknown error */
	    }
	}
    } while (ret == (size_t) -1);

    lua_pushlstring(L, outbufs, obsize - obleft);
    if (hasone == 1) {
	lua_concat(L, 2);
    }
    free(outbufs);
    lua_pushnil(L);
    return 2;
}

static int Liconv_close(lua_State *L) {
    iconv_t cd;
    if( (cd = get_iconv_t(L, 1)) != (iconv_t)-1 && iconv_close(cd) == 0) {
	/* Mark the pointer as freed, preventing interpreter crashes
	   if the user forces __gc to be called twice. */
	*((iconv_t *)lua_touserdata(L, 1)) = (iconv_t) -1;
	lua_pushboolean(L, 1);
    } else {
        lua_pushnil(L);
    }
    return 1;
}

static const luaL_Reg iconv_funcs[] = {
    { "open",	Liconv_open },
    { "new",	Liconv_open },
    { NULL, NULL }
};

static const luaL_Reg object_funcs[] = {
    { "iconv",	Liconv },
    { "close",	Liconv_close },
    {"__gc", Liconv_close},
    { NULL, NULL }
};

static void createmeta(lua_State *L, const char *name, const luaL_Reg *funcs) {
    luaL_newmetatable(L, name);
    lua_pushvalue(L, -1);  /* push metatable */
    lua_setfield(L, -2, "__index");  /* metatable.__index = metatable */
    luaL_setfuncs(L, funcs, 0);  /* add file methods to new metatable */
    lua_pop(L, 1);  /* pop new metatable */
}

LUAMOD_API int luaopen_iconv(lua_State *L)
{
    luaL_newlib(L, iconv_funcs);
    TBL_SET_INT_CONST(L, ERROR_NO_MEMORY);
    TBL_SET_INT_CONST(L, ERROR_INVALID);
    TBL_SET_INT_CONST(L, ERROR_INCOMPLETE);
    TBL_SET_INT_CONST(L, ERROR_FINALIZED);
    TBL_SET_INT_CONST(L, ERROR_UNKNOWN);
    createmeta(L, ICONV_METATABLE, object_funcs);
    return 1;
}
