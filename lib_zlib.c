/* -*- C -*- */
/* Copyright (c) 2006 - 2020 omobus-scgid authors, see the included COPYRIGHT file. */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#define LUA_LIB
#include "lua.h"
#include "luaaux.h"

#define ZBUF_SIZE		4096
#define DEFLATE_METATABLE	"zlib.deflate.meta"
#define INFLATE_METATABLE	"zlib.inflate.meta"
#define ECONTEXT()		luaL_argerror(L, 1, "zlib context is already cleanup or uninitialized")

typedef struct _context_t {
    z_stream z;
    unsigned short initialized;
} context_t;

static int lz_assert(lua_State *L, int result, const z_stream *z, const char* file, int line) 
{
    if( !(result == Z_OK || result == Z_STREAM_END) ) {
	switch ( result ) {
	case Z_NEED_DICT:
	    lua_pushfstring(L, "%s:%d input stream requires a dictionary to be deflated: %s.",
		file, line, z->msg);
	    break;
	case Z_STREAM_ERROR:
	    lua_pushfstring(L, "%s:%d  inconsistent internal zlib stream: %s.",
		file, line, z->msg);
	    break;
	case Z_DATA_ERROR:
	    lua_pushfstring(L, "%s:%d input string does not conform to zlib format or checksum failed.",
		file, line);
	    break;
	case Z_MEM_ERROR:
	    lua_pushfstring(L, "%s:%d not enough memory: %s.",
		file, line, z->msg);
	    break;
	case Z_BUF_ERROR:
	    lua_pushfstring(L, "%s:%d no progress possible: %s.",
		file, line, z->msg);
	    break;
	case Z_VERSION_ERROR:
	    lua_pushfstring(L, "%s:%d built with version %s, but dynamically linked with version %s: %s.",
		file, line, ZLIB_VERSION, zlibVersion(), z->msg);
	    break;
	default:
	    lua_pushfstring(L, "%s:%d unknown code %d (%s).",
		file, line, result, z->msg);
	}
	lua_error(L);
    }
    return result;
}

static int lz_stream(lua_State *L, int (*filter)(z_streamp, int), int (*end)(z_streamp), int flush, const char *meta)
{
    context_t *ctx;
    luaL_Buffer zbuf;
    int result;
    size_t size;

    ctx = (context_t *) luaL_checkudata(L, 1, meta);
    if( !ctx->initialized ) {
	return ECONTEXT();
    }

    luaL_buffinitsize(L, &zbuf, ZBUF_SIZE);
    size = 0;
    ctx->z.next_in = (Bytef *) lua_tolstring(L, 2, &size);
    ctx->z.avail_in = size;
    do {
	ctx->z.next_out = (unsigned char*)luaL_prepbuffer(&zbuf);
	ctx->z.avail_out = ZBUF_SIZE;
	if( (result = filter(&ctx->z, flush)) != Z_BUF_ERROR ) {
	    lz_assert(L, result, &ctx->z, __FILE__, __LINE__);
        }
        luaL_addsize(&zbuf, ZBUF_SIZE - ctx->z.avail_out);
    } while( ctx->z.avail_out == 0 );

    luaL_pushresult(&zbuf);

    if( result == Z_STREAM_END ) {
	lz_assert(L, end(&ctx->z), &ctx->z, __FILE__, __LINE__);
	ctx->initialized = 0;
	lua_pushboolean(L, 1);
    } else {
	lua_pushboolean(L, 0);
    }
    lua_pushinteger(L, ctx->z.total_in);
    lua_pushinteger(L, ctx->z.total_out);

    return 4;
}

static int lz_deflate_new(lua_State *L) 
{
    int level, window_size, result;
    context_t *ctx;

    level = luaL_optinteger(L, 1, Z_DEFAULT_COMPRESSION);
    window_size = luaL_optinteger(L, 2, MAX_WBITS);
    ctx = (context_t *) lua_newuserdata(L, sizeof(context_t));
    ctx->z.zalloc = Z_NULL;
    ctx->z.zfree  = Z_NULL;
    ctx->z.opaque = Z_NULL;
    ctx->initialized = 0;

    result = deflateInit2(&ctx->z, level, Z_DEFLATED, window_size, 9, Z_DEFAULT_STRATEGY);
    lz_assert(L, result, &ctx->z, __FILE__, __LINE__);
    ctx->initialized = 1;

    luaL_getmetatable(L, DEFLATE_METATABLE);
    lua_setmetatable(L, -2);

    return 1;
}

static int lz_deflate_delete(lua_State *L)
{
    context_t *ctx;

    ctx = (context_t *) luaL_checkudata(L, 1, DEFLATE_METATABLE);
    if( ctx->initialized ) {
	deflateEnd(&ctx->z);
	ctx->initialized = 0;
    }
    return 0;
}

static int lz_deflate_set(lua_State *L) 
{
    return lz_stream(L, deflate, deflateEnd, Z_NO_FLUSH, DEFLATE_METATABLE);
}

static int lz_deflate_finish(lua_State *L) 
{
    return lz_stream(L, deflate, deflateEnd, Z_FINISH, DEFLATE_METATABLE);
}

static int lz_inflate_new(lua_State *L) 
{
    int window_size;
    context_t *ctx;

    window_size = luaL_optinteger(L, 1, MAX_WBITS + 32);
    ctx = (context_t *) lua_newuserdata(L, sizeof(context_t));
    ctx->z.zalloc = Z_NULL;
    ctx->z.zfree  = Z_NULL;
    ctx->z.opaque = Z_NULL;
    ctx->initialized = 0;

    lz_assert(L, inflateInit2(&ctx->z, window_size), &ctx->z, __FILE__, __LINE__);
    ctx->initialized = 1;

    luaL_getmetatable(L, INFLATE_METATABLE);
    lua_setmetatable(L, -2);

    return 1;
}

static int lz_inflate_delete(lua_State *L)
{
    context_t *ctx;

    ctx = (context_t *) luaL_checkudata(L, 1, INFLATE_METATABLE);
    if( ctx->initialized ) {
	inflateEnd(&ctx->z);
	ctx->initialized = 0;
    }
    return 0;
}

static int lz_inflate_set(lua_State *L) 
{
    return lz_stream(L, inflate, inflateEnd, Z_NO_FLUSH, INFLATE_METATABLE);
}

static int lz_inflate_finish(lua_State *L) 
{
    return lz_stream(L, inflate, inflateEnd, Z_FINISH, INFLATE_METATABLE);
}

static const luaL_Reg zlib_funcs[] = {
    { "deflate", lz_deflate_new },
    { "inflate", lz_inflate_new },
    { NULL, NULL }
};

static const luaL_Reg deflate_funcs[] = {
    { "set", lz_deflate_set },
    { "finish", lz_deflate_finish },
    { "__gc", lz_deflate_delete },
    { NULL, NULL }
};

static const luaL_Reg inflate_funcs[] = {
    { "set", lz_inflate_set },
    { "finish", lz_inflate_finish },
    { "__gc", lz_inflate_delete },
    { NULL, NULL }
};

static void createmeta(lua_State *L, const char *name, const luaL_Reg *funcs) {
    luaL_newmetatable(L, name);
    lua_pushvalue(L, -1);  /* push metatable */
    lua_setfield(L, -2, "__index");  /* metatable.__index = metatable */
    luaL_setfuncs(L, funcs, 0);  /* add file methods to new metatable */
    lua_pop(L, 1);  /* pop new metatable */
}

LUALIB_API int luaopen_zlib(lua_State * const L) 
{
    luaL_newlib(L, zlib_funcs);
    createmeta(L, DEFLATE_METATABLE, deflate_funcs);
    createmeta(L, INFLATE_METATABLE, inflate_funcs);
    return 1;
}
