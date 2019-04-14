/* -*- C -*- */
/* Copyright (c) 2006 - 2019 omobus-scgid authors, see the included COPYRIGHT file. */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <bzlib.h>

#define LUA_LIB
#include "lua.h"
#include "luaaux.h"

#define ZBUF_SIZE		4096
#define COMPRESS_METATABLE	"bzip2.compress.meta"
#define DECOMPRESS_METATABLE	"bzip2.decompress.meta"
#define ECONTEXT()		luaL_argerror(L, 1, "bzip2 context is already cleanup or uninitialized")

typedef struct _context_t {
    bz_stream bz;
    unsigned short initialized;
} context_t;

typedef int (*stream_t)(bz_stream *strm);

static int decompress(bz_stream *strm) {
    return BZ2_bzDecompress(strm);
}

static int compress(bz_stream *strm) {
    return BZ2_bzCompress(strm, BZ_RUN);
}

static int compress_finish(bz_stream *strm) {
    return BZ2_bzCompress(strm, BZ_FINISH);
}

static int lbz_assert(lua_State *L, int result, const char* file, int line) 
{
    if( !(result == BZ_OK || result == BZ_STREAM_END || result == BZ_RUN_OK || result == BZ_FLUSH_OK || result == BZ_FINISH_OK) ) {
	switch ( result ) {
	case BZ_CONFIG_ERROR:
	    lua_pushfstring(L, "%s:%d the bzip2 library has been improperly compiled on your platform.",
		file, line);
	    break;
	case BZ_SEQUENCE_ERROR:
	    lua_pushfstring(L, "%s:%d incorrect functions call sequence.",
		file, line);
	    break;
	case BZ_PARAM_ERROR:
	    lua_pushfstring(L, "%s:%d incorrect function input parameters.",
		file, line);
	    break;
	case BZ_MEM_ERROR:
	    lua_pushfstring(L, "%s:%d no enough memory.",
		file, line);
	    break;
	case BZ_DATA_ERROR:
	    lua_pushfstring(L, "%s:%d the input string does not conform to bzip2 format or checksum failed.",
		file, line);
	    break;
	case BZ_DATA_ERROR_MAGIC:
	    lua_pushfstring(L, "%s:%d the compressed stream does not start with the correct magic bytes.",
		file, line);
	    break;
	case BZ_OUTBUFF_FULL:
	    lua_pushfstring(L, "%s:%d output buffer is full.",
		file, line);
	    break;
	default:
	    lua_pushfstring(L, "%s:%d unknown code %d.",
		file, line, result);
	}
	lua_error(L);
    }
    return result;
}

static int lbz_stream(lua_State *L, stream_t filter, stream_t end, const char *meta)
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
    ctx->bz.next_in = (char *) lua_tolstring(L, 2, &size);
    ctx->bz.avail_in = size;
    do {
	ctx->bz.next_out = (char*) luaL_prepbuffer(&zbuf);
	ctx->bz.avail_out = ZBUF_SIZE;
	result = filter(&ctx->bz);
	lbz_assert(L, result, __FILE__, __LINE__);
        luaL_addsize(&zbuf, ZBUF_SIZE - ctx->bz.avail_out);
    } while( ctx->bz.avail_out == 0 );

    luaL_pushresult(&zbuf);

    if( result == BZ_STREAM_END ) {
	lbz_assert(L, end(&ctx->bz), __FILE__, __LINE__);
	ctx->initialized = 0;
	lua_pushboolean(L, 1);
    } else {
	lua_pushboolean(L, 0);
    }
    lua_pushinteger(L, /*(total_in_hi32 << 32) + */ctx->bz.total_in_lo32);
    lua_pushinteger(L, /*(total_out_hi32 << 32) + */ctx->bz.total_out_lo32);

    return 4;
}

static int lbz_compress_new(lua_State *L) 
{
    int level, work_factor;
    context_t *ctx;

    level = luaL_optinteger(L, 1, 9);
    work_factor = luaL_optinteger(L, 2, 0);
    ctx = (context_t *) lua_newuserdata(L, sizeof(context_t));
    ctx->bz.bzalloc = NULL;
    ctx->bz.bzfree  = NULL;
    ctx->bz.opaque = NULL;
    ctx->initialized = 0;

    lbz_assert(L, BZ2_bzCompressInit(&ctx->bz, level, 0, work_factor), __FILE__, __LINE__);
    ctx->initialized = 1;

    luaL_getmetatable(L, COMPRESS_METATABLE);
    lua_setmetatable(L, -2);

    return 1;
}

static int lbz_compress_delete(lua_State *L)
{
    context_t *ctx;

    ctx = (context_t *) luaL_checkudata(L, 1, COMPRESS_METATABLE);
    if( ctx->initialized ) {
	BZ2_bzCompressEnd(&ctx->bz);
	ctx->initialized = 0;
    }
    return 0;
}

static int lbz_compress_set(lua_State *L) 
{
    return lbz_stream(L, compress, BZ2_bzCompressEnd, COMPRESS_METATABLE);
}

static int lbz_compress_finish(lua_State *L) 
{
    return lbz_stream(L, compress_finish, BZ2_bzCompressEnd, COMPRESS_METATABLE);
}

static int lbz_decompress_new(lua_State *L) 
{
    int small;
    context_t *ctx;

    small = luaL_optboolean(L, 1, 0);
    ctx = (context_t *) lua_newuserdata(L, sizeof(context_t));
    ctx->bz.bzalloc = NULL;
    ctx->bz.bzfree  = NULL;
    ctx->bz.opaque = NULL;
    ctx->initialized = 0;

    lbz_assert(L, BZ2_bzDecompressInit(&ctx->bz, 0, small), __FILE__, __LINE__);
    ctx->initialized = 1;

    luaL_getmetatable(L, DECOMPRESS_METATABLE);
    lua_setmetatable(L, -2);

    return 1;
}

static int lbz_decompress_delete(lua_State *L)
{
    context_t *ctx;

    ctx = (context_t *) luaL_checkudata(L, 1, DECOMPRESS_METATABLE);
    if( ctx->initialized ) {
	BZ2_bzDecompressEnd(&ctx->bz);
	ctx->initialized = 0;
    }
    return 0;
}

static int lbz_decompress_set(lua_State *L) 
{
    return lbz_stream(L, decompress, BZ2_bzDecompressEnd, DECOMPRESS_METATABLE);
}

static int lbz_decompress_finish(lua_State *L) 
{
    return lbz_stream(L, decompress, BZ2_bzDecompressEnd, DECOMPRESS_METATABLE);
}

static const luaL_Reg bzip2_funcs[] = {
    { "compress", lbz_compress_new },
    { "decompress", lbz_decompress_new },
    { NULL, NULL }
};

static const luaL_Reg compress_funcs[] = {
    { "set", lbz_compress_set },
    { "finish", lbz_compress_finish },
    { "__gc", lbz_compress_delete },
    { NULL, NULL }
};

static const luaL_Reg decompress_funcs[] = {
    { "set", lbz_decompress_set },
    { "finish", lbz_decompress_finish },
    { "__gc", lbz_decompress_delete },
    { NULL, NULL }
};

static void createmeta(lua_State *L, const char *name, const luaL_Reg *funcs) {
    luaL_newmetatable(L, name);
    lua_pushvalue(L, -1);  /* push metatable */
    lua_setfield(L, -2, "__index");  /* metatable.__index = metatable */
    luaL_setfuncs(L, funcs, 0);  /* add file methods to new metatable */
    lua_pop(L, 1);  /* pop new metatable */
}

LUALIB_API int luaopen_bzlib(lua_State * const L) 
{
    luaL_newlib(L, bzip2_funcs);
    createmeta(L, COMPRESS_METATABLE, compress_funcs);
    createmeta(L, DECOMPRESS_METATABLE, decompress_funcs);
    return 1;
}
