/* -*- C -*- */
/* Copyright (c) 2006 - 2021 omobus-scgid authors, see the included COPYRIGHT file. */

#include <stdlib.h>
#include <memory.h>
#include "crc32.h"
#include "crc64.h"
#include "md5.h"
#include "sha1.h"
#include "base64.h"

#define LUA_LIB
#include "lua.h"
#include "luaaux.h"

#define CRC32_METATABLE		"hash:crc32"
#define CRC64_METATABLE		"hash:crc64"
#define MD5_METATABLE		"hash:md5"
#define SHA1_METATABLE		"hash:sha1"

static void setmeta(lua_State *L, const char *name) {
    luaL_getmetatable(L, name);
    lua_setmetatable(L, -2);
}

static int crc32_init(lua_State *L) 
{
    int32_t *hash;

    hash = (int32_t *)lua_newuserdata(L, sizeof(int32_t));
    memset(hash, 0, sizeof(int32_t));
    setmeta(L, CRC32_METATABLE);

    return 1;
}

static int crc32_calc(lua_State *L) 
{
    int32_t *hash;
    const char *s;
    size_t l = 0;

    hash = (int32_t *) luaL_checkudata(L, 1, CRC32_METATABLE);

    if( (s = luaL_checklstring(L, 2, &l)) != NULL && l > 0 ) {
	*hash = crc32(*hash, s, l);
    }

    return 0;
}

static int crc32_tostring(lua_State *L) 
{
    int32_t *hash;
    char hex[17];

    hash = (int32_t *) luaL_checkudata(L, 1, CRC32_METATABLE);
    memset(hex, 0, sizeof(hex));
    snprintf(hex, 16, "%08x", *hash);
    lua_pushstring(L, hex);

    return 1;
}

static int crc32_close(lua_State *L) 
{
    int32_t *hash;

    hash = (int32_t *) luaL_checkudata(L, 1, CRC32_METATABLE);
    memset(hash, 0, sizeof(int32_t));

    return 0;
}

static int crc64_init(lua_State *L) 
{
    int64_t *hash;

    hash = (int64_t *)lua_newuserdata(L, sizeof(int64_t));
    memset(hash, 0, sizeof(int64_t));
    setmeta(L, CRC64_METATABLE);

    return 1;
}

static int crc64_calc(lua_State *L) 
{
    int64_t *hash;
    const char *s;
    size_t l = 0;

    hash = (int64_t *) luaL_checkudata(L, 1, CRC64_METATABLE);

    if( (s = luaL_checklstring(L, 2, &l)) != NULL && l > 0 ) {
	*hash = crc64(*hash, s, l);
    }

    return 0;
}

static int crc64_tostring(lua_State *L) 
{
    int64_t *hash;
    char hex[33];

    hash = (int64_t *) luaL_checkudata(L, 1, CRC64_METATABLE);
    memset(hex, 0, sizeof(hex));
    snprintf(hex, 32, "%016llx", (unsigned long long) *hash);
    lua_pushstring(L, hex);

    return 1;
}

static int crc64_close(lua_State *L) 
{
    int64_t *hash;

    hash = (int64_t *) luaL_checkudata(L, 1, CRC64_METATABLE);
    memset(hash, 0, sizeof(int64_t));

    return 0;
}

static int md5_init(lua_State *L) 
{
    MD5_CTX *ctx;

    ctx = (MD5_CTX *)lua_newuserdata(L, sizeof(MD5_CTX));
    md5init(ctx);
    setmeta(L, MD5_METATABLE);

    return 1;
}

static int md5_update(lua_State *L) 
{
    MD5_CTX *ctx;
    const char *s;
    size_t l = 0;

    ctx = (MD5_CTX *) luaL_checkudata(L, 1, MD5_METATABLE);
    if( (s = luaL_checklstring(L, 2, &l)) != NULL && l > 0 ) {
	md5update(ctx, (const unsigned char *) s, l);
    }

    return 0;
}

static int md5_final(lua_State *L)
{
    MD5_CTX *ctx;
    int rc = 0, i;
    unsigned char digest[MD5_BYTES];
    char md5string[MD5_BYTES*2+1];

    ctx = (MD5_CTX *) luaL_checkudata(L, 1, MD5_METATABLE);
    md5final(digest, ctx);
    if( luaL_optboolean(L, 2, 0) == 0 ) {
	for( i = 0; i < MD5_BYTES; ++i ) {
	    sprintf(&md5string[i*2], "%02x", (unsigned int)digest[i]);
	}
	md5string[MD5_BYTES*2] = '\0';
	lua_pushlstring(L, md5string, MD5_BYTES*2);
	rc++;
    } else {
	lua_pushlstring(L, (const char *)digest, MD5_BYTES);
	rc++;
    }

    return rc;
}

static int md5_digest_size(lua_State *L)
{
    lua_pushinteger(L, MD5_BYTES);
    return 1;
}

static int md5_gc(lua_State *L)
{
    MD5_CTX *ctx;

    ctx = (MD5_CTX *) luaL_checkudata(L, 1, MD5_METATABLE);
    memset(ctx, 0, sizeof(MD5_CTX));

    return 0;
}

static int sha1_init(lua_State *L)
{
    SHA1_CTX *ctx;

    ctx = (SHA1_CTX *)lua_newuserdata(L, sizeof(SHA1_CTX));
    SHA1Init(ctx);
    setmeta(L, SHA1_METATABLE);

    return 1;
}

static int sha1_update(lua_State *L) 
{
    SHA1_CTX *ctx;
    const char *s;
    size_t l = 0;

    ctx = (SHA1_CTX *) luaL_checkudata(L, 1, SHA1_METATABLE);
    if( (s = luaL_checklstring(L, 2, &l)) != NULL && l > 0 ) {
	SHA1Update(ctx, (const unsigned char *) s, l);
    }

    return 0;
}

static int sha1_final(lua_State *L)
{
    SHA1_CTX *ctx;
    int rc = 0, i;
    unsigned char digest[SHA1_BYTES];
    char sha1string[SHA1_BYTES*2+1];

    ctx = (SHA1_CTX *) luaL_checkudata(L, 1, SHA1_METATABLE);
    SHA1Final(digest, ctx);
    if( luaL_optboolean(L, 2, 0) == 0 ) {
	for( i = 0; i < SHA1_BYTES; ++i ) {
	    sprintf(&sha1string[i*2], "%02x", (unsigned int)digest[i]);
	}
	sha1string[SHA1_BYTES*2] = '\0';
	lua_pushlstring(L, sha1string, SHA1_BYTES*2);
	rc++;
    } else {
	lua_pushlstring(L, (const char *)digest, SHA1_BYTES);
	rc++;
    }

    return rc;
}

static int sha1_digest_size(lua_State *L)
{
    lua_pushinteger(L, SHA1_BYTES);
    return 1;
}

static int sha1_gc(lua_State *L)
{
    SHA1_CTX *ctx;

    ctx = (SHA1_CTX *) luaL_checkudata(L, 1, SHA1_METATABLE);
    memset(ctx, 0, sizeof(SHA1_CTX));

    return 0;
}

static int base64_encode(lua_State *L)
{
    const char *s;
    char *b64;
    size_t l = 0;
    int rc = 0, r = 0;

    if( (s = luaL_checklstring(L, 1, &l)) != NULL && l > 0 ) {
	if( (r = base64encode_len(l)) > 0 && (b64 = (char *)malloc(r)) != NULL ) {
	    memset(b64, 0, r);
	    base64encode(b64, s, l);
	    lua_pushstring(L, b64);
	    free(b64);
	    rc++;
	} else {
	    rc = luaL_error(L, "unable to encode to base64");
	}
    }
    return rc;
}

static int base64_decode(lua_State *L)
{
    const char *s;
    char *data;
    size_t l = 0;
    int rc = 0, sz = 0, d = 0;

    if( (s = luaL_checklstring(L, 1, &l)) != NULL && l > 0 ) {
	if( (sz = base64decode_len(s)) > 0 && (data = (char *)malloc(sz)) != NULL ) {
	    memset(data, 0, sz);
	    d = base64decode(data, s);
	    lua_pushlstring(L, data, d);
	    free(data);
	    rc++;
	} else {
	    rc = luaL_error(L, "unable to decode from base64");
	}
    }
    return rc;
}


static const luaL_Reg crc32_funcs[] = {
    { "calc", crc32_calc },
    { "get", crc32_tostring },
    { "__gc", crc32_close },
    { "__tostring", crc32_tostring },
    { NULL, NULL }
};

static const luaL_Reg crc64_funcs[] = {
    { "calc", crc64_calc },
    { "get", crc64_tostring },
    { "__gc", crc64_close },
    { "__tostring", crc64_tostring },
    { NULL, NULL }
};

static const luaL_Reg md5_funcs[] = {
    { "update", md5_update },
    { "final", md5_final },
    { "__gc", md5_gc },
    { "__tostring", md5_final },
    { NULL, NULL }
};

static const luaL_Reg sha1_funcs[] = {
    { "update", sha1_update },
    { "final", sha1_final },
    { "__gc", sha1_gc },
    { "__tostring", sha1_final },
    { NULL, NULL }
};

static const luaL_Reg hash_funcs[] = {
    { "crc32", crc32_init },
    { "crc64", crc64_init },
    { "md5", md5_init },
    { "sha1", sha1_init },
    { "md5_digest_size", md5_digest_size },
    { "sha1_digest_size", sha1_digest_size },
    { NULL, NULL }
};

static void createmeta(lua_State *L, const char *name, const luaL_Reg *funcs) {
    luaL_newmetatable(L, name);
    lua_pushvalue(L, -1);  /* push metatable */
    lua_setfield(L, -2, "__index");  /* metatable.__index = metatable */
    luaL_setfuncs(L, funcs, 0);  /* add file methods to new metatable */
    lua_pop(L, 1);  /* pop new metatable */
}

LUAMOD_API int luaopen_hash(lua_State *L)
{
    luaL_newlib(L, hash_funcs);
    createmeta(L, CRC32_METATABLE, crc32_funcs);
    createmeta(L, CRC64_METATABLE, crc64_funcs);
    createmeta(L, MD5_METATABLE, md5_funcs);
    createmeta(L, SHA1_METATABLE, sha1_funcs);
    return 1;
}

static const luaL_Reg base64_funcs[] = {
    { "encode", base64_encode },
    { "decode", base64_decode },
    { NULL, NULL }
};

LUAMOD_API int luaopen_base64(lua_State *L)
{
    luaL_newlib(L, base64_funcs);
    return 1;
}
