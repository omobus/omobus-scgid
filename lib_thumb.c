/* -*- C -*- */
/* Copyright (c) 2006 - 2022 omobus-scgid authors, see the included COPYRIGHT file. */

#include <stdlib.h>
#include "thumb.h"

#define LUA_LIB
#include "lua.h"
#include "luaaux.h"

static inline void setintegerfield(lua_State *L, const char *key, int value)
{
    lua_pushinteger(L, value);
    lua_setfield(L, -2, key);
}

static inline void setdoublefield(lua_State *L, const char *key, double value)
{
    lua_pushnumber(L, value);
    lua_setfield(L, -2, key);
}

static inline void setrawfield(lua_State *L, const char *key, const char *buf, size_t size)
{
    lua_pushlstring(L, buf, size);
    lua_setfield(L, -2, key);
}

static inline int max(int arg1, int arg2)
{
    return arg1 > arg2 ? arg1 : arg2;
}

static int thumb_encode(lua_State *L)
{
    const char *data = luaL_checkstring(L, 1);
    size_t size = lua_rawlen(L, 1);
    int width = 0, height = luaL_checkinteger(L, 2); /* target height */
    int quality = luaL_checkinteger(L, 3); /* target quality */
    int w = 0, h = 0;
    Epeg_Image *im = NULL;
    unsigned char *thumb = NULL;
    int thumbSize = 0;
    int rc = 0;

    if( data == NULL || size <= 0 ) {
	lua_pushnil(L);
	lua_pushboolean(L, 1);
	lua_pushstring(L, "incorrect JPEG data");
	rc = 3;
    } else if( height < 100 ) {
	lua_pushnil(L);
	lua_pushboolean(L, 1);
	lua_pushfstring(L, "result thumbnail image is to small (target height only %dpx), height is expected to be at least 100px", height);
	rc = 3;
    } else if( !(30 <= quality && quality <= 100) ) {
	lua_pushnil(L);
	lua_pushboolean(L, 1);
	lua_pushfstring(L, "quality of thumbnail must be between 30 and 100, current value is %d", quality);
	rc = 3;
    } else if( (im = epeg_memory_open((void*)data, size)) == NULL ) {
	lua_pushnil(L);
	lua_pushboolean(L, 1);
	lua_pushstring(L, "unable to open JPEG data");
	rc = 3;
    } else {
	epeg_size_get(im, &w, &h);
	if( h < height ) { /* nothing to do if image height less then thumbnail height: */
	    lua_pushnil(L);
	    lua_pushboolean(L, 0);
	    rc = 2;
	} else {
	    width = max(w * height / h, 1);
	    epeg_decode_size_set(im, width, height);
	    epeg_quality_set(im, quality);
	    epeg_memory_output_set(im, &thumb, &thumbSize);
	    epeg_encode(im);
	}
	epeg_close(im);

	if( thumb != NULL && thumbSize > 0 ) {
	    lua_createtable(L, 0, 4);  /* 4 = number of fields */
	    setdoublefield(L, "scaleFactor", (double)height / (double)h);
	    setintegerfield(L, "width", width);
	    setintegerfield(L, "height", height);
	    setrawfield(L, "data", (const char *) thumb, thumbSize);
	    rc = 1;
	} else {
	    lua_pushnil(L);
	    lua_pushboolean(L, 1);
	    lua_pushstring(L, "unable to encode JPEG data to thumbnail image");
	    rc = 3;
	}
	if( thumb != NULL ) {
	    free(thumb);
	    thumb = NULL;
	}
    }

    return rc;
}

static const luaL_Reg thumb_funcs[] = {
    { "encode", thumb_encode },
    { NULL, NULL }
};

LUAMOD_API int luaopen_thumb(lua_State *L)
{
    luaL_newlib(L, thumb_funcs);
    return 1;
}
