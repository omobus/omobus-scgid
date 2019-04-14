/* -*- C -*- */
/* Copyright (c) 2006 - 2019 omobus-scgid authors, see the included COPYRIGHT file. */

#define LUA_LIB
#include "lua.h"
#include "luaaux.h"

static int dummy0(lua_State *L) 
{
    lua_pushstring(L, "dummy0");
    return 1;
}

static const luaL_Reg dummy0_funcs[] = {
    {"dummy0", dummy0},
    {NULL, NULL}
};

LUAMOD_API int luaopen_bind_dummy(lua_State *L)
{
    luaL_newlib(L, dummy0_funcs);
    return 1;
}
