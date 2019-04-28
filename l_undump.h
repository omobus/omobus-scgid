/* -*- H -*- */
/* This file is a part of the omobusd project.
 * Major portions taken verbatim or adapted from the Lua interpreter.
 * Copyright (C) 1994-2015 Lua.org, PUC-Rio. See Copyright Notice in COPYRIGHT.Lua.
 */

#ifndef lundump_h
#define lundump_h

#include "l_limits.h"
#include "l_object.h"
#include "l_zio.h"


/* data to catch conversion errors */
#define LUAC_DATA	"\x19\x93\r\n\x1a\n"

#define LUAC_INT	0x5678
#define LUAC_NUM	cast_num(370.5)

#define MYINT(s)	(s[0]-'0')
#define LUAC_VERSION	(MYINT(LUA_VERSION_MAJOR)*16+MYINT(LUA_VERSION_MINOR))
#define LUAC_FORMAT	0	/* this is the official format */

/* load one chunk; from lundump.c */
LUAI_FUNC LClosure* luaU_undump (lua_State* L, ZIO* Z, Mbuffer* buff,
                                 const char* name);

/* dump one chunk; from ldump.c */
LUAI_FUNC int luaU_dump (lua_State* L, const Proto* f, lua_Writer w,
                         void* data, int strip);

#endif
