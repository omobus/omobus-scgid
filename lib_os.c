/* -*- C -*- */
/* This file is a part of the omobus-scgid project.
 * Major portions taken verbatim or adapted from the Lua interpreter.
 * Copyright (C) 1994-2011 Lua.org, PUC-Rio. See Copyright Notice in COPYRIGHT.Lua.
 */

#include <string.h>
#include <time.h>
#include <unistd.h>

#define LUA_LIB
#include "lua.h"
#include "luaaux.h"

/* list of valid conversion specifiers for the 'strftime' function */
#define LUA_STRFTIMEOPTIONS	{ "aAbBcCdDeFgGhHIjmMnprRStTuUVwWxXyYzZ%", "", "E", "cCxXyY", "O", "deHImMSuUVwWy" }


static void setfield(lua_State *L, const char *key, int value) 
{
    lua_pushinteger(L, value);
    lua_setfield(L, -2, key);
}


static void setboolfield(lua_State *L, const char *key, int value) 
{
    if( value < 0 ) {  /* undefined? */
	return;  /* does not set field */
    }
    lua_pushboolean(L, value);
    lua_setfield(L, -2, key);
}

static int getboolfield(lua_State *L, const char *key) {
    int res;
    lua_getfield(L, -1, key);
    res = lua_isnil(L, -1) ? -1 : lua_toboolean(L, -1);
    lua_pop(L, 1);
    return res;
}

static int getfield(lua_State *L, const char *key, int d) {
    int res, isnum;
    lua_getfield(L, -1, key);
    res = (int)lua_tointegerx(L, -1, &isnum);
    if( !isnum ) {
	if( d < 0 ) {
	    return luaL_error(L, "field " LUA_QS " missing in date table", key);
	}
	res = d;
    }
    lua_pop(L, 1);
    return res;
}

static const char *checkoption(lua_State *L, const char *conv, char *buff) 
{
    static const char *const options[] = LUA_STRFTIMEOPTIONS;
    unsigned int i;
    for( i = 0; i < sizeof(options)/sizeof(options[0]); i += 2 ) {
	if (*conv != '\0' && strchr(options[i], *conv) != NULL) {
	    buff[1] = *conv;
	    if (*options[i + 1] == '\0') {  /* one-char conversion specifier? */
		buff[2] = '\0';  /* end buffer */
		return conv + 1;
	    } else if (*(conv + 1) != '\0' && strchr(options[i + 1], *(conv + 1)) != NULL) {
		buff[2] = *(conv + 1);  /* valid two-char conversion specifier */
		buff[3] = '\0';  /* end buffer */
		return conv + 2;
	    }
	}
    }
    luaL_argerror(L, 1, lua_pushfstring(L, "invalid conversion specifier '%%%s'", conv));
    return conv;  /* to avoid warnings */
}


static int os_date(lua_State *L) 
{
    const char *s = luaL_optstring(L, 1, "%c");
    time_t t = luaL_opt(L, (time_t)luaL_checknumber, 2, time(NULL));
    struct tm tmr, *stm;
    if( *s == '!' ) {  /* UTC? */
	stm = gmtime_r(&t, &tmr);
	s++;  /* skip `!' */
    } else {
	stm = localtime_r(&t, &tmr);
    }
    if( stm == NULL ) {  /* invalid date? */
	lua_pushnil(L);
    } else if (strcmp(s, "*t") == 0) {
	lua_createtable(L, 0, 9);  /* 9 = number of fields */
	setfield(L, "sec", stm->tm_sec);
	setfield(L, "min", stm->tm_min);
	setfield(L, "hour", stm->tm_hour);
	setfield(L, "day", stm->tm_mday);
	setfield(L, "month", stm->tm_mon+1);
	setfield(L, "year", stm->tm_year+1900);
	setfield(L, "wday", stm->tm_wday+1);
	setfield(L, "yday", stm->tm_yday+1);
	setboolfield(L, "isdst", stm->tm_isdst);
    } else {
	char cc[4];
	luaL_Buffer b;
	cc[0] = '%';
	luaL_buffinit(L, &b);
	while( *s ) {
	    if( *s != '%' ) { /* no conversion specifier? */
		luaL_addchar(&b, *s++);
	    } else {
		size_t reslen;
		char buff[200];  /* should be big enough for any conversion result */
		s = checkoption(L, s + 1, cc);
		reslen = strftime(buff, sizeof(buff), cc, stm);
		luaL_addlstring(&b, buff, reslen);
	    }
	}
	luaL_pushresult(&b);
    }
    return 1;
}

static int os_time(lua_State *L) 
{
    time_t t;
    if( lua_isnoneornil(L, 1) ) { /* called without args? */
	t = time(NULL);  /* get current time */
    } else {
	struct tm ts;
	luaL_checktype(L, 1, LUA_TTABLE);
	lua_settop(L, 1);  /* make sure table is at the top */
	ts.tm_sec = getfield(L, "sec", 0);
	ts.tm_min = getfield(L, "min", 0);
	ts.tm_hour = getfield(L, "hour", 12);
	ts.tm_mday = getfield(L, "day", -1);
	ts.tm_mon = getfield(L, "month", -1) - 1;
	ts.tm_year = getfield(L, "year", -1) - 1900;
	ts.tm_isdst = getboolfield(L, "isdst");
	t = mktime(&ts);
    }
    if( t == (time_t)(-1) ) {
	lua_pushnil(L);
    } else {
	lua_pushnumber(L, (lua_Number)t);
    }
    return 1;
}

static int os_difftime(lua_State *L) {
  lua_pushnumber(L, difftime((time_t)(luaL_checknumber(L, 1)), (time_t)(luaL_optnumber(L, 2, 0))));
  return 1;
}

static int os_getpid(lua_State *L) 
{
    lua_pushnumber(L, (lua_Number) getpid());
    return 1;
}

static const luaL_Reg lib_funcs[] = {
    { "getpid", os_getpid},
    { "date", os_date},
    { "time", os_time},
    { "difftime", os_difftime},
    { NULL, NULL }
};

LUAMOD_API int luaopen_os(lua_State *L) 
{
    luaL_newlib(L, lib_funcs);
    return 1;
}
