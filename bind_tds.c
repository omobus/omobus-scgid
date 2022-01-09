/* -*- C -*- */
/* Copyright (c) 2006 - 2022 omobus-scgid authors, see the included COPYRIGHT file. */

#include <stdlib.h>
#include <time.h>
#include <memory.h>
#include <sqlfront.h>
#include <sqldb.h>
#include <cstypes.h>

#define LUA_LIB
#include "lua.h"
#include "luaaux.h"

#include "omobus-scgid.h"
#include "package_params.h"

#define LOGIN_METATABLE		"bind_tds login metatable"
#define DBPROC_METATABLE	"bind_tds dbproc metatable"

#define ELOGIN()		luaL_argerror(L, 1, "login is already cleanup or uninitialized")
#define EDBPROC()		luaL_argerror(L, 1, "dbproc is already cleanup or uninitialized")
#define EALLOC()		luaL_argerror(L, 1, "unable to allocate memory")

typedef struct _context_t {
    lua_State *state;
    int msghandle, errhandle;
} context_t;

typedef struct _constant_t {
    const char *name;
    int value;
} constant_t;

static context_t *_dbctx = NULL;

static int l_dbinit(lua_State *L) 
{
    dbinit();
    if( _dbctx == NULL ) {
	if( (_dbctx = (context_t *)malloc(sizeof(context_t))) == NULL ) {
	    return EALLOC();
	}
	_dbctx->state = L;
	_dbctx->msghandle = LUA_NOREF;
	_dbctx->errhandle = LUA_NOREF;
    }
    return 0;
}

static int l_dbsetifile(lua_State *L) 
{
    dbsetifile((char *)luaL_checkstring(L,1));
    return 0;
}

static int l_dbexit(lua_State *L) 
{
    if( _dbctx != NULL ) {
	if( _dbctx->state != NULL ) {
	    if( _dbctx->msghandle != LUA_NOREF ) {
		luaL_unref(_dbctx->state, LUA_REGISTRYINDEX, _dbctx->msghandle);
	    }
	    if( _dbctx->errhandle != LUA_NOREF ) {
		luaL_unref(_dbctx->state, LUA_REGISTRYINDEX, _dbctx->errhandle);
	    }
	}
	free(_dbctx);
	_dbctx = NULL;
    }
    dbexit();
    return 0;
}

static
int message_handler(DBPROCESS *dbproc, DBINT msgno, int msgstate, int severity,
    char *msgtext, char *srvname, char *procname, int line)
{
    if( _dbctx != NULL && _dbctx->state != NULL && _dbctx->msghandle != LUA_NOREF ) {
	lua_rawgeti(_dbctx->state, LUA_REGISTRYINDEX, _dbctx->msghandle); 
	lua_pushinteger(_dbctx->state, msgno);
	lua_pushinteger(_dbctx->state, msgstate);
	lua_pushinteger(_dbctx->state, severity);
	lua_pushstring(_dbctx->state, msgtext);
	lua_pushstring(_dbctx->state, srvname);
	lua_pushstring(_dbctx->state, procname);
	lua_pushinteger(_dbctx->state, line);
	lua_call(_dbctx->state, 7, 0);
    }
    return 0;
}

static int l_dbmsghandle(lua_State *L)
{
    if( _dbctx != NULL ) {
	if( _dbctx->state == NULL ) {
	    _dbctx->state = L;
	}
	if( !lua_isfunction(L, 1) ) {
	    return luaL_argerror(L, 1, lua_pushfstring(L, "function expected, got %s", lua_typename(L, 1)));
	}
	if( _dbctx->msghandle != LUA_NOREF ) {
	    luaL_unref(L, LUA_REGISTRYINDEX, _dbctx->msghandle);
	}
	_dbctx->msghandle = luaL_ref(L, LUA_REGISTRYINDEX);
	dbmsghandle(message_handler);
    }
    return 0;
}

static
int error_handler(DBPROCESS *dbproc, int severity, int dberr, int oserr,
    char *dberrstr, char *oserrstr)
{
    if( _dbctx != NULL && _dbctx->state != NULL && _dbctx->errhandle != LUA_NOREF ) {
	lua_rawgeti(_dbctx->state, LUA_REGISTRYINDEX, _dbctx->errhandle); 
	lua_pushinteger(_dbctx->state, severity);
	lua_pushinteger(_dbctx->state, dberr);
	lua_pushinteger(_dbctx->state, oserr);
	lua_pushstring(_dbctx->state, dberrstr);
	lua_pushstring(_dbctx->state, oserrstr);
	lua_call(_dbctx->state, 5, 0);
    }
    return INT_CANCEL;
}

static int l_dberrhandle(lua_State *L)
{
    if( _dbctx != NULL ) {
	if( _dbctx->state == NULL ) {
	    _dbctx->state = L;
	}
	if( !lua_isfunction(L, 1) ) {
	    return luaL_argerror(L, 1, lua_pushfstring(L, "function expected, got %s", lua_typename(L, 1)));
	}
	if( _dbctx->errhandle != LUA_NOREF ) {
	    luaL_unref(L, LUA_REGISTRYINDEX, _dbctx->errhandle);
	}
	_dbctx->errhandle = luaL_ref(L, LUA_REGISTRYINDEX);
	dberrhandle(error_handler);
    }
    return 0;
}

static int l_dblogin(lua_State *L)
{
    LOGINREC *login, **data;
    if( (login = dblogin()) != NULL ) {
	data = (LOGINREC**) lua_newuserdata(L, sizeof(LOGINREC*));
	*data = login;
	luaL_getmetatable(L, LOGIN_METATABLE);
	lua_setmetatable(L, -2);
    } else {
	lua_pushnil(L);
    }
    return 1;
}

static int l_dbfreelogin(lua_State *L)
{
    LOGINREC **login;
    login = (LOGINREC **)luaL_checkudata(L, 1, LOGIN_METATABLE);
    if( *login != NULL ) {
	dbfreelogin(*login);
	*login = NULL;
    }
    return 0;
}

static int l_dbsetluser(lua_State *L)
{
    LOGINREC *login;
    if( (login = *(LOGINREC **)luaL_checkudata(L, 1, LOGIN_METATABLE)) == NULL ) {
	return ELOGIN();
    }
    DBSETLUSER(login, luaL_checkstring(L, 2));
    return 0;
}

static int l_dbsetlpwd(lua_State *L)
{
    LOGINREC *login;
    if( (login = *(LOGINREC **)luaL_checkudata(L, 1, LOGIN_METATABLE)) == NULL ) {
	return ELOGIN();
    }
    DBSETLPWD(login, luaL_checkstring(L, 2));
    return 0;
}

static int l_dbsetlhost(lua_State *L)
{
    LOGINREC *login;
    if( (login = *(LOGINREC **)luaL_checkudata(L, 1, LOGIN_METATABLE)) == NULL ) {
	return ELOGIN();
    }
    DBSETLHOST(login, luaL_checkstring(L, 2));
    return 0;
}

static int l_dbsetlapp(lua_State *L)
{
    LOGINREC *login;
    if( (login = *(LOGINREC **)luaL_checkudata(L, 1, LOGIN_METATABLE)) == NULL ) {
	return ELOGIN();
    }
    DBSETLAPP(login, luaL_checkstring(L, 2));
    return 0;
}

/*static int l_dbsetltime(lua_State *L)
{
    LOGINREC *login;
    if( (login = *(LOGINREC **)luaL_checkudata(L, 1, LOGIN_METATABLE)) == NULL ) {
	return ELOGIN();
    }
    DBSETLAPP(login, luaL_checkinteger(L, 2));
    return 0;
}*/

static int l_dbsetlsecure(lua_State *L)
{
    LOGINREC *login;
    if( (login = *(LOGINREC **)luaL_checkudata(L, 1, LOGIN_METATABLE)) == NULL ) {
	return ELOGIN();
    }
    return 0;
}

static int l_dbopen(lua_State *L)
{
    LOGINREC *login;
    DBPROCESS *dbproc, **data;
    if( (login = *(LOGINREC **)luaL_checkudata(L, 1, LOGIN_METATABLE)) == NULL ) {
	return ELOGIN();
    }
    if( (dbproc = dbopen(login, luaL_checkstring(L, 2))) != NULL ) {
	data = (DBPROCESS**) lua_newuserdata(L, sizeof(DBPROCESS*));
	*data = dbproc;
	luaL_getmetatable(L, DBPROC_METATABLE);
	lua_setmetatable(L, -2);
    } else {
	lua_pushnil(L);
    }
    return 1;
}

static int l_dbclose(lua_State *L)
{
    DBPROCESS **dbproc;
    dbproc = (DBPROCESS **)luaL_checkudata(L, 1, DBPROC_METATABLE);
    if( *dbproc != NULL ) {
	dbclose(*dbproc);
	*dbproc = NULL;
    }
    return 0;
}

static int l_dbdead(lua_State *L)
{
    DBPROCESS *dbproc;
    if( (dbproc = *(DBPROCESS **)luaL_checkudata(L, 1, DBPROC_METATABLE)) == NULL ) {
	return EDBPROC();
    }
    lua_pushboolean(L, dbdead(dbproc));
    return 1;
}

static int l_dbuse(lua_State *L)
{
    DBPROCESS *dbproc;
    if( (dbproc = *(DBPROCESS **)luaL_checkudata(L, 1, DBPROC_METATABLE)) == NULL ) {
	return EDBPROC();
    }
    lua_pushinteger(L, dbuse(dbproc, luaL_checkstring(L, 2)));
    return 1;
}

static int l_dbfreebuf(lua_State *L)
{
    DBPROCESS *dbproc;
    if( (dbproc = *(DBPROCESS **)luaL_checkudata(L, 1, DBPROC_METATABLE)) == NULL ) {
	return EDBPROC();
    }
    dbfreebuf(dbproc);
    return 0;
}

static int l_dbcmd(lua_State *L)
{
    DBPROCESS *dbproc;
    if( (dbproc = *(DBPROCESS **)luaL_checkudata(L, 1, DBPROC_METATABLE)) == NULL ) {
	return EDBPROC();
    }
    lua_pushinteger(L, dbcmd(dbproc, luaL_checkstring(L, 2)));
    return 1;
}

static int l_dbsqlexec(lua_State *L)
{
    DBPROCESS *dbproc;
    if( (dbproc = *(DBPROCESS **)luaL_checkudata(L, 1, DBPROC_METATABLE)) == NULL ) {
	return EDBPROC();
    }
    lua_pushinteger(L, dbsqlexec(dbproc));
    return 1;
}

static int l_dbsqlsend(lua_State *L)
{
    DBPROCESS *dbproc;
    if( (dbproc = *(DBPROCESS **)luaL_checkudata(L, 1, DBPROC_METATABLE)) == NULL ) {
	return EDBPROC();
    }
    lua_pushinteger(L, dbsqlsend(dbproc));
    return 1;
}

static int l_dbsqlok(lua_State *L)
{
    DBPROCESS *dbproc;
    if( (dbproc = *(DBPROCESS **)luaL_checkudata(L, 1, DBPROC_METATABLE)) == NULL ) {
	return EDBPROC();
    }
    lua_pushinteger(L, dbsqlok(dbproc));
    return 1;
}

static int l_dbresults(lua_State *L)
{
    DBPROCESS *dbproc;
    if( (dbproc = *(DBPROCESS **)luaL_checkudata(L, 1, DBPROC_METATABLE)) == NULL ) {
	return EDBPROC();
    }
    lua_pushinteger(L, dbresults(dbproc));
    return 1;
}

static int l_dbcancel(lua_State *L)
{
    DBPROCESS *dbproc;
    if( (dbproc = *(DBPROCESS **)luaL_checkudata(L, 1, DBPROC_METATABLE)) == NULL ) {
	return EDBPROC();
    }
    lua_pushinteger(L, dbcancel(dbproc));
    return 1;
}

static int l_dbcanquery(lua_State *L)
{
    DBPROCESS *dbproc;
    if( (dbproc = *(DBPROCESS **)luaL_checkudata(L, 1, DBPROC_METATABLE)) == NULL ) {
	return EDBPROC();
    }
    lua_pushinteger(L, dbcanquery(dbproc));
    return 1;
}

static int l_dbnextrow(lua_State *L)
{
    DBPROCESS *dbproc;
    if( (dbproc = *(DBPROCESS **)luaL_checkudata(L, 1, DBPROC_METATABLE)) == NULL ) {
	return EDBPROC();
    }
    lua_pushinteger(L, dbnextrow(dbproc));
    return 1;
}

static int l_dbgetrow(lua_State *L)
{
    DBPROCESS *dbproc;
    if( (dbproc = *(DBPROCESS **)luaL_checkudata(L, 1, DBPROC_METATABLE)) == NULL ) {
	return EDBPROC();
    }
    lua_pushinteger(L, dbgetrow(dbproc, luaL_checkinteger(L, 2)));
    return 1;
}

static int l_dbclrbuf(lua_State *L)
{
    DBPROCESS *dbproc;
    if( (dbproc = *(DBPROCESS **)luaL_checkudata(L, 1, DBPROC_METATABLE)) == NULL ) {
	return EDBPROC();
    }
    dbclrbuf(dbproc, luaL_checkinteger(L, 2));
    return 0;
}

static int l_dbnumcols(lua_State *L)
{
    DBPROCESS *dbproc;
    if( (dbproc = *(DBPROCESS **)luaL_checkudata(L, 1, DBPROC_METATABLE)) == NULL ) {
	return EDBPROC();
    }
    lua_pushinteger(L, dbnumcols(dbproc));
    return 1;
}

static int l_dbcolname(lua_State *L)
{
    DBPROCESS *dbproc;
    if( (dbproc = *(DBPROCESS **)luaL_checkudata(L, 1, DBPROC_METATABLE)) == NULL ) {
	return EDBPROC();
    }
    lua_pushstring(L, dbcolname(dbproc, luaL_checkinteger(L, 2)));
    return 1;
}

static int l_dbcollen(lua_State *L)
{
    DBPROCESS *dbproc;
    if( (dbproc = *(DBPROCESS **)luaL_checkudata(L, 1, DBPROC_METATABLE)) == NULL ) {
	return EDBPROC();
    }
    lua_pushinteger(L, dbcollen(dbproc, luaL_checkinteger(L, 2)));
    return 1;
}

static int l_dbcoltype(lua_State *L)
{
    DBPROCESS *dbproc;
    if( (dbproc = *(DBPROCESS **)luaL_checkudata(L, 1, DBPROC_METATABLE)) == NULL ) {
	return EDBPROC();
    }
    lua_pushinteger(L, dbcoltype(dbproc, luaL_checkinteger(L, 2)));
    return 1;
}

static int l_dbcolutype(lua_State *L)
{
    DBPROCESS *dbproc;
    if( (dbproc = *(DBPROCESS **)luaL_checkudata(L, 1, DBPROC_METATABLE)) == NULL ) {
	return EDBPROC();
    }
    lua_pushinteger(L, dbcolutype(dbproc, luaL_checkinteger(L, 2)));
    return 1;
}

static int l_dbdatlen(lua_State *L)
{
    DBPROCESS *dbproc;
    if( (dbproc = *(DBPROCESS **)luaL_checkudata(L, 1, DBPROC_METATABLE)) == NULL ) {
	return EDBPROC();
    }
    lua_pushinteger(L, dbdatlen(dbproc, luaL_checkinteger(L, 2)));
    return 1;
}

static int l_dbdata(lua_State *L)
{
    DBPROCESS *dbproc;
    int column;
    BYTE *byteptr;
    if( (dbproc = *(DBPROCESS **)luaL_checkudata(L, 1, DBPROC_METATABLE)) == NULL ) {
	return EDBPROC();
    }
    column = luaL_checkinteger(L, 2);
    if( (byteptr = dbdata(dbproc, column)) == NULL ) {
	lua_pushnil(L);
    } else {
	lua_pushlstring(L, (const char *)byteptr, dbdatlen(dbproc, column));
    }
    return 1;
}

static int l_dbadlen(lua_State *L)
{
    DBPROCESS *dbproc;
    if( (dbproc = *(DBPROCESS **)luaL_checkudata(L, 1, DBPROC_METATABLE)) == NULL ) {
	return EDBPROC();
    }
    lua_pushinteger(L, dbadlen(dbproc, luaL_checkinteger(L, 2), luaL_checkinteger(L, 3)));
    return 1;
}

static int l_dbadata(lua_State *L)
{
    DBPROCESS *dbproc;
    int computeid, column;
    BYTE *byteptr;
    if( (dbproc = *(DBPROCESS **)luaL_checkudata(L, 1, DBPROC_METATABLE)) == NULL ) {
	return EDBPROC();
    }
    computeid = luaL_checkinteger(L, 2);
    column = luaL_checkinteger(L, 3);
    if( (byteptr = dbadata(dbproc, computeid, column)) == NULL ) {
	lua_pushnil(L);
    } else {
	lua_pushlstring(L, (const char *)byteptr, dbadlen(dbproc, computeid, column));
    }
    return 1;
}

static int l_dbalttype(lua_State *L)
{
    DBPROCESS *dbproc;
    if( (dbproc = *(DBPROCESS **)luaL_checkudata(L, 1, DBPROC_METATABLE)) == NULL ) {
	return EDBPROC();
    }
    lua_pushinteger(L, dbalttype(dbproc, luaL_checkinteger(L, 2), luaL_checkinteger(L, 3)));
    return 1;
}

static int l_dbaltutype(lua_State *L)
{
    DBPROCESS *dbproc;
    if( (dbproc = *(DBPROCESS **)luaL_checkudata(L, 1, DBPROC_METATABLE)) == NULL ) {
	return EDBPROC();
    }
    lua_pushinteger(L, dbaltutype(dbproc, luaL_checkinteger(L, 2), luaL_checkinteger(L, 3)));
    return 1;
}

static int l_dbaltop(lua_State *L)
{
    DBPROCESS *dbproc;
    if( (dbproc = *(DBPROCESS **)luaL_checkudata(L, 1, DBPROC_METATABLE)) == NULL ) {
	return EDBPROC();
    }
    lua_pushinteger(L, dbaltop(dbproc, luaL_checkinteger(L, 2), luaL_checkinteger(L, 3)));
    return 1;
}

static int l_dbaltcolid(lua_State *L)
{
    DBPROCESS *dbproc;
    if( (dbproc = *(DBPROCESS **)luaL_checkudata(L, 1, DBPROC_METATABLE)) == NULL ) {
	return EDBPROC();
    }
    lua_pushinteger(L, dbaltcolid(dbproc, luaL_checkinteger(L, 2), luaL_checkinteger(L, 3)));
    return 1;
}

static int l_dbtds(lua_State *L)
{
    DBPROCESS *dbproc;
    if( (dbproc = *(DBPROCESS **)luaL_checkudata(L, 1, DBPROC_METATABLE)) == NULL ) {
	return EDBPROC();
    }
    lua_pushinteger(L, dbtds(dbproc));
    return 1;
}

static int l_dbconvert(lua_State *L)
{
    DBPROCESS *dbproc;
    int coltype; 
    size_t len;
    const char *ptr;
    double dbl;

    if( (dbproc = *(DBPROCESS **)luaL_checkudata(L, 1, DBPROC_METATABLE)) == NULL ) {
	return EDBPROC();
    }
    coltype = luaL_checkinteger(L, 2);
    ptr = luaL_checklstring(L, 3, &len);
    if( len == 0 || ptr == NULL ) {
	lua_pushnil(L);
    } else if( coltype == SYBVARCHAR ) {
	if( sizeof(DBVARYCHAR) > len ) {
	    luaL_error(L, "input data is not a DBVARYCHAR");
	} else {
	    lua_pushlstring(L, ((DBVARYCHAR *)ptr)->str, ((DBVARYCHAR *)ptr)->len);
	}
    } else if( coltype == SYBVARBINARY ) {
	if( sizeof(CS_VARBINARY) > len ) {
	    luaL_error(L, "input data is not a CS_VARBINARY");
	} else {
	    lua_pushlstring(L, ((CS_VARBINARY *)ptr)->array, ((CS_VARBINARY *)ptr)->len);
	}
    } else if( coltype == SYBINT1 || coltype == SYBINT2 || coltype == SYBINT4 || coltype == SYBMONEY4 ) {
	if( len == sizeof(char) ) {
	    lua_pushinteger(L, *((char *)ptr));
	} else if( len == sizeof(short) ) {
	    lua_pushinteger(L, *((short *)ptr));
	} else if( len == sizeof(int32_t) ) {
	    lua_pushinteger(L, *((int32_t *)ptr));
	} else {
	    luaL_error(L, "input data is not a integer (input len: %d bytes)", len);
	}
    } else if( coltype == SYBFLT8 ) {
	if( len == sizeof(float) ) {
	    lua_pushnumber(L, *((float *)ptr));
	} else if( len == sizeof(double) ) {
	    lua_pushnumber(L, *((double *)ptr));
	} else {
	    luaL_error(L, "input data is not a double (input len: %d bytes)", len);
	}
    } else if( coltype == SYBMONEY ) {
	dbl = 0.0;
	if( dbconvert(dbproc, coltype, (BYTE *)ptr, len, SYBFLT8, (BYTE *)&dbl, sizeof(dbl)) == -1 ) {
	    luaL_error(L, "unable to convert SYBMONEY to SYBFLT8");
	} else {
	    lua_pushnumber(L, dbl);
	}
    } else if( coltype == SYBNUMERIC ) {
	dbl = 0.0;
	if( dbconvert(dbproc, coltype, (BYTE *)ptr, len, SYBFLT8, (BYTE *)&dbl, sizeof(dbl)) == -1 ) {
	    luaL_error(L, "unable to convert SYBNUMERIC to SYBFLT8");
	} else {
	    lua_pushnumber(L, dbl);
	}
    } else if( coltype == SYBDECIMAL ) {
	dbl = 0.0;
	if( dbconvert(dbproc, coltype, (BYTE *)ptr, len, SYBFLT8, (BYTE *)&dbl, sizeof(dbl)) == -1 ) {
	    luaL_error(L, "unable to convert SYBDECIMAL to SYBFLT8");
	} else {
	    lua_pushnumber(L, dbl);
	}
    } else if( coltype == SYBDATETIME ) {
	struct tm t; DBDATEREC ts; char buf[64];
	memset(&t, 0, sizeof(t));
	memset(&ts, 0, sizeof(ts));
	memset(buf, 0, sizeof(buf));
	dbdatecrack(dbproc, &ts, (DBDATETIME *)ptr);
	t.tm_year = ts.dateyear - 1900;
	t.tm_mon = ts.datemonth;
	t.tm_mday = ts.datedmonth;
	t.tm_hour = ts.datehour;
	t.tm_min = ts.dateminute;
	t.tm_sec = ts.datesecond;
	t.tm_yday = ts.datedyear - 1;
	t.tm_wday = ts.datedweek;
	t.tm_isdst = -1;
	mktime(&t);
	strftime(buf, charbufsize(buf), "%Y-%m-%d %H:%M:%S", &t);
	lua_pushstring(L, buf);
    } else {
	luaL_error(L, "unknown input data type: %d", coltype);
    }
    return 1;
}

static const luaL_Reg global_funcs[] = {
    { "dbinit", l_dbinit },
    { "dbexit", l_dbexit },
    { "dbsetifile", l_dbsetifile },
    { "dbmsghandle", l_dbmsghandle },
    { "dberrhandle", l_dberrhandle },
    { "dblogin", l_dblogin },
    { NULL, NULL }
};

static const luaL_Reg login_funcs[] = {
    { "dbfreelogin", l_dbfreelogin },
    { "dbsetluser", l_dbsetluser },
    { "dbsetlpwd", l_dbsetlpwd },
    { "dbsetlhost", l_dbsetlhost },
    { "dbsetlapp", l_dbsetlapp },
    /*{ "dbsetltime", l_dbsetltime },*/
    { "dbsetlsecure", l_dbsetlsecure },
    { "dbopen", l_dbopen },
    { NULL, NULL }
};

static const luaL_Reg dbproc_funcs[] = {
    { "dbclose", l_dbclose },
    { "dbdead", l_dbdead },
    { "dbuse", l_dbuse },
    { "dbfreebuf", l_dbfreebuf },
    { "dbcmd", l_dbcmd },
    { "dbsqlexec", l_dbsqlexec },
    { "dbsqlsend", l_dbsqlsend },
    { "dbsqlok", l_dbsqlok },
    { "dbresults", l_dbresults },
    { "dbcancel", l_dbcancel },
    { "dbcanquery", l_dbcanquery },
    { "dbnextrow", l_dbnextrow },
    { "dbgetrow", l_dbgetrow },
    { "dbclrbuf", l_dbclrbuf },
    { "dbnumcols", l_dbnumcols },
    { "dbcolname", l_dbcolname },
    { "dbcollen", l_dbcollen },
    { "dbcoltype", l_dbcoltype },
    { "dbcolutype", l_dbcolutype },
    { "dbdatlen", l_dbdatlen },
    { "dbdata", l_dbdata },
    { "dbadlen", l_dbadlen },
    { "dbadata", l_dbadata },
    { "dbalttype", l_dbalttype },
    { "dbaltutype", l_dbaltutype },
    { "dbaltop", l_dbaltop },
    { "dbaltcolid", l_dbaltcolid },
    { "dbtds", l_dbtds },
    { "dbconvert", l_dbconvert },
    { NULL, NULL }
};

static constant_t constants[] = {
    { "SUCCEED", SUCCEED },
    { "FAIL", FAIL },
    { "DBNOERR", DBNOERR },
    { "NO_MORE_RESULTS", NO_MORE_RESULTS },
    { "REG_ROW", REG_ROW },
    { "NO_MORE_ROWS", NO_MORE_ROWS },
    { "BUF_FULL", BUF_FULL },
    { "SYBCHAR", SYBCHAR },
    { "SYBTEXT", SYBTEXT },
    { "SYBVARCHAR", SYBVARCHAR },
    { "SYBIMAGE", SYBIMAGE },
    { "SYBBINARY", SYBBINARY },
    { "SYBVARBINARY", SYBVARBINARY },
    { "SYBINT1", SYBINT1 },
    { "SYBINT2", SYBINT2 },
    { "SYBINT4", SYBINT4 },
    { "SYBMONEY4", SYBMONEY4 },
    { "SYBFLT8", SYBFLT8 },
    { "SYBMONEY", SYBMONEY },
    { "SYBNUMERIC", SYBNUMERIC },
    { "SYBDECIMAL", SYBDECIMAL },
    { "SYBDATETIME", SYBDATETIME },
    { "SYBAOPSUM", SYBAOPSUM },
    { "SYBAOPAVG", SYBAOPAVG },
    { "SYBAOPCNT", SYBAOPCNT },
    { "SYBAOPMIN", SYBAOPMIN },
    { "SYBAOPMAX", SYBAOPMAX },
    { NULL, 0 }
};

LUAMOD_API int luaopen_bind_tds(lua_State *L)
{
    luaL_newmetatable(L, LOGIN_METATABLE);
    luaL_setfuncs(L, login_funcs, 0);
    /* define metamethods */
    lua_pushliteral(L, "__gc");
    lua_pushcfunction(L, l_dbfreelogin);
    lua_settable(L, -3);
    lua_pushliteral(L, "__index");
    lua_pushvalue(L, -2);
    lua_settable(L, -3);
    lua_pushliteral(L, "__metatable");
    lua_pushliteral(L, "bind_tds: you're not allowed to get this metatable");
    lua_settable(L, -3);

    luaL_newmetatable(L, DBPROC_METATABLE);
    luaL_setfuncs(L, dbproc_funcs, 0);
    /* define metamethods */
    lua_pushliteral(L, "__gc");
    lua_pushcfunction(L, l_dbclose);
    lua_settable(L, -3);
    lua_pushliteral(L, "__index");
    lua_pushvalue(L, -2);
    lua_settable(L, -3);
    lua_pushliteral(L, "__metatable");
    lua_pushliteral(L, "bind_tds: you're not allowed to get this metatable");
    lua_settable(L, -3);

    luaL_newlib(L, global_funcs);

    lua_pushliteral(L, "_VERSION");
    lua_pushliteral(L, PACKAGE_VERSION);
    lua_settable(L, -3);

    for( int n = 0; constants[n].name != NULL; n++ ) {
	lua_pushinteger(L, constants[n].value);
	lua_setfield(L, -2, constants[n].name);
    }

    return 1;
}
