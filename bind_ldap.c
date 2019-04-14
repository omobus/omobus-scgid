/* -*- C -*- */
/* Copyright (c) 2006 - 2019 omobus-scgid authors, see the included COPYRIGHT file. */

#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <lber.h>
#include <ldap.h>

#include "package_params.h"
#define LUA_LIB
#include "lua.h"
#include "luaaux.h"

/* Original code created by Roberto Ierusalimschy, Andr&eacute; Carregal and 
 * Tom&aacute;s Guisasola.
 * http://www.keplerproject.org/lualdap/
 */

#define LUALDAP_PREFIX			"bind_ldap: "
#define LUALDAP_CONNECTION_METATABLE	"bind_ldap connection"
#define LUALDAP_SEARCH_METATABLE	"bind_ldap search"

#define LUALDAP_MOD_ADD (LDAP_MOD_ADD | LDAP_MOD_BVALUES)
#define LUALDAP_MOD_DEL (LDAP_MOD_DELETE | LDAP_MOD_BVALUES)
#define LUALDAP_MOD_REP (LDAP_MOD_REPLACE | LDAP_MOD_BVALUES)
#define LUALDAP_NO_OP   0

/* Maximum number of attributes manipulated in an operation */
#ifndef LUALDAP_MAX_ATTRS
#define LUALDAP_MAX_ATTRS 100
#endif

/* Size of buffer of NULL-terminated arrays of pointers to struct values */
#ifndef LUALDAP_ARRAY_VALUES_SIZE
#define LUALDAP_ARRAY_VALUES_SIZE (2 * LUALDAP_MAX_ATTRS)
#endif

/* Maximum number of values structures */
#ifndef LUALDAP_MAX_VALUES
#define LUALDAP_MAX_VALUES (LUALDAP_ARRAY_VALUES_SIZE / 2)
#endif

/* LDAP connection information */
typedef struct _conn_data_t {
    int version; /* LDAP version */
    LDAP *ld;    /* LDAP connection */
} conn_data_t;

/* LDAP search context information */
typedef struct _search_data_t {
    int conn; /* connection ref */
    int msgid;
} search_data_t;

/* LDAP attribute modification structure */
typedef struct _attrs_data_t {
    LDAPMod *attrs[LUALDAP_MAX_ATTRS + 1], mods[LUALDAP_MAX_ATTRS];
    int ai;
    BerValue *values[LUALDAP_ARRAY_VALUES_SIZE];
    int vi;
    BerValue bvals[LUALDAP_MAX_VALUES];
    int bi;
} attrs_data_t;


static int faildirect(lua_State *L, const char *errmsg) {
    lua_pushnil(L);
    lua_pushstring (L, errmsg);
    return 2;
}

/* Get a connection object from the first stack position. */
static conn_data_t *getconnection(lua_State *L) {
    conn_data_t *conn = (conn_data_t *) luaL_checkudata (L, 1, LUALDAP_CONNECTION_METATABLE);
    luaL_argcheck(L, conn != NULL, 1, LUALDAP_PREFIX "LDAP connection expected");
    luaL_argcheck(L, conn->ld, 1, LUALDAP_PREFIX "LDAP connection is closed");
    return conn;
}

/* Get a search object from the first upvalue position. */
static search_data_t *getsearch(lua_State *L) {
    /* don't need to check upvalue's integrity */
    search_data_t *search = (search_data_t *) lua_touserdata (L, lua_upvalueindex(1));
    luaL_argcheck(L, search->conn != LUA_NOREF, 1, LUALDAP_PREFIX "LDAP search is closed");
    return search;
}

/* Set metatable of userdata on top of the stack. */
static void lualdap_setmeta(lua_State *L, const char *name) {
    luaL_getmetatable (L, name);
    lua_setmetatable (L, -2);
}

/* Error on option. */
static int option_error(lua_State *L, const char *name, const char *type) {
    return luaL_error(L, LUALDAP_PREFIX "invalid value on option `%s': %s expected, got %s", name, type, lua_typename (L, lua_type (L, -1)));
}

/* Get the field called name of the table at position 2. */
static void strgettable(lua_State *L, const char *name) {
    lua_pushstring (L, name);
    lua_gettable (L, 2);
}

/* Get the field named name as a string. The table MUST be at position 2. */
static const char *strtabparam(lua_State *L, const char *name, char *def) {
    strgettable (L, name);
    if( lua_isnil (L, -1) ) {
	return def;
    } else if( lua_isstring(L, -1) ) {
	return lua_tostring(L, -1);
    } else {
	option_error(L, name, "string");
	return NULL;
    }
}

/* Get the field named name as an integer. The table MUST be at position 2. */
static long longtabparam(lua_State *L, const char *name, int def) {
    strgettable (L, name);
    if( lua_isnil(L, -1) ) {
	return def;
    } else if( lua_isnumber(L, -1) ) {
	return (long)lua_tonumber (L, -1);
    } else {
	return option_error(L, name, "number");
    }
}

/* Get the field named name as a double. The table MUST be at position 2. */
static double numbertabparam(lua_State *L, const char *name, double def) {
    strgettable (L, name);
    if( lua_isnil(L, -1) ) {
	return def;
    } else if( lua_isnumber(L, -1) ) {
	return lua_tonumber(L, -1);
    } else {
	return option_error(L, name, "number");
    }
}

/* Get the field named name as a boolean. The table MUST be at position 2. */
static int booltabparam(lua_State *L, const char *name, int def) {
    strgettable(L, name);
    if( lua_isnil(L, -1) ) {
	return def;
    } else if( lua_isboolean(L, -1) ) {
	return lua_toboolean(L, -1);
    } else {
	return option_error(L, name, "boolean");
    }
}

/* Error on attribute's value. */
static void value_error(lua_State *L, const char *name) {
    luaL_error(L, LUALDAP_PREFIX"invalid value of attribute `%s'(%s)", 
	name, lua_typename(L, lua_type(L, -1)));
}

/* Initialize attributes structure. */
static void A_init(attrs_data_t *attrs) {
    attrs->ai = 0;
    attrs->attrs[0] = NULL;
    attrs->vi = 0;
    attrs->values[0] = NULL;
    attrs->bi = 0;
}

/* Store the string on top of the stack on the attributes structure. Increment the bvals counter. */
static BerValue *A_setbval(lua_State *L, attrs_data_t *a, const char *n) {
    BerValue *ret = &(a->bvals[a->bi]);
    if(a->bi >= LUALDAP_MAX_VALUES) {
	luaL_error(L, LUALDAP_PREFIX "too many values");
	return NULL;
    } else if(!lua_isstring(L, -1)) {
	value_error(L, n);
	return NULL;
    }
    a->bvals[a->bi].bv_len = lua_rawlen(L, -1);
    a->bvals[a->bi].bv_val =(char *)lua_tostring(L, -1);
    a->bi++;
    return ret;
}

/* Store a pointer to the value on top of the stack on the attributes structure. */
static BerValue **A_setval(lua_State *L, attrs_data_t *a, const char *n) {
    BerValue **ret = &(a->values[a->vi]);
    if(a->vi >= LUALDAP_ARRAY_VALUES_SIZE) {
	luaL_error(L, LUALDAP_PREFIX "too many values");
	return NULL;
    }
    a->values[a->vi] = A_setbval(L, a, n);
    a->vi++;
    return ret;
}

/* Store a NULL pointer on the attributes structure. */
static BerValue **A_nullval(lua_State *L, attrs_data_t *a) {
    BerValue **ret = &(a->values[a->vi]);
    if(a->vi >= LUALDAP_ARRAY_VALUES_SIZE) {
	luaL_error(L, LUALDAP_PREFIX"too many values");
	return NULL;
    }
    a->values[a->vi] = NULL;
    a->vi++;
    return ret;
}

/* Store the value of an attribute. Valid values are:
 *	true => no values;
 *	string => one value; or
 *	table of strings => many values.
*/
static BerValue **A_tab2val(lua_State *L, attrs_data_t *a, const char *name) {
    int tab = lua_gettop(L);
    BerValue **ret = &(a->values[a->vi]);
    if(lua_isboolean(L, tab) &&(lua_toboolean(L, tab) == 1)) /* true */
	return NULL;
    else if(lua_isstring(L, tab)) /* string */
	A_setval(L, a, name);
    else if(lua_istable(L, tab)) { /* list of strings */
	int i;
	int n = lua_rawlen(L, tab);
	for(i = 1; i <= n; i++) {
	    lua_rawgeti(L, tab, i); /* push table element */
	    A_setval(L, a, name);
	}
	lua_pop(L, n);
    } else {
	value_error(L, name);
	return NULL;
    }
    A_nullval(L, a);
    return ret;
}

/* Set a modification value(which MUST be on top of the stack). */
static void A_setmod(lua_State *L, attrs_data_t *a, int op, const char *name) {
    if( a->ai >= LUALDAP_MAX_ATTRS ) {
	luaL_error(L, LUALDAP_PREFIX"too many attributes");
	return;
    }
    a->mods[a->ai].mod_op = op;
    a->mods[a->ai].mod_type =(char *)name;
    a->mods[a->ai].mod_bvalues = A_tab2val(L, a, name);
    a->attrs[a->ai] = &a->mods[a->ai];
    a->ai++;
}

/* Convert a Lua table into an array of modifications.
   An array of modifications is a NULL-terminated array of LDAPMod's. */
static void A_tab2mod(lua_State *L, attrs_data_t *a, int tab, int op) {
    lua_pushnil(L); /* first key for lua_next */
    while( lua_next(L, tab) != 0 ) {
	/* attribute must be a string and not a number */
	if( (!lua_isnumber(L, -2)) && (lua_isstring(L, -2)) ) {
	    A_setmod(L, a, op, lua_tostring(L, -2));
	}
	/* pop value and leave last key on the stack as next key for lua_next */
	lua_pop(L, 1);
    }
}

/* Terminate the array of attributes. */
static void A_lastattr(lua_State *L, attrs_data_t *a) {
    if(a->ai >= LUALDAP_MAX_ATTRS) {
	luaL_error(L, LUALDAP_PREFIX "too many attributes");
	return;
    }
    a->attrs[a->ai] = NULL;
    a->ai++;
}

/* Copy a string or a table of strings from Lua to a NULL-terminated array of C-strings. */
static int table2strarray(lua_State *L, int tab, char *array[], int limit) {
    if(lua_isstring(L, tab)) {
	if( limit < 2 ) {
	    return luaL_error(L, LUALDAP_PREFIX "too many arguments");
	}
	array[0] = (char *)lua_tostring(L, tab);
	array[1] = NULL;
    } else if(lua_istable(L, tab)) {
	int i, n = lua_rawlen(L, tab);
	if( limit < (n+1) ) {
	    return luaL_error(L, LUALDAP_PREFIX "too many arguments");
	}
	for( i = 0; i < n; i++ ) {
	    lua_rawgeti(L, tab, i+1); /* push table element */
	    if(lua_isstring(L, -1)) {
		array[i] =(char *)lua_tostring(L, -1);
	    } else {
		return luaL_error(L, LUALDAP_PREFIX"invalid value #%d", i+1);
	    }
	}
	array[n] = NULL;
    } else {
	return luaL_error(L, LUALDAP_PREFIX"bad argument #%d(table or string expected, got %s)", tab, lua_typename(L, lua_type(L, tab)));
    }
    return 0;
}

/* Get the result message of an operation.
 *	#1 upvalue == connection
 *	#2 upvalue == msgid
 *	#3 upvalue == result code of the message(ADD, DEL etc.) to be received.
*/
static int result_message(lua_State *L) {
    struct timeval *timeout = NULL; /* ??? function parameter ??? */
    LDAPMessage *res;
    int rc;
    conn_data_t *conn =(conn_data_t *)lua_touserdata(L, lua_upvalueindex(1));
    int msgid =(int)lua_tonumber(L, lua_upvalueindex(2));

    luaL_argcheck(L, conn->ld, 1, LUALDAP_PREFIX "LDAP connection is closed");
    rc = ldap_result(conn->ld, msgid, LDAP_MSG_ONE, timeout, &res);
    if(rc == 0) {
	return faildirect(L, LUALDAP_PREFIX "result timeout expired");
    } else if(rc < 0) {
	ldap_msgfree(res);
	return faildirect(L, LUALDAP_PREFIX "result error");
    } else {
	int err, ret = 1;
	char *mdn, *msg;
	rc = ldap_parse_result(conn->ld, res, &err, &mdn, &msg, NULL, NULL, 1);
	if(rc != LDAP_SUCCESS) {
	    return faildirect(L, ldap_err2string(rc));
	}
	switch(err) {
	case LDAP_SUCCESS:
	case LDAP_COMPARE_TRUE:
	    lua_pushboolean(L, 1);
	    break;
	case LDAP_COMPARE_FALSE:
	    lua_pushboolean(L, 0);
	    break;
	default:
	    lua_pushnil(L);
	    lua_pushliteral(L, LUALDAP_PREFIX);
	    lua_pushstring(L, msg);
	    lua_pushliteral(L, " ");
	    lua_pushstring(L, ldap_err2string(err));
	    lua_concat(L, 4);
	    ret = 2;
	}
	ldap_memfree(mdn);
	ldap_memfree(msg);
	return ret;
    }
}

/* Push a function to process the LDAP result. */
static int create_future(lua_State *L, int rc, int conn, int msgid, int code) {
    if(rc != LDAP_SUCCESS) {
	return faildirect(L, ldap_err2string(rc));
    }
    lua_pushvalue(L, conn); /* push connection as #1 upvalue */
    lua_pushnumber(L, msgid); /* push msgid as #2 upvalue */
    lua_pushnumber(L, code); /* push code as #3 upvalue */
    lua_pushcclosure(L, result_message, 3);
    return 1;
}

/* Unbind from the directory.
 *	#1 LDAP connection.
 *	return 1 in case of success; nothing when already closed.
*/
static int lualdap_close(lua_State *L) {
    conn_data_t *conn = (conn_data_t *) luaL_checkudata(L, 1, LUALDAP_CONNECTION_METATABLE);
    luaL_argcheck(L, conn != NULL, 1, LUALDAP_PREFIX"LDAP connection expected");
    if(conn->ld == NULL) { /* already closed */
	return 0;
    }
    ldap_unbind_ext(conn->ld, NULL, NULL);
    conn->ld = NULL;
    lua_pushnumber(L, 1);
    return 1;
}

/* Add a new entry to the directory.
 * 	#1 LDAP connection.
 * 	#2 String with new entry's DN.
 * 	#3 Table with new entry's attributes and values.
 * 	return Function to process the LDAP result.
*/
static int lualdap_add(lua_State *L) {
    attrs_data_t attrs;
    int rc, msgid;
    conn_data_t *conn = getconnection(L);
    const char *dn = luaL_checkstring(L, 2);
    A_init(&attrs);
    if( lua_istable(L, 3) ) {
	A_tab2mod(L, &attrs, 3, LUALDAP_MOD_ADD);
    }
    A_lastattr(L, &attrs);
    rc = ldap_add_ext(conn->ld, dn, attrs.attrs, NULL, NULL, &msgid);
    return create_future(L, rc, 1, msgid, LDAP_RES_ADD);
}

/* Compare a value against an entry.
 * 	#1 LDAP connection.
 * 	#2 String with entry's DN.
 * 	#3 String with attribute's name.
 * 	#4 String with attribute's value.
 * 	return Function to process the LDAP result.
*/
static int lualdap_compare(lua_State *L) {
    BerValue bvalue;
    int rc, msgid;
    conn_data_t *conn = getconnection(L);
    const char *dn = luaL_checkstring(L, 2);
    const char *attr = luaL_checkstring(L, 3);
    bvalue.bv_val =(char *)luaL_checkstring(L, 4);
    bvalue.bv_len = lua_rawlen(L, 4);
    rc = ldap_compare_ext(conn->ld, dn, attr, &bvalue, NULL, NULL, &msgid);
    return create_future(L, rc, 1, msgid, LDAP_RES_COMPARE);
}

/* Delete an entry.
 * 	#1 LDAP connection.
 * 	#2 String with entry's DN.
 * 	return Boolean.
*/
static int lualdap_delete(lua_State *L) {
    int rc, msgid;
    conn_data_t *conn = getconnection(L);
    const char * dn = luaL_checkstring(L, 2);
    rc = ldap_delete_ext(conn->ld, dn, NULL, NULL, &msgid);
    return create_future(L, rc, 1, msgid, LDAP_RES_DELETE);
}

/* Convert a string into an internal LDAP_MOD operation code. */
static int op2code(const char *s) {
    if( !s ) {
	return LUALDAP_NO_OP;
    }
    switch( *s ) {
    case '+':
	return LUALDAP_MOD_ADD;
    case '-':
	return LUALDAP_MOD_DEL;
    case '=':
	return LUALDAP_MOD_REP;
    default:
	return LUALDAP_NO_OP;
    }
}

/* Modify an entry.
 * 	#1 LDAP connection.
 * 	#2 String with entry's DN.
 * 	#3, #4... Tables with modifications to apply.
 * 	return True on success or nil, error message otherwise.
*/
static int lualdap_modify(lua_State *L) {
    attrs_data_t attrs;
    int rc, msgid, param = 3;
    conn_data_t *conn = getconnection(L);
    const char * dn = luaL_checkstring(L, 2);
    A_init(&attrs);
    while(lua_istable(L, param)) {
	int op;
	/* get operation('+','-','=' operations allowed) */
	lua_rawgeti(L, param, 1);
	if( (op = op2code(lua_tostring(L, -1))) == LUALDAP_NO_OP ) {
	    return luaL_error(L, LUALDAP_PREFIX "forgotten operation on argument #%d", param);
	}
	/* get array of attributes and values */
	A_tab2mod(L, &attrs, param, op);
	param++;
    }
    A_lastattr(L, &attrs);
    rc = ldap_modify_ext(conn->ld, dn, attrs.attrs, NULL, NULL, &msgid);
    return create_future(L, rc, 1, msgid, LDAP_RES_MODIFY);
}

/* Change the distinguished name of an entry. */
static int lualdap_rename(lua_State *L) {
    int rc, msgid;
    conn_data_t *conn = getconnection(L);
    const char * dn = luaL_checkstring(L, 2);
    const char * rdn = luaL_checkstring(L, 3);
    const char * par = luaL_optlstring(L, 4, NULL, NULL);
    const int del = luaL_optnumber(L, 5, 0);
    rc = ldap_rename(conn->ld, dn, rdn, par, del, NULL, NULL, &msgid);
    return create_future(L, rc, 1, msgid, LDAP_RES_MODDN);
}

/* Push an attribute value(or a table of values) on top of the stack.
 * 	L lua_State.
 * 	ld LDAP Connection.
 * 	entry Current entry.
 * 	attr Name of entry's attribute to get values from.
 * 	return 1 in case of success.
*/
static int push_values(lua_State *L, LDAP *ld, LDAPMessage *entry, char *attr) {
    int i, n;
    BerValue **vals = ldap_get_values_len(ld, entry, attr);
    n = ldap_count_values_len(vals);
    if( n == 0 ) { /* no values */
	lua_pushboolean(L, 1);
    } else if( n == 1 ) { /* just one value */
	lua_pushlstring(L, vals[0]->bv_val, vals[0]->bv_len);
    } else { /* Multiple values */
	lua_newtable(L);
	for( i = 0; i < n; i++ ) {
	    lua_pushlstring(L, vals[i]->bv_val, vals[i]->bv_len);
	    lua_rawseti(L, -2, i+1);
	}
    }
    ldap_value_free_len(vals);
    return 1;
}

/* Store entry's attributes and values at the given table.
 * 	entry Current entry.
 * 	tab Absolute stack index of the table.
*/
static void set_attribs(lua_State *L, LDAP *ld, LDAPMessage *entry, int tab) {
    char *attr;
    BerElement *ber = NULL;
    for( attr = ldap_first_attribute(ld, entry, &ber); attr != NULL; attr = ldap_next_attribute(ld, entry, ber) ) {
	lua_pushstring(L, attr);
	push_values(L, ld, entry, attr);
	lua_rawset(L, tab); /* tab[attr] = vals */
	ldap_memfree(attr);
    }
    ber_free(ber, 0); /* don't need to test if(ber == NULL) */
}

/* Get the distinguished name of the given entry and pushes it on the stack. */
static void push_dn(lua_State *L, LDAP *ld, LDAPMessage *entry) {
    char *dn = ldap_get_dn(ld, entry);
    lua_pushstring(L, dn);
    ldap_memfree(dn);
}

/* Release connection reference. */
static void search_close(lua_State *L, search_data_t *search) {
    luaL_unref(L, LUA_REGISTRYINDEX, search->conn);
    search->conn = LUA_NOREF;
}

/* Retrieve next message:
 * 	return #1 entry's distinguished name.
 * 	return #2 table with entry's attributes and values.
*/
static int next_message(lua_State *L) {
    search_data_t *search = getsearch(L);
    conn_data_t *conn;
    struct timeval *timeout = NULL; /* ??? function parameter ??? */
    LDAPMessage *res;
    int rc, ret;

    lua_rawgeti(L, LUA_REGISTRYINDEX, search->conn);
    conn =(conn_data_t *)lua_touserdata(L, -1); /* get connection */

    rc = ldap_result(conn->ld, search->msgid, LDAP_MSG_ONE, timeout, &res);
    if(rc == 0) {
	return faildirect(L, LUALDAP_PREFIX "result timeout expired");
    } else if(rc == -1) {
	return faildirect(L, LUALDAP_PREFIX "result error");
    } else if(rc == LDAP_RES_SEARCH_RESULT) { /* last message => nil */
	/* close search object to avoid reuse */
	search_close(L, search);
	ret = 0;
    } else {
	LDAPMessage *msg = ldap_first_message(conn->ld, res);
	switch(ldap_msgtype(msg)) {
	case LDAP_RES_SEARCH_ENTRY: {
	    LDAPMessage *entry = ldap_first_entry(conn->ld, msg);
	    push_dn(L, conn->ld, entry);
	    lua_newtable(L);
	    set_attribs(L, conn->ld, entry, lua_gettop(L));
	    ret = 2; /* two return values */
	    break;
	}
	case LDAP_RES_SEARCH_REFERENCE: {
	    LDAPMessage *ref = ldap_first_reference(conn->ld, msg);
	    push_dn(L, conn->ld, ref); /* is this supposed to work? */
	    lua_pushnil(L);
	    ret = 2; /* two return values */
	    break;
	}
	case LDAP_RES_SEARCH_RESULT:
	    /* close search object to avoid reuse */
	    search_close(L, search);
	    ret = 0;
	    break;
	default:
	    ldap_msgfree(res);
	    return luaL_error(L, LUALDAP_PREFIX "error on search result chain");
	}
    }
    ldap_msgfree(res);
    return ret;
}

/* Convert a string to one of the possible scopes of the search. */
static int string2scope(lua_State *L, const char *s) {
    if( s == NULL || *s == '\0' ) {
	return LDAP_SCOPE_DEFAULT;
    }
    switch(*s) {
    case 'b':
	return LDAP_SCOPE_BASE;
    case 'o':
	return LDAP_SCOPE_ONELEVEL;
    case 's':
	return LDAP_SCOPE_SUBTREE;
    default:
	return luaL_error(L, LUALDAP_PREFIX "invalid search scope `%s'", s);
    }
}

/* Close the search object. */
static int lualdap_search_close(lua_State *L) {
    search_data_t *search = (search_data_t *) luaL_checkudata(L, 1, LUALDAP_SEARCH_METATABLE);
    luaL_argcheck(L, search!=NULL, 1, LUALDAP_PREFIX "LDAP search expected");
    if( search->conn == LUA_NOREF ) {
	return 0;
    }
    search_close(L, search);
    lua_pushnumber(L, 1);
    return 1;
}

/* Create a search object and leaves it on top of the stack. */
static void create_search(lua_State *L, int conn_index, int msgid) {
    search_data_t *search =(search_data_t *)lua_newuserdata(L, sizeof(search_data_t));
    lualdap_setmeta(L, LUALDAP_SEARCH_METATABLE);
    search->conn = LUA_NOREF;
    search->msgid = msgid;
    lua_pushvalue(L, conn_index);
    search->conn = luaL_ref(L, LUA_REGISTRYINDEX);
}

/* Fill in the attrs array, according to the attrs parameter. */
static int get_attrs_param(lua_State *L, char *attrs[]) {
    lua_pushstring(L, "attrs");
    lua_gettable(L, 2);
    if(lua_isstring(L, -1)) {
	attrs[0] =(char *)lua_tostring(L, -1);
	attrs[1] = NULL;
    } else if(!lua_istable(L, -1)) {
	attrs[0] = NULL;
    } else {
	if( table2strarray(L, lua_gettop(L), attrs, LUALDAP_MAX_ATTRS) ) {
	    return 0;
	}
    }
    return 1;
}

/* Fill in the struct timeval, according to the timeout parameter. */
static struct timeval *get_timeout_param(lua_State *L, struct timeval *st) {
    double t = numbertabparam(L, "timeout", 0);
    st->tv_sec =(long)t;
    st->tv_usec =(long)(1000000 *(t - st->tv_sec));
    return st->tv_sec == 0 && st->tv_usec == 0 ? NULL : st;
}

/* Perform a search operation.
 * 	return #1 Function to iterate over the result entries.
 * 	return #2 nil.
 * 	return #3 nil as first entry.
 * The search result is defined as an upvalue of the iterator.
*/
static int lualdap_search(lua_State *L) {
    conn_data_t *conn = getconnection(L);
    const char *base, *filter;
    char *attrs[LUALDAP_MAX_ATTRS];
    int scope, attrsonly, msgid, rc, sizelimit;
    struct timeval st, *timeout;

    if( !lua_istable(L, 2) ) {
	return luaL_error(L, LUALDAP_PREFIX "no search specification");
    }
    if(!get_attrs_param(L, attrs)) {
	return 2;
    }

    /* get other parameters */
    attrsonly = booltabparam(L, "attrsonly", 0);
    base = strtabparam(L, "base", NULL);
    filter = strtabparam(L, "filter", NULL);
    scope = string2scope(L, strtabparam(L, "scope", NULL));
    sizelimit = longtabparam(L, "sizelimit", LDAP_NO_LIMIT);
    timeout = get_timeout_param(L, &st);

    if( (rc = ldap_search_ext(conn->ld, base, scope, filter, attrs, attrsonly, NULL, NULL, timeout, sizelimit, &msgid)) 
	    != LDAP_SUCCESS ) {
	return luaL_error(L, LUALDAP_PREFIX "%s", ldap_err2string(rc));
    }

    create_search(L, 1, msgid);
    lua_pushcclosure(L, next_message, 1);
    return 1;
}

/* Return the name of the object's metatable. This function is used by `tostring'. */
static int lualdap_conn_tostring(lua_State *L) {
    char buff[100];
    conn_data_t *conn =(conn_data_t *)lua_touserdata(L, 1);
    if( conn->ld == NULL ) {
	strcpy(buff, "closed");
    } else {
	sprintf(buff, "%p", (void *)conn);
    }
    lua_pushfstring(L, "%s(%s)", LUALDAP_CONNECTION_METATABLE, buff);
    return 1;
}

/* Return the name of the object's metatable. This function is used by `tostring'. */
static int lualdap_search_tostring(lua_State *L) {
    char buff[100];
    search_data_t *search =(search_data_t *)lua_touserdata(L, 1);
    luaL_argcheck(L,search->conn!=LUA_NOREF,1,LUALDAP_PREFIX "LDAP search is closed");
    if( search->conn == LUA_NOREF ) {
	strcpy(buff, "closed");
    } else {
	sprintf(buff, "%p", (void *)search);
    }
    lua_pushfstring(L, "%s(%s)", LUALDAP_SEARCH_METATABLE, buff);
    return 1;
}

/* Open and initialize a connection to a server.
 * 	#1 String with uri.
 * 	#2 String with bind dn.
 * 	#3 String with bind password.
 * 	#4 Boolean indicating if TLS must be used.
 * 	return userdata with connection structure.
*/
static int lualdap_open_simple(lua_State *L) {
    const char *uri, *dn, *passwd;
    int use_tls, err;
    conn_data_t *conn;
    BerValue cred;

    uri = luaL_checkstring(L, 1);
    dn = luaL_optstring(L, 2, NULL);
    passwd = luaL_optstring(L, 3, NULL);
    use_tls = luaL_optboolean(L, 4, 0);
    conn = (conn_data_t *)lua_newuserdata(L, sizeof(conn_data_t));
    conn->ld = NULL;
    conn->version = LDAP_VERSION3;
    memset(&cred, 0, sizeof(cred));
    cred.bv_val = (char *) passwd;
    cred.bv_len = passwd == NULL ? 0 : strlen(passwd);
    lualdap_setmeta(L, LUALDAP_CONNECTION_METATABLE);

    if( (err = ldap_initialize(&conn->ld, uri)) != LDAP_SUCCESS ) {
	return faildirect(L,LUALDAP_PREFIX "error connecting to the LDAP server");
    }
    if( ldap_set_option(conn->ld, LDAP_OPT_PROTOCOL_VERSION, &conn->version) != LDAP_OPT_SUCCESS) {
	ldap_unbind_ext(conn->ld, NULL, NULL);
	conn->ld = NULL;
	return faildirect(L, LUALDAP_PREFIX "error setting LDAP version");
    }
    if( use_tls && (err = ldap_start_tls_s(conn->ld, NULL, NULL)) != LDAP_SUCCESS ) {
	ldap_unbind_ext(conn->ld, NULL, NULL);
	conn->ld = NULL;
	return faildirect(L, LUALDAP_PREFIX "unable to start TLS session" /*ldap_err2string(err)*/);
    }
    if( (err = ldap_sasl_bind_s(conn->ld, dn, NULL/*SIMPLE*/, &cred, NULL, NULL, NULL)) != LDAP_SUCCESS ) {
	ldap_unbind_ext(conn->ld, NULL, NULL);
	conn->ld = NULL;
	return faildirect(L, LUALDAP_PREFIX "error binding to the LDAP server" /*ldap_err2string(err)*/);
    }

    return 1;
}

static const luaL_Reg meta_methods[] = {
    {"close", lualdap_close},
    {"add", lualdap_add},
    {"compare", lualdap_compare},
    {"delete", lualdap_delete},
    {"modify", lualdap_modify},
    {"rename", lualdap_rename},
    {"search", lualdap_search},
    {NULL, NULL}
};

struct luaL_Reg lualdap_methods[] = {
    {"open_simple", lualdap_open_simple},
    {NULL, NULL},
};

LUAMOD_API int luaopen_bind_ldap(lua_State *L) 
{
    luaL_newmetatable(L, LUALDAP_CONNECTION_METATABLE);
    luaL_setfuncs(L, meta_methods, 0);
    /* define metamethods */
    lua_pushliteral(L, "__gc");
    lua_pushcfunction(L, lualdap_close);
    lua_settable(L, -3);
    lua_pushliteral(L, "__index");
    lua_pushvalue(L, -2);
    lua_settable(L, -3);
    lua_pushliteral(L, "__tostring");
    lua_pushcfunction(L, lualdap_conn_tostring);
    lua_settable(L, -3);
    lua_pushliteral(L, "__metatable");
    lua_pushliteral(L,LUALDAP_PREFIX "you're not allowed to get this metatable");
    lua_settable(L, -3);

    luaL_newmetatable(L, LUALDAP_SEARCH_METATABLE);
    lua_pushliteral(L, "__gc");
    lua_pushcfunction(L, lualdap_search_close);
    lua_settable(L, -3);
    lua_pushliteral(L, "__tostring");
    lua_pushcclosure(L, lualdap_search_tostring, 1);
    lua_settable(L, -3);
    lua_pushliteral(L, "__metatable");
    lua_pushliteral(L,LUALDAP_PREFIX "you're not allowed to get this metatable");
    lua_settable(L, -3);

    luaL_newlib(L, lualdap_methods);

    lua_pushliteral(L, "_VERSION");
    lua_pushliteral(L, PACKAGE_VERSION);
    lua_settable(L, -3);

    return 1;
}
