/* -*- C -*- */
/* Copyright (c) 2006 - 2022 omobus-scgid authors, see the included COPYRIGHT file. */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <math.h>
#include <limits.h>

#include "omobus-scgid.h"

#define LUA_LIB
#include "lua.h"
#include "luaaux.h"

/* Original code created by Mark Pulford <mark@kyne.com.au>
 * https://github.com/mpx/lua-cjson.git
 */

/* Caveats:
 * - JSON "null" values are represented as lightuserdata since Lua
 *   tables cannot contain "nil". Compare with json.null.
 * - Invalid UTF-8 characters are not detected and will be passed
 *   untouched. If required, UTF-8 error checking should be done
 *   outside this library.
 * - Javascript comments are not part of the JSON spec, and are not
 *   currently supported.
 *
 * Note: Decoding is slower than encoding. Lua spends significant
 *       time (30%) managing tables when parsing JSON since it is
 *       difficult to know object/array sizes ahead of time.
 */

/* Workaround for Solaris platforms missing isinf() */
#if !defined(isinf) && (defined(USE_INTERNAL_ISINF) || defined(MISSING_ISINF))
#define isinf(x) (!isnan(x) && isnan((x) - (x)))
#endif

#define DEFAULT_SPARSE_CONVERT 		0
#define DEFAULT_SPARSE_RATIO 		2
#define DEFAULT_SPARSE_SAFE 		10
#define DEFAULT_ENCODE_MAX_DEPTH 	1000
#define DEFAULT_DECODE_MAX_DEPTH 	1000
#define DEFAULT_ENCODE_INVALID_NUMBERS 	0
#define DEFAULT_DECODE_INVALID_NUMBERS 	1
#define DEFAULT_ENCODE_NUMBER_PRECISION 14

typedef enum {
    T_OBJ_BEGIN,
    T_OBJ_END,
    T_ARR_BEGIN,
    T_ARR_END,
    T_STRING,
    T_NUMBER,
    T_BOOLEAN,
    T_NULL,
    T_COLON,
    T_COMMA,
    T_END,
    T_WHITESPACE,
    T_ERROR,
    T_UNKNOWN
} json_token_type_t;

static const char *json_token_type_name[] = {
    "T_OBJ_BEGIN",
    "T_OBJ_END",
    "T_ARR_BEGIN",
    "T_ARR_END",
    "T_STRING",
    "T_NUMBER",
    "T_BOOLEAN",
    "T_NULL",
    "T_COLON",
    "T_COMMA",
    "T_END",
    "T_WHITESPACE",
    "T_ERROR",
    "T_UNKNOWN",
    NULL
};

typedef struct _membuf_t {
    FILE *f;
    char *byteptr;
    size_t size;
} membuf_t;

typedef struct {
    json_token_type_t ch2token[256];
    char escape2char[256];  /* Decoding */

    int encode_sparse_convert;
    int encode_sparse_ratio;
    int encode_sparse_safe;
    int encode_max_depth;
    int encode_invalid_numbers;     /* 2 => Encode as "null" */
    int encode_number_precision;

    int decode_invalid_numbers;
    int decode_max_depth;
} json_config_t;

typedef struct {
    const char *data;
    const char *ptr;
    json_config_t *cfg;
    int current_depth;
    int debug_allocs, debug_frees;
} json_parse_t;

typedef struct {
    json_token_type_t type;
    int index;
    /* value */
    char *string;
    int string_len;
    double number;
    int boolean;
} json_token_t;

static const char *char2escape[256] = {
    "\\u0000", "\\u0001", "\\u0002", "\\u0003",
    "\\u0004", "\\u0005", "\\u0006", "\\u0007",
    "\\b", "\\t", "\\n", "\\u000b",
    "\\f", "\\r", "\\u000e", "\\u000f",
    "\\u0010", "\\u0011", "\\u0012", "\\u0013",
    "\\u0014", "\\u0015", "\\u0016", "\\u0017",
    "\\u0018", "\\u0019", "\\u001a", "\\u001b",
    "\\u001c", "\\u001d", "\\u001e", "\\u001f",
    NULL, NULL, "\\\"", NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, /*"\\/"*/NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, "\\\\", NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, "\\u007f",
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
};

static void json_append_data(lua_State *L, json_config_t *cfg, int current_depth, membuf_t *json);
static void json_process_value(lua_State *L, json_parse_t *json, json_token_t *token);
static int lua_json_new(lua_State *L);

static int membuf_init(membuf_t *p)
{
    p->size = 0;
    p->byteptr = NULL;
    return (p->f = open_memstream(&p->byteptr, &p->size)) == NULL ? -1 : 0;
}

static void membuf_close(membuf_t *p)
{
    if( p != NULL && p->f != NULL ) {
	fclose(p->f);
	p->f = NULL;
    }
}

static void membuf_cleanup(membuf_t *p)
{
    membuf_close(p);
    if( p != NULL && p->byteptr != NULL ) {
	free(p->byteptr);
	p->byteptr = NULL;
	p->size = 0;
    }
}

static void membuf_write(membuf_t *p, const void *buf, size_t sz)
{
    if( p != NULL && p->f != NULL && buf != NULL && sz > 0 ) {
	fwrite(buf, sz, 1, p->f);
    }
}

static void membuf_putc(membuf_t *p, int ch)
{
    if( p != NULL && p->f != NULL ) {
	fputc(ch, p->f);
    }
}

static void membuf_puts(membuf_t *p, const char *s)
{
    if( p != NULL && p->f != NULL && s != NULL ) {
	fputs(s, p->f);
    }
}

static void membuf_printf(membuf_t *p, const char *fmt, ...)
{
    va_list arg;
    /*int fmt_len;*/
    if( p != NULL && p->f != NULL && fmt != NULL ) {
	va_start(arg, fmt);
	/*fmt_len = */vfprintf(p->f, fmt, arg);
	va_end(arg);
    }
}

static json_config_t *json_fetch_config(lua_State *L)
{
    json_config_t *cfg;
    if( (cfg = lua_touserdata(L, lua_upvalueindex(1))) == NULL ) {
	luaL_error(L, "BUG: unable to fetch JSON configuration");
    }
    return cfg;
}

/* Ensure the correct number of arguments have been provided.
 * Pad with nil to allow other functions to simply check arg[i]
 * to find whether an argument was provided */
static json_config_t *json_arg_init(lua_State *L, int args)
{
    luaL_argcheck(L, lua_gettop(L) <= args, args + 1, "found too many arguments");
    while (lua_gettop(L) < args) {
	lua_pushnil(L);
    }
    return json_fetch_config(L);
}

/* Process integer options for configuration functions */
static int json_integer_option(lua_State *L, int optindex, int *setting, int min, int max)
{
    char errmsg[64];
    int value;

    if( !lua_isnil(L, optindex) ) {
	value = luaL_checkinteger(L, optindex);
	snprintf(errmsg, sizeof(errmsg), "expected integer between %d and %d", min, max);
	luaL_argcheck(L, min <= value && value <= max, 1, errmsg);
	*setting = value;
    }

    lua_pushinteger(L, *setting);

    return 1;
}

/* Process enumerated arguments for a configuration function */
static int json_enum_option(lua_State *L, int optindex, int *setting, const char **options, int bool_true)
{
    static const char *bool_options[] = { "off", "on", NULL };

    if( !options ) {
	options = bool_options;
	bool_true = 1;
    }
    if( !lua_isnil(L, optindex) ) {
	if (bool_true && lua_isboolean(L, optindex)) {
	    *setting = lua_toboolean(L, optindex) * bool_true;
	} else {
	    *setting = luaL_checkoption(L, optindex, NULL, options);
	}
    }
    if( bool_true && (*setting == 0 || *setting == bool_true) ) {
	lua_pushboolean(L, *setting);
    } else {
	lua_pushstring(L, options[*setting]);
    }

    return 1;
}

/* Configures handling of extremely sparse arrays:
 * convert: Convert extremely sparse arrays into objects? Otherwise error.
 * ratio: 0: always allow sparse; 1: never allow sparse; >1: use ratio
 * safe: Always use an array when the max index <= safe */
static int json_cfg_encode_sparse_array(lua_State *L)
{
    json_config_t *cfg = json_arg_init(L, 3);

    json_enum_option(L, 1, &cfg->encode_sparse_convert, NULL, 1);
    json_integer_option(L, 2, &cfg->encode_sparse_ratio, 0, INT_MAX);
    json_integer_option(L, 3, &cfg->encode_sparse_safe, 0, INT_MAX);

    return 3;
}

/* Configures the maximum number of nested arrays/objects allowed when
 * encoding */
static int json_cfg_encode_max_depth(lua_State *L)
{
    json_config_t *cfg = json_arg_init(L, 1);
    return json_integer_option(L, 1, &cfg->encode_max_depth, 1, INT_MAX);
}

/* Configures the maximum number of nested arrays/objects allowed when
 * encoding */
static int json_cfg_decode_max_depth(lua_State *L)
{
    json_config_t *cfg = json_arg_init(L, 1);
    return json_integer_option(L, 1, &cfg->decode_max_depth, 1, INT_MAX);
}

/* Configures number precision when converting doubles to text */
static int json_cfg_encode_number_precision(lua_State *L)
{
    json_config_t *cfg = json_arg_init(L, 1);
    return json_integer_option(L, 1, &cfg->encode_number_precision, 1, 14);
}

static int json_cfg_encode_invalid_numbers(lua_State *L)
{
    static const char *options[] = { "off", "on", "null", NULL };
    json_config_t *cfg = json_arg_init(L, 1);
    json_enum_option(L, 1, &cfg->encode_invalid_numbers, options, 1);
    return 1;
}

static int json_cfg_decode_invalid_numbers(lua_State *L)
{
    json_config_t *cfg = json_arg_init(L, 1);
    json_enum_option(L, 1, &cfg->decode_invalid_numbers, NULL, 1);
    return 1;
}

static int json_destroy_config(lua_State *L)
{
    json_config_t *cfg;

    if( (cfg = lua_touserdata(L, 1)) != NULL ) {
	cfg = NULL;
    }

    return 0;
}

static void json_create_config(lua_State *L)
{
    json_config_t *cfg;
    int i;

    cfg = lua_newuserdata(L, sizeof(*cfg));

    lua_newtable(L);
    lua_pushcfunction(L, json_destroy_config);
    lua_setfield(L, -2, "__gc");
    lua_setmetatable(L, -2);

    cfg->encode_sparse_convert = DEFAULT_SPARSE_CONVERT;
    cfg->encode_sparse_ratio = DEFAULT_SPARSE_RATIO;
    cfg->encode_sparse_safe = DEFAULT_SPARSE_SAFE;
    cfg->encode_max_depth = DEFAULT_ENCODE_MAX_DEPTH;
    cfg->decode_max_depth = DEFAULT_DECODE_MAX_DEPTH;
    cfg->encode_invalid_numbers = DEFAULT_ENCODE_INVALID_NUMBERS;
    cfg->decode_invalid_numbers = DEFAULT_DECODE_INVALID_NUMBERS;
    cfg->encode_number_precision = DEFAULT_ENCODE_NUMBER_PRECISION;

    /* Decoding init */

    /* Tag all characters as an error */
    for (i = 0; i < 256; i++) {
        cfg->ch2token[i] = T_ERROR;
    }

    /* Set tokens that require no further processing */
    cfg->ch2token['{'] = T_OBJ_BEGIN;
    cfg->ch2token['}'] = T_OBJ_END;
    cfg->ch2token['['] = T_ARR_BEGIN;
    cfg->ch2token[']'] = T_ARR_END;
    cfg->ch2token[','] = T_COMMA;
    cfg->ch2token[':'] = T_COLON;
    cfg->ch2token['\0'] = T_END;
    cfg->ch2token[' '] = T_WHITESPACE;
    cfg->ch2token['\t'] = T_WHITESPACE;
    cfg->ch2token['\n'] = T_WHITESPACE;
    cfg->ch2token['\r'] = T_WHITESPACE;

    /* Update characters that require further processing */
    cfg->ch2token['f'] = T_UNKNOWN;     /* false? */
    cfg->ch2token['i'] = T_UNKNOWN;     /* inf, ininity? */
    cfg->ch2token['I'] = T_UNKNOWN;
    cfg->ch2token['n'] = T_UNKNOWN;     /* null, nan? */
    cfg->ch2token['N'] = T_UNKNOWN;
    cfg->ch2token['t'] = T_UNKNOWN;     /* true? */
    cfg->ch2token['"'] = T_UNKNOWN;     /* string? */
    cfg->ch2token['+'] = T_UNKNOWN;     /* number? */
    cfg->ch2token['-'] = T_UNKNOWN;

    for (i = 0; i < 10; i++) {
        cfg->ch2token['0' + i] = T_UNKNOWN;
    }

    /* Lookup table for parsing escape characters */
    for (i = 0; i < 256; i++) {
        cfg->escape2char[i] = 0;          /* String error */
    }
    cfg->escape2char['"'] = '"';
    cfg->escape2char['\\'] = '\\';
    cfg->escape2char['/'] = '/';
    cfg->escape2char['b'] = '\b';
    cfg->escape2char['t'] = '\t';
    cfg->escape2char['n'] = '\n';
    cfg->escape2char['f'] = '\f';
    cfg->escape2char['r'] = '\r';
    cfg->escape2char['u'] = 'u';          /* Unicode parsing required */
}

static void json_encode_exception(lua_State *L, json_config_t *cfg, membuf_t *json, int lindex, 
    const char *reason)
{
    membuf_cleanup(json);
    luaL_error(L, "cannot serialise %s: %s", lua_typename(L, lua_type(L, lindex)), reason);
}

static void json_append_string(lua_State *L, membuf_t *json, int lindex)
{
    const char *escstr, *str;
    int i;
    size_t len;
    char ch;

    if( (str = lua_tolstring(L, lindex, &len)) != NULL ) {
	membuf_putc(json, '\"');
	for( i = 0; i < len; i++ ) {
	    ch = str[i];
	    if( (escstr = char2escape[(unsigned char)ch]) != NULL ) {
		membuf_puts(json, escstr);
	    } else {
		membuf_putc(json, ch);
	    }
	}
	membuf_putc(json, '\"');
    }
}

/* Find the size of the array on the top of the Lua stack
 * -1   object (not a pure array)
 * >=0  elements in array
 */
static int lua_array_length(lua_State *L, json_config_t *cfg, membuf_t *json)
{
    double k;
    int max;
    int items;

    max = 0;
    items = 0;

    lua_pushnil(L);
    /* table, startkey */
    while( lua_next(L, -2) != 0 ) {
	/* table, key, value */
	if( lua_type(L, -2) == LUA_TNUMBER && (k = lua_tonumber(L, -2)) ) {
	    /* Integer >= 1 ? */
	    if( floor(k) == k && k >= 1 ) {
		if (k > max) {
		    max = k;
		}
		items++;
		lua_pop(L, 1);
		continue;
	    }
	}
	/* Must not be an array (non integer key) */
	lua_pop(L, 2);
	return -1;
    }

    /* Encode excessively sparse arrays as objects (if enabled) */
    if (cfg->encode_sparse_ratio > 0 && max > items * cfg->encode_sparse_ratio &&
	max > cfg->encode_sparse_safe) {
	if( !cfg->encode_sparse_convert ) {
	    json_encode_exception(L, cfg, json, -1, "excessively sparse array");
	}
        return -1;
    }

    return max;
}

static void json_check_encode_depth(lua_State *L, json_config_t *cfg, 
    int current_depth, membuf_t *json)
{
    /* Ensure there are enough slots free to traverse a table (key,
     * value) and push a string for a potential error message.
     *
     * Unlike "decode", the key and value are still on the stack when
     * lua_checkstack() is called.  Hence an extra slot for luaL_error()
     * below is required just in case the next check to lua_checkstack()
     * fails.
     *
     * While this won't cause a crash due to the EXTRA_STACK reserve
     * slots, it would still be an improper use of the API. */
    if( current_depth <= cfg->encode_max_depth && lua_checkstack(L, 3) ) {
	return;
    }
    membuf_cleanup(json);
    luaL_error(L, "cannot serialise, excessive nesting (%d)", current_depth);
}

static void json_append_array(lua_State *L, json_config_t *cfg, int current_depth,
    membuf_t *json, int array_length)
{
    int comma, i;

    membuf_putc(json, '[');
    for( i = 1, comma = 0; i <= array_length; i++ ) {
	if( comma ) {
	    membuf_putc(json, ',');
	} else {
	    comma = 1;
	}
	lua_rawgeti(L, -1, i);
	json_append_data(L, cfg, current_depth, json);
	lua_pop(L, 1);
    }
    membuf_putc(json, ']');
}

static inline char *number_format(char *fmt, int precision)
{
    int d1, d2, i;
    if( !(1 <= precision && precision <= 14) ) {
	precision = 14;
    }
    /* Create printf format (%.14g) from precision */
    d1 = precision / 10;
    d2 = precision % 10;
    fmt[0] = '%';
    fmt[1] = '.';
    i = 2;
    if( d1 ) {
	fmt[i++] = '0' + d1;
    }
    fmt[i++] = '0' + d2;
    fmt[i++] = 'g';
    fmt[i] = '\0';
    return fmt;
}

static void json_append_number(lua_State *L, json_config_t *cfg, membuf_t *json, int lindex)
{
    double num;
    char fmt[6];

    num = lua_tonumber(L, lindex);

    if(cfg->encode_invalid_numbers == 0 ) {
	/* Prevent encoding invalid numbers */
	if( isinf(num) || isnan(num) ) {
	    json_encode_exception(L, cfg, json, lindex, "must not be NaN or Infinity");
	}
    } else if (cfg->encode_invalid_numbers == 1) {
	/* Encode NaN/Infinity separately to ensure Javascript compatible
	 * values are used. */
	if( isnan(num) ) {
	    membuf_puts(json, "NaN");
	    return;
	}
	if( isinf(num) ) {
	    if( num < 0 ) {
		membuf_puts(json, "-Infinity");
	    } else {
		membuf_puts(json, "Infinity");
	    }
	    return;
	}
    } else {
	/* Encode invalid numbers as "null" */
	if( isinf(num) || isnan(num) ) {
	    membuf_puts(json, "null");
	    return;
	}
    }

    membuf_printf(json, number_format(fmt, cfg->encode_number_precision), num);
}

static void json_append_object(lua_State *L, json_config_t *cfg, int current_depth, membuf_t *json)
{
    int comma, keytype;

    membuf_putc(json, '{');
    lua_pushnil(L);
    comma = 0;
    while( lua_next(L, -2) != 0 ) {
	if( comma ) {
	    membuf_putc(json, ',');
	} else {
	    comma = 1;
	}
	/* table, key, value */
	keytype = lua_type(L, -2);
	if (keytype == LUA_TNUMBER) {
	    membuf_putc(json, '"');
	    json_append_number(L, cfg, json, -2);
	    membuf_puts(json, "\":");
	} else if (keytype == LUA_TSTRING) {
	    json_append_string(L, json, -2);
	    membuf_putc(json, ':');
	} else {
	    json_encode_exception(L, cfg, json, -2, "table key must be a number or string");
	    /* never returns */
	}
	/* table, key, value */
	json_append_data(L, cfg, current_depth, json);
	lua_pop(L, 1);
	/* table, key */
    }
    membuf_putc(json, '}');
}

/* Serialise Lua data into JSON string. */
static void json_append_data(lua_State *L, json_config_t *cfg, int current_depth, membuf_t *json)
{
    int len;

    switch( lua_type(L, -1) ) {
    case LUA_TSTRING:
	json_append_string(L, json, -1);
	break;
    case LUA_TNUMBER:
	json_append_number(L, cfg, json, -1);
	break;
    case LUA_TBOOLEAN:
	membuf_puts(json, lua_toboolean(L, -1) ? "true" : "false");
	break;
    case LUA_TTABLE:
	current_depth++;
	json_check_encode_depth(L, cfg, current_depth, json);
	len = lua_array_length(L, cfg, json);
	if( len > 0 ) {
	    json_append_array(L, cfg, current_depth, json, len);
	} else {
	    json_append_object(L, cfg, current_depth, json);
	}
        break;
    case LUA_TNIL:
	membuf_puts(json, "null");
	break;
    case LUA_TLIGHTUSERDATA:
	if( lua_touserdata(L, -1) == NULL ) {
	    membuf_puts(json, "null");
	    break;
        }
    default:
        /* Remaining types (LUA_TFUNCTION, LUA_TUSERDATA, LUA_TTHREAD,
         * and LUA_TLIGHTUSERDATA) cannot be serialised */
        json_encode_exception(L, cfg, json, -1, "type not supported");
        /* never returns */
    }
}

static int json_encode(lua_State *L)
{
    json_config_t *cfg;
    membuf_t jsonbuf;

    cfg = json_fetch_config(L);
    luaL_argcheck(L, lua_gettop(L) == 1, 1, "expected 1 argument");
    if( membuf_init(&jsonbuf) == -1 ) {
	return luaL_error(L, "unable to initialize memory stream.");
    }
    json_append_data(L, cfg, 0, &jsonbuf);
    membuf_close(&jsonbuf);
    lua_pushlstring(L, jsonbuf.byteptr, jsonbuf.size);
    membuf_cleanup(&jsonbuf);
    return 1;
}

static int hexdigit2int(char hex)
{
    if ('0' <= hex  && hex <= '9') {
	return hex - '0';
    }

    /* Force lowercase */
    hex |= 0x20;
    if ('a' <= hex && hex <= 'f') {
	return 10 + hex - 'a';
    }

    return -1;
}

static int decode_hex4(const char *hex)
{
    int digit[4];
    int i;

    /* Convert ASCII hex digit to numeric digit
     * Note: this returns an error for invalid hex digits, including NULL */
    for (i = 0; i < 4; i++) {
        digit[i] = hexdigit2int(hex[i]);
        if (digit[i] < 0) {
            return -1;
        }
    }

    return (digit[0] << 12) + (digit[1] << 8) + (digit[2] << 4) + digit[3];
}

/* Converts a Unicode codepoint to UTF-8.
 * Returns UTF-8 string length, and up to 4 bytes in utf8.
 */
static int codepoint_to_utf8(char *utf8, int codepoint)
{
    /* 0xxxxxxx */
    if (codepoint <= 0x7F) {
        utf8[0] = codepoint;
        return 1;
    }

    /* 110xxxxx 10xxxxxx */
    if (codepoint <= 0x7FF) {
        utf8[0] = (codepoint >> 6) | 0xC0;
        utf8[1] = (codepoint & 0x3F) | 0x80;
        return 2;
    }

    /* 1110xxxx 10xxxxxx 10xxxxxx */
    if (codepoint <= 0xFFFF) {
        utf8[0] = (codepoint >> 12) | 0xE0;
        utf8[1] = ((codepoint >> 6) & 0x3F) | 0x80;
        utf8[2] = (codepoint & 0x3F) | 0x80;
        return 3;
    }

    /* 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx */
    if (codepoint <= 0x1FFFFF) {
        utf8[0] = (codepoint >> 18) | 0xF0;
        utf8[1] = ((codepoint >> 12) & 0x3F) | 0x80;
        utf8[2] = ((codepoint >> 6) & 0x3F) | 0x80;
        utf8[3] = (codepoint & 0x3F) | 0x80;
        return 4;
    }

    return 0;
}

/* Called when index pointing to beginning of UTF-16 code escape: \uXXXX
 * \u is guaranteed to exist, but the remaining hex characters may be
 * missing.
 * Translate to UTF-8 and append to temporary token string.
 * Must advance index to the next character to be processed.
 * Returns: 0 - success or -1 - error.
 */
static int json_append_unicode_escape(json_parse_t *json, membuf_t *buf)
{
    char utf8[4];       /* Surrogate pairs require 4 UTF-8 bytes */
    int codepoint;
    int surrogate_low;
    int len;
    int escape_len = 6;

    /* Fetch UTF-16 code unit */
    if( (codepoint = decode_hex4(json->ptr + 2)) < 0 ) {
	return -1;
    }

    /* UTF-16 surrogate pairs take the following 2 byte form:
     *      11011 x yyyyyyyyyy
     * When x = 0: y is the high 10 bits of the codepoint
     *      x = 1: y is the low 10 bits of the codepoint
     *
     * Check for a surrogate pair (high or low) */
    if( (codepoint & 0xF800) == 0xD800 ) {
	/* Error if the 1st surrogate is not high */
	if( codepoint & 0x400 ) {
	    return -1;
	}

	/* Ensure the next code is a unicode escape */
	if (*(json->ptr + escape_len) != '\\' ||
	    *(json->ptr + escape_len + 1) != 'u') {
	    return -1;
	}

	/* Fetch the next codepoint */
	if( (surrogate_low = decode_hex4(json->ptr + 2 + escape_len)) < 0) {
	    return -1;
	}

	/* Error if the 2nd code is not a low surrogate */
	if( (surrogate_low & 0xFC00) != 0xDC00) {
	    return -1;
	}

	/* Calculate Unicode codepoint */
	codepoint = (codepoint & 0x3FF) << 10;
	surrogate_low &= 0x3FF;
	codepoint = (codepoint | surrogate_low) + 0x10000;
	escape_len = 12;
    }

    /* Convert codepoint to UTF-8 */
    if( (len = codepoint_to_utf8(utf8, codepoint)) == 0 ) {
	return -1;
    }

    /* Append bytes and advance parse index */
    membuf_write(buf, utf8, len);
    json->ptr += escape_len;

    return 0;
}

static void json_set_token_error(json_token_t *token, json_parse_t *json, const char *errmsg)
{
    token->type = T_ERROR;
    token->index = json->ptr - json->data;
    token->string = strdup(errmsg);
    token->string_len = token->string ? strlen(token->string) : 0;
    json->debug_allocs++;
}

static void json_next_string_token(json_parse_t *json, json_token_t *token)
{
    char *escape2char, ch;
    membuf_t buf;

    if( !(*json->ptr == '"') ) {
	json_set_token_error(token, json, "unexpected begin of string");
	return;
    }

    escape2char = json->cfg->escape2char;
    json->ptr++; /* Skip " */

    if( membuf_init(&buf) == -1 ) {
	json_set_token_error(token, json, "unable to allocate memory stream");
	return;
    }
    while( (ch = *json->ptr) != '"' ) {
	if( !ch ) {
	    membuf_cleanup(&buf);
	    json_set_token_error(token, json, "unexpected end of string");
	    return;
	}
	/* Handle escapes */
	if( ch == '\\' ) {
	    ch = escape2char[(unsigned char)(*(json->ptr + 1))];
	    if( ch == 'u' ) {
		if( json_append_unicode_escape(json, &buf) == 0 ) {
		    continue;
		}
		membuf_cleanup(&buf);
		json_set_token_error(token, json, "invalid unicode escape code");
		return;
	    }
	    if( !ch ) {
		membuf_cleanup(&buf);
		json_set_token_error(token, json, "invalid escape code");
		return;
	    }
	    /* Skip '\' */
	    json->ptr++;
	}
	/* Append normal character or translated single character
	 * Unicode escapes are handled above */
	membuf_putc(&buf, ch);
	json->ptr++;
    }
    json->ptr++;    /* Eat final quote (") */

    membuf_close(&buf);
    token->type = T_STRING;
    token->string = buf.byteptr;
    token->string_len = buf.size;
    json->debug_allocs++;
}

static void json_cleanup_token(json_parse_t *json, json_token_t *token)
{
    if( token->string != NULL ) {
	free(token->string);
	token->string = NULL;
	json->debug_frees++;
    }
    token->number = 0.0;
    token->boolean = 0;
    token->string_len = 0;
}

/* JSON numbers should take the following form:
 *      -?(0|[1-9]|[1-9][0-9]+)(.[0-9]+)?([eE][-+]?[0-9]+)?
 *
 * json_next_number_token() uses strtod() which allows other forms:
 * - numbers starting with '+'
 * - NaN, -NaN, infinity, -infinity
 * - hexadecimal numbers
 * - numbers with leading zeros
 *
 * json_is_invalid_number() detects "numbers" which may pass strtod()'s
 * error checking, but should not be allowed with strict JSON.
 *
 * json_is_invalid_number() may pass numbers which cause strtod()
 * to generate an error.
 */
static int json_is_invalid_number(json_parse_t *json)
{
    const char *p = json->ptr;

    if( *p == '+' ) { /* Reject numbers starting with + */
        return 1;
    }
    if (*p == '-') { /* Skip minus sign if it exists */
        p++;
    }
    if (*p == '0') { /* Reject numbers starting with 0x, or leading zeros */
	int ch2 = *(p + 1);
	if( (ch2 | 0x20) == 'x' /* Hex */ || ('0' <= ch2 && ch2 <= '9') /* Leading zero */ ) { 
	    return 1;
	}
	return 0;
    } else if( *p <= '9' ) {
	return 0; /* Ordinary number */
    }
    /* Reject inf/nan */
    if( !strncasecmp(p, "inf", 3) ) {
	return 1;
    }
    if( !strncasecmp(p, "nan", 3) ) {
	return 1;
    }

    /* Pass all other numbers which may still be invalid, but
     * strtod() will catch them. */
    return 0;
}

static void json_next_number_token(json_parse_t *json, json_token_t *token)
{
    char *endptr;

    token->type = T_NUMBER;
    token->number = strtod(json->ptr, &endptr);
    if( json->ptr == endptr ) {
	json_set_token_error(token, json, "invalid number");
    } else {
	json->ptr = endptr;     /* Skip the processed number */
    }

    return;
}

/* Fills in the token struct.
 * T_STRING will return a pointer to the json_parse_t temporary string
 * T_ERROR will leave the json->ptr pointer at the error.
 */
static void json_next_token(json_parse_t *json, json_token_t *token)
{
    const json_token_type_t *ch2token;
    int ch;

    ch2token = json->cfg->ch2token;
    /* Eat whitespace. */
    while( 1 ) {
	ch = (unsigned char)*(json->ptr);
	token->type = ch2token[ch];
	if (token->type != T_WHITESPACE) {
	    break;
	}
	json->ptr++;
    }

    /* Store location of new token. Required when throwing errors
     * for unexpected tokens (syntax errors). */
    token->index = json->ptr - json->data;

    /* Don't advance the pointer for an error or the end */
    if( token->type == T_ERROR ) {
	json_set_token_error(token, json, "invalid token");
	return;
    }
    if( token->type == T_END ) {
	return;
    }
    /* Found a known single character token, advance index and return */
    if( token->type != T_UNKNOWN ) {
	json->ptr++;
	return;
    }

    /* Process characters which triggered T_UNKNOWN
     *
     * Must use strncmp() to match the front of the JSON string.
     * JSON identifier must be lowercase.
     * When strict_numbers if disabled, either case is allowed for
     * Infinity/NaN (since we are no longer following the spec..) */
    if( ch == '"' ) {
	json_next_string_token(json, token);
    } else if( ch == '-' || ('0' <= ch && ch <= '9') ) {
	if( !json->cfg->decode_invalid_numbers && json_is_invalid_number(json) ) {
	    json_set_token_error(token, json, "invalid number");
        } else {
	    json_next_number_token(json, token);
	}
    } else if( !strncmp(json->ptr, "true", 4) ) {
	token->type = T_BOOLEAN;
	token->boolean = 1;
	json->ptr += 4;
    } else if( !strncmp(json->ptr, "false", 5) ) {
	token->type = T_BOOLEAN;
	token->boolean = 0;
	json->ptr += 5;
    } else if( !strncmp(json->ptr, "null", 4) ) {
	token->type = T_NULL;
	json->ptr += 4;
    } else if (json->cfg->decode_invalid_numbers && json_is_invalid_number(json)) {
	/* When decode_invalid_numbers is enabled, only attempt to process
	 * numbers we know are invalid JSON (Inf, NaN, hex)
	 * This is required to generate an appropriate token error,
	 * otherwise all bad tokens will register as "invalid number"
	 */
	json_next_number_token(json, token);
    } else {
	/* Token starts with t/f/n but isn't recognised above. */
	json_set_token_error(token, json, "invalid token");
    }
}

static int json_throw_parse_error(lua_State *L, json_parse_t *json, const char *exp, json_token_t *token)
{
    const char *errmsg;
    errmsg = lua_pushfstring(L, "expected %s but found %s at character %d.",
	exp, token->type == T_ERROR && token->string != NULL ?
	token->string : json_token_type_name[token->type], token->index + 1);
    if( token->string != NULL ) {
	free(token->string);
	token->string = NULL;
	json->debug_frees++;
    }
    /* This function does not return. */
    return luaL_error(L, errmsg);
}

static inline void json_decode_ascend(json_parse_t *json)
{
    json->current_depth--;
}

static void json_decode_descend(lua_State *L, json_parse_t *json, int slots)
{
    json->current_depth++;

    if( !(json->current_depth <= json->cfg->decode_max_depth && lua_checkstack(L, slots)) ) {
	luaL_error(L, "found too many nested data structures (%d) at character %d",
	    json->current_depth, json->ptr - json->data);
    }
}

static void json_parse_object_context(lua_State *L, json_parse_t *json)
{
    json_token_t token;

    memset(&token, 0, sizeof(token));
    json_decode_descend(L, json, 3); /* 3 slots required: table, key, value */
    lua_newtable(L);
    json_next_token(json, &token);

    /* Handle empty objects */
    if( token.type == T_OBJ_END ) {
        json_decode_ascend(json);
        return;
    }
    while( 1 ) {
	if (token.type != T_STRING) {
	    json_throw_parse_error(L, json, "object key string", &token);
	    return;
	}
	lua_pushlstring(L, token.string, token.string_len);
	json_cleanup_token(json, &token);

	json_next_token(json, &token);
	if( token.type != T_COLON ) {
	    json_throw_parse_error(L, json, "colon", &token);
	    return;
	}

	/* Fetch value */
	json_next_token(json, &token);
	json_process_value(L, json, &token);
	json_cleanup_token(json, &token);

	/* Set key = value */
	lua_rawset(L, -3);

	json_next_token(json, &token);
	if (token.type == T_OBJ_END) {
	    json_decode_ascend(json);
	    return;
	}
	if( token.type != T_COMMA ) {
	    json_throw_parse_error(L, json, "comma or object end", &token);
	    return;
	}

	json_cleanup_token(json, &token);
	json_next_token(json, &token);
    }
}

static void json_parse_array_context(lua_State *L, json_parse_t *json)
{
    json_token_t token;
    int i;

    memset(&token, 0, sizeof(token));
    json_decode_descend(L, json, 2); /* 2 slots required: table, value */
    lua_newtable(L);

    json_next_token(json, &token);

    if( token.type == T_ARR_END ) { /* Handle empty arrays */
	json_decode_ascend(json);
	return;
    }
    for( i = 1; ; i++ ) {
	json_process_value(L, json, &token);
	json_cleanup_token(json, &token);
	lua_rawseti(L, -2, i);            /* arr[i] = value */

	json_next_token(json, &token);

	if( token.type == T_ARR_END ) {
	    json_decode_ascend(json);
	    return;
	}
	if( token.type != T_COMMA ) {
	    json_throw_parse_error(L, json, "comma or array end", &token);
	    return;
	}

	json_next_token(json, &token);
    }
}

static void json_process_value(lua_State *L, json_parse_t *json, json_token_t *token)
{
    switch (token->type) {
    case T_STRING:
	lua_pushlstring(L, token->string, token->string_len);
	break;
    case T_NUMBER:
	lua_pushnumber(L, token->number);
	break;
    case T_BOOLEAN:
	lua_pushboolean(L, token->boolean);
	break;
    case T_OBJ_BEGIN:
	json_parse_object_context(L, json);
	break;
    case T_ARR_BEGIN:
	json_parse_array_context(L, json);
	break;
    case T_NULL:
	/* In Lua, setting "t[k] = nil" will delete k from the table.
	 * Hence a NULL pointer lightuserdata object is used instead */
	lua_pushlightuserdata(L, NULL);
	break;;
    default:
	json_throw_parse_error(L, json, "value", token);
    }
}

static int json_decode(lua_State *L)
{
    json_parse_t json;
    json_token_t token;
    size_t json_len;

    luaL_argcheck(L, lua_gettop(L) == 1, 1, "expected 1 argument");
    json.cfg = json_fetch_config(L);
    json.data = luaL_checklstring(L, 1, &json_len);
    json.current_depth = 0;
    json.ptr = json.data;
    json.debug_allocs = json.debug_frees = 0;
    memset(&token, 0, sizeof(token));

    /* Detect Unicode other than UTF-8 (see RFC 4627, Sec 3)
     *
     * CJSON can support any simple data type, hence only the first
     * character is guaranteed to be ASCII (at worst: '"'). This is
     * still enough to detect whether the wrong encoding is in use. */
    if( json_len >= 2 && (!json.data[0] || !json.data[1]) ) {
	return luaL_error(L, "JSON parser does not support UTF-16 or UTF-32");
    }

    json_next_token(&json, &token);
    json_process_value(L, &json, &token);
    json_cleanup_token(&json, &token);
    /* Ensure there is no more input left */
    json_next_token(&json, &token);
    json_cleanup_token(&json, &token);

    if( json.debug_allocs != json.debug_frees && stderr != NULL ) {
	fprintf(stderr, OMOBUS_JPREFIX " memory leak. Toatal allocs %d, frees %d", 
	    json.debug_allocs, json.debug_frees);
    }

    return token.type != T_END ? json_throw_parse_error(L, &json, "the end", &token) : 1;
}

/* Call target function in protected mode with all supplied args.
 * Assumes target function only returns a single non-nil value.*
 * Convert and return thrown errors as: nil, "error message" */
static int json_protect_conversion(lua_State *L)
{
    int err;

    /* Deliberately throw an error for invalid arguments */
    luaL_argcheck(L, lua_gettop(L) == 1, 1, "expected 1 argument");

    /* pcall() the function stored as upvalue(1) */
    lua_pushvalue(L, lua_upvalueindex(1));
    lua_insert(L, 1);
    err = lua_pcall(L, 1, 1, 0);
    if( !err ) {
        return 1;
    }
    if( err == LUA_ERRRUN ) {
        lua_pushnil(L);
        lua_insert(L, -2);
        return 2;
    }

    /* Since we are not using a custom error handler, the only remaining
     * errors are memory related. */
    return luaL_error(L, "memory allocation error in JSON protected call.");
}

static const luaL_Reg json_funcs[] = {
    { "encode", json_encode },
    { "decode", json_decode },
    { "encode_sparse_array", json_cfg_encode_sparse_array },
    { "encode_max_depth", json_cfg_encode_max_depth },
    { "decode_max_depth", json_cfg_decode_max_depth },
    { "encode_number_precision", json_cfg_encode_number_precision },
    { "encode_invalid_numbers", json_cfg_encode_invalid_numbers },
    { "decode_invalid_numbers", json_cfg_decode_invalid_numbers },
    { "new", lua_json_new },
    { NULL, NULL }
};

static int lua_json_new(lua_State *L)
{
    lua_newtable(L);
    json_create_config(L);
    luaL_setfuncs(L, json_funcs, 1);
    /* Set json.null */
    lua_pushlightuserdata(L, NULL);
    lua_setfield(L, -2, "null");
    return 1;
}

static int lua_json_safe_new(lua_State *L)
{
    static const char *func[] = { "decode", "encode", NULL };
    int i;

    lua_json_new(L);

    /* Fix new() method */
    lua_pushcfunction(L, lua_json_safe_new);
    lua_setfield(L, -2, "new");

    for (i = 0; func[i]; i++) {
        lua_getfield(L, -1, func[i]);
        lua_pushcclosure(L, json_protect_conversion, 1);
        lua_setfield(L, -2, func[i]);
    }

    return 1;
}

int luaopen_json(lua_State *L)
{
    lua_json_new(L);
    return 1;
}

int luaopen_json_safe(lua_State *L)
{
    lua_json_safe_new(L);
    return 1;
}
