/* -*- H -*- */
/* This file is a part of the omobusd project.
 * Major portions taken verbatim or adapted from the Lua interpreter.
 * Copyright (C) 1994-2015 Lua.org, PUC-Rio. See Copyright Notice in COPYRIGHT.Lua.
 */

#ifndef l_prefix_h
#define l_prefix_h

#if !defined(LUA_USE_C89)
# if !defined(_XOPEN_SOURCE)
#  define _XOPEN_SOURCE           600
# elif _XOPEN_SOURCE == 0
#  undef _XOPEN_SOURCE  /* use -D_XOPEN_SOURCE=0 to undefine it */
# endif
/* Allows manipulation of large files in gcc and some other compilers */
# if !defined(LUA_32BITS) && !defined(_FILE_OFFSET_BITS)
#  define _LARGEFILE_SOURCE       1
#  define _FILE_OFFSET_BITS       64
# endif
#endif // ! LUA_USE_C89

#endif //l_prefix_h

