/* -*- H -*- */
/* This file is a part of the omobusd project.
 * Major portions taken verbatim or adapted from the Lua interpreter.
 * Copyright (C) 1994-2015 Lua.org, PUC-Rio. See Copyright Notice in COPYRIGHT.Lua.
 */

#ifndef lapi_h
#define lapi_h


#include "l_limits.h"
#include "l_state.h"

#define api_incr_top(L)   {L->top++; api_check(L, L->top <= L->ci->top, \
				"stack overflow");}

#define adjustresults(L,nres) \
    { if ((nres) == LUA_MULTRET && L->ci->top < L->top) L->ci->top = L->top; }

#define api_checknelems(L,n)	api_check(L, (n) < (L->top - L->ci->func), \
				  "not enough elements in the stack")


#endif
