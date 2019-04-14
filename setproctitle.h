/* -*- H -*- */
/* Copyright (c) 2006 - 2019 omobus-scgid authors, see the included COPYRIGHT file. */

#ifndef __setproctitle_h__
#define __setproctitle_h__

#ifdef HAVE_SETPROCTITLE
# define initproctitle(argc, argv)
#else
void initproctitle(int argc, char **argv);
void setproctitle(const char *fmt, ...);
#endif //HAVE_SETPROCTITLE

#endif //__setproctitle_h__
