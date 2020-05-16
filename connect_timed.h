/* -*- H -*- */
/* Copyright (c) 2006 - 2020 omobus-scgid authors, see the included COPYRIGHT file. */

#ifndef __connect_timed_h__
#define __connect_timed_h__

#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#ifdef __cplusplus
extern "C" {
#endif

int connect_timed(int sockfd, const struct sockaddr *saptr, socklen_t salen, int nsec);

#ifdef __cplusplus
} //extern "C"
#endif

#endif //__connect_timed_h__

