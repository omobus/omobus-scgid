/* -*- C -*- */
/* Copyright (c) 2006 - 2020 omobus-scgid authors, see the included COPYRIGHT file. */

#include <memory.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include "connect_timed.h"
#include "omobus-scgid.h"

int connect_timed(int sockfd, const struct sockaddr *saptr, socklen_t salen, int nsec)
{
    int n, error, rc, flags;
    socklen_t len;
    fd_set rset, wset;
    struct timeval tval;

    error = rc = 0;
    flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    if( (n = connect(sockfd, saptr, salen)) < 0) {
	if (errno != EINPROGRESS) {
	    error = errno;
	    fcntl(sockfd, F_SETFL, flags);
	    errno = error;
	    return SOCKET_ERROR;
	}
    }

    if( n == 0 ) {
	fcntl(sockfd, F_SETFL, flags);
	errno = 0;
	return 0;
    }

    FD_ZERO(&rset);
    FD_SET(sockfd, &rset);
    wset = rset;
    tval.tv_sec = nsec;
    tval.tv_usec = 0;

    if( (n = select(sockfd + 1, &rset, &wset, NULL, nsec ? &tval : NULL)) == 0 ) {
	fcntl(sockfd, F_SETFL, flags);
	errno = ETIMEDOUT;
	return SOCKET_ERROR;
    }

    if( FD_ISSET(sockfd, &rset) || FD_ISSET(sockfd, &wset) ) {
	len = sizeof(error);
	if( getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 ) {
	    /* Solaris pending error */
	    if( error == 0 )
		error = errno != 0 ? errno : EINVAL;
	}
    } else {
	/* select error: sockfd not set */
	error = EINVAL;
    }

    fcntl(sockfd, F_SETFL, flags);

    if( error != 0 ) {
	errno = error;
	rc = SOCKET_ERROR;
    }

    return rc;
}
