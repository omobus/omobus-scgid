/* -*- H -*- */
/* Copyright (c) 2006 - 2022 omobus-scgid authors, see the included COPYRIGHT file. */

#ifndef __omobus_scgid_h__
#define __omobus_scgid_h__

#define OMOBUS_STRINGIZE(X) 		OMOBUS_DO_STRINGIZE(X)
#define OMOBUS_DO_STRINGIZE(X) 		#X
#define OMOBUS_JPREFIX			__BASE_FILE__ ":" OMOBUS_STRINGIZE(__LINE__) " "

#define OMOBUS_OK 			0
#define OMOBUS_ERR 			-1

#ifndef SOCKET_ERROR
# define SOCKET_ERROR			(-1)
#endif //SOCKET_ERROR

#define charbufsize(buf)		(sizeof(buf)/sizeof(buf[0]) - 1)
#define chk_free(ptr)			if( ptr != NULL ) free(ptr); ptr = NULL;
#define chk_fclose(ptr)			if( ptr != NULL ) fclose(ptr); ptr = NULL;
#define chk_strdup(ptr)			(ptr==NULL?NULL:strdup(ptr))
#define allocate_memory_error(msg)	logmsg_e(">>> PANIC <<< unable to allocate memory at %s, line %d, msg: %s", __BASE_FILE__, __LINE__, msg)
#define closesocket			close
#define sock_errno()			errno

#ifdef __cplusplus
extern "C" {
#endif

void logmsg_e(const char *fmt, ...);
void logmsg_w(const char *fmt, ...);

#ifdef __cplusplus
} //extern "C"
#endif

#endif //__omobus_scgid_h__
