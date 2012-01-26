/**************************************************************************\
*    Filename: sfnettest_waitall_hack.h
*      Author: David Riddoch <driddoch@solarflare.com>
* Description: Hack to work-around stacks without MSG_WAITALL support.
*   Copyright: (C) 2012 Solarflare Communications Inc.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License version 2 as published
* by the Free Software Foundation, incorporated herein by reference.
\**************************************************************************/

#ifndef __SFNETTEST_WAITALL_HACK_H__
#define __SFNETTEST_WAITALL_HACK_H__

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>


static inline ssize_t
sfnt_recv_waitall_hack(int fd, void* buf, size_t len, int flags)
{
  int rc, got = 0, all = flags & MSG_WAITALL;
  flags &= ~MSG_WAITALL;
  do {
    if( (rc = recv(fd, (char*) buf + got, len - got, flags)) > 0 )
      got += rc;
  } while( all && got < len && rc > 0 );
  return got ? got : rc;
}

#undef recv
#define recv sfnt_recv_waitall_hack


static inline ssize_t
sfnt_recvfrom_waitall_hack(int fd, void* buf, size_t len, int flags,
                           struct sockaddr* from, socklen_t* fromlen)
{
  int rc, got = 0, all = flags & MSG_WAITALL;
  flags &= ~MSG_WAITALL;
  do {
    if( (rc = recvfrom(fd, (char*) buf + got, len - got,
                       flags, from, fromlen)) > 0 )
      got += rc;
  } while( all && got < len && rc > 0 );
  return got ? got : rc;
}

#undef recvfrom
#define recvfrom sfnt_recvfrom_waitall_hack


#if 0  /* TODO if/when needed -- more complex than recv and recvfrom! */
static inline ssize_t
sfnt_recvmsg_waitall_hack(int s, struct msghdr *msg, int flags)
{
  int rc, got = 0, all = flags & MSG_WAITALL;
  flags &= ~MSG_WAITALL;
  do {
    if( (rc = recvmsg(fd, (char*) buf + got, len - got, flags)) > 0 )
      got += rc;
  } while( all && got < len && rc > 0 );
  return got ? got : rc;
}
#endif

#undef recvmsg
#define recvmsg sfnt_recvmsg_waitall_hack


#endif  /* __SFNETTEST_WAITALL_HACK_H__ */
