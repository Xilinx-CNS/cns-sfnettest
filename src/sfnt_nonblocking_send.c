/**************************************************************************\
*    Filename: sfnt_nonblocking_send.c
*      Author: Frank Burton <fburton@solarflare.com>
* Description: Wrapper for non-blocking UDP sends on FreeBSD
*   Copyright: (C) 2005-2015 Solarflare Communications Inc.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License version 2 as published
* by the Free Software Foundation, incorporated herein by reference.
\**************************************************************************/

#ifdef __FreeBSD__
/* On FreeBSD UDP send is non blocking and can fail
 * We need to capture the ENOBUFF errors and resend if this occurs
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

ssize_t sfnt_send_freebsd(int sockfd, const void *buf, size_t len, int flags)
{
  ssize_t rc;
  do {
    rc = send(sockfd, buf, len, flags);
  } while( rc < 0 && errno == ENOBUFS );
  return rc;
}

ssize_t sfnt_sendto_freebsd(int sockfd, const void *buf, size_t len, int flags,
    const struct sockaddr *dest_addr, socklen_t addrlen)
{
  ssize_t rc;
  do {
    rc = sendto(sockfd, buf, len, flags, dest_addr, addrlen);
  } while( rc < 0 && errno == ENOBUFS );
  return rc;
}

ssize_t sfnt_sendmsg_freebsd(int sockfd, const struct msghdr *msg, int flags)
{
  ssize_t rc;
  do {
    rc = sendmsg(sockfd, msg, flags);
  } while( rc < 0 && errno == ENOBUFS );
  return rc;
}
#endif
