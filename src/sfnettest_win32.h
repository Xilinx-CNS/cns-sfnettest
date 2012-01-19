/**************************************************************************\
*    Filename: sfnettest_win32.h
*      Author: David Riddoch <driddoch@solarflare.com>
* Description: Compatibility layer for _WIN32 API.
*   Copyright: (C) 2005-2012 Solarflare Communications Inc.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License version 2 as published
* by the Free Software Foundation, incorporated herein by reference.
\**************************************************************************/

#ifndef __SFNETTEST_WIN32_H__
#define __SFNETTEST_WIN32_H__

#define NT_SUPPORTS_ONLOAD 0

#define NT_HAVE_POLL    0
#define NT_HAVE_EPOLL   0


#define NT_PRINTF_LIKE(a, b)


#ifndef SOL_IP
#define SOL_IP 0
#endif


/**********************************************************************
 * Work-around WIN32 breakage of sockets interface.
 */

static __inline ssize_t __nt_recv(int fd, void* buf, size_t len, int flags)
{
  return recv(fd, (char*) buf, len, flags);
}
#define recv __nt_recv


#endif  /* __SFNETTEST_WIN32_H__ */
