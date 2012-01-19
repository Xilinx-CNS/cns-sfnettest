/**************************************************************************\
*    Filename: sfnettest_unix.h
*      Author: David Riddoch <driddoch@solarflare.com>
* Description: Compatibility layer for UNIX platforms.
*   Copyright: (C) 2005-2012 Solarflare Communications Inc.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License version 2 as published
* by the Free Software Foundation, incorporated herein by reference.
\**************************************************************************/

#ifndef __SFNETTEST_UNIX_H__
#define __SFNETTEST_UNIX_H__

#include <unistd.h>
#include <poll.h>
#include <signal.h>
#ifdef __linux__
# include <sys/epoll.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#if defined(__FreeBSD__)
# include <sys/endian.h>
#elif defined(__linux__)
# include <endian.h>
#elif defined(__APPLE__)
# include <machine/endian.h>
#elif defined(__sun__)
# include <sys/isa_defs.h>
#endif
#ifdef __MACH__
# include <mach/clock.h>
# include <mach/mach.h>
#endif
#include <pthread.h>

#if defined(__linux__)
# define NT_SUPPORTS_ONLOAD 1
#else
# define NT_SUPPORTS_ONLOAD 0
#endif

#define NT_HAVE_POLL    1
#if defined(__linux__)
# define NT_HAVE_EPOLL   1
#elif defined(__sun__) || defined(__FreeBSD__) || defined(__APPLE__)
# define NT_HAVE_EPOLL   0
#else
# error "Please define NT_HAVE_EPOLL for this platform"
#endif

#if defined(__linux__)
# define NT_HAVE_SO_BINDTODEVICE 1
#elif defined(__sun__) || defined(__APPLE__)  || defined(__FreeBSD__)
# define NT_HAVE_SO_BINDTODEVICE 0
#else
# error "Please define NT_HAVE_SO_BINDTODEVICE for this platform"
#endif

#if defined(__linux__) || defined(__FreeBSD__)
# define NT_HAVE_IP_MREQN 1
#elif defined(__sun__) || defined(__APPLE__)
# define NT_HAVE_IP_MREQN 0
#else
# error "Please define NT_HAVE_IP_MREQN for this platform"
#endif

#if defined(__linux__) || defined(__FreeBSD__) || defined(__APPLE__)
# define NT_HAVE_FIONBIO 1
#elif defined(__sun__) 
# define NT_HAVE_FIONBIO 0
#else
# error "Please define NT_HAVE_FIONBIO for this platform"
#endif

#ifdef __GNUC__
# define NT_PRINTF_LIKE(a, b)  __attribute__((format(printf,a,b)))
#else
# define NT_PRINTF_LIKE(a, b)
#endif

#if defined(__linux__) || defined(__FreeBSD__)
# define NT_LITTLE_ENDIAN  (__BYTE_ORDER == __LITTLE_ENDIAN)
#elif defined(__APPLE__)
# define NT_LITTLE_ENDIAN  (__DARWIN_BYTE_ORDER == __DARWIN_LITTLE_ENDIAN)
#elif defined(__sun__)
# ifdef _LITTLE_ENDIAN
#  define NT_LITTLE_ENDIAN 1
# else
#  define NT_LITTLE_ENDIAN 0
# endif
#else
# error "Please define NT_LITLE_ENDIAN for this platform"
#endif

#if !defined(SOL_IP)
# define SOL_IP IPPROTO_IP
#endif
#if !defined(SOL_TCP)
# define SOL_TCP IPPROTO_TCP
#endif


#endif  /* __SFNETTEST_UNIX_H__ */
