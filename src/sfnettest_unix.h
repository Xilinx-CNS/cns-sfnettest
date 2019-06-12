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
# include <sys/param.h>
# include <sys/cpuset.h>
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
#if defined(__FreeBSD__)
#include <stdlib.h>
#else
#include <alloca.h>
#endif
#include <pthread.h>
#include <sched.h>
#include <fcntl.h>

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

#if defined(__linux__)
#elif defined(__sun__) || defined(__APPLE__)  || defined(__FreeBSD__)
# define MSG_MORE 0
#else
# error "Please decide whether to define MSG_MORE for this platform"
#endif

#if defined(__linux__)
# define NT_HAVE_IP_MREQN 1
#elif defined(__sun__) || defined(__APPLE__) || defined(__FreeBSD__)
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

#ifndef NT_PRINTF_LIKE
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


#if defined(__sun__) || defined(__APPLE__) || defined(__FreeBSD__)
# ifndef __NFDBITS
#  define __NFDBITS NFDBITS
# endif
# ifndef __FDS_BITS
#  define __FDS_BITS(fds) &(fds)->fds_bits[0]
# endif
#endif


#ifdef __APPLE__
typedef int clockid_t;
#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 6
extern int clock_gettime(clockid_t clk_id, struct timespec* ts);
#endif

#ifdef __FreeBSD__
/*  On FreeBSD UDP send is non blocking and can fail
 *  We need to capture the ENOBUFF errors and resend if this occur
 */

extern ssize_t sfnt_send_freebsd(int sockfd, const void *buf, size_t len, int flags);

extern ssize_t sfnt_sendto_freebsd(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen);

extern ssize_t sfnt_sendmsg_freebsd(int sockfd, const struct msghdr *msg, int flags);

#define send     sfnt_send_freebsd
#define sendto   sfnt_sendto_freebsd
#define sendmsg  sfnt_sendmsg_freebsd
#endif

static inline uint64_t monotonic_clock_freq(void)
{
  return 1000000000;
}


static inline uint64_t monotonic_clock(void)
{
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}

#endif  /* __SFNETTEST_UNIX_H__ */
