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

#include <malloc.h>  /* For _alloca() */

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <windows.h>
#include <time.h>
#include <process.h>


/**********************************************************************
 * Temporary work-around until I can get the MSVC build system to
 * set the version and source checksum definitions.
 */

#ifndef SFNT_VERSION
#define SFNT_VERSION "<Unknown>"
#endif

#ifndef SFNT_SRC_CSUM
#define SFNT_SRC_CSUM "<Not calculated>"
#endif

#define MSG_MORE 0


/**********************************************************************
 * Platform configuration
 */

#define NT_LITTLE_ENDIAN   1

#define NT_SUPPORTS_ONLOAD 0

#define NT_HAVE_FIONBIO    1

#define NT_HAVE_POLL       0
#define NT_HAVE_EPOLL      0


/**********************************************************************
 * Work-around WIN32 breakage of sockets interface.
 */

typedef intptr_t ssize_t;
typedef unsigned int nfds_t;
typedef uint32_t in_addr_t;
typedef uint16_t in_port_t;

static inline int __nt_accept(int fd, struct sockaddr* addr, socklen_t* addrlen)
{
  return (int) accept(fd, addr, addrlen);
}
#define accept __nt_accept


static inline int __nt_bind(int fd, const struct sockaddr* addr, socklen_t addrlen)
{
  return bind(fd, addr, addrlen);
}
#define bind __nt_bind


static inline int __nt_close(int fd)
{
  return closesocket(fd);
}
#define close __nt_close


static inline int __nt_connect(int fd, const struct sockaddr* addr, socklen_t addrlen)
{
  return connect(fd, addr, addrlen);
}
#define connect __nt_connect


static inline int __nt_ioctl(int fd, long cmd, void* argp)
{
  return ioctlsocket(fd, cmd, argp);
}
#define ioctl __nt_ioctl


static inline ssize_t __nt_recv(int fd, void* buf, size_t len, int flags)
{
  ssize_t rc;
  size_t got = 0;
  int all = flags & MSG_WAITALL;
  flags &= ~MSG_WAITALL;
  do {
    if( (rc = recv(fd, (char*) buf + got, (int) (len - got), flags)) > 0 )
      got += rc;
  } while( all && got < len && rc > 0 );
  return got ? got : rc;
}
#define recv __nt_recv


static inline ssize_t __nt_recvfrom(int fd, void* buf, size_t len, int flags,
                                    struct sockaddr* from, socklen_t* fromlen)
{
  ssize_t rc;
  size_t got = 0;
  int all = flags & MSG_WAITALL;
  flags &= ~MSG_WAITALL;
  do {
    if( (rc = recvfrom(fd, (char*) buf + got, (int) (len - got), flags, from, fromlen)) > 0 )
      got += rc;
  } while( all && got < len && rc > 0 );
  return got ? got : rc;
}
#define recvfrom __nt_recvfrom


static inline ssize_t __nt_send(int fd, const void* buf, size_t len, int flags)
{
  return send(fd, (const char*) buf, (int) len, flags);
}
#define send __nt_send


static inline ssize_t __nt_sendto(int fd, const void* buf, size_t len, int flags,
                                  const struct sockaddr* addr, socklen_t addrlen)
{
  return sendto(fd, (const char*) buf, (int) len, flags, addr, (int) addrlen);
}
#define sendto __nt_sendto


#ifndef SOL_IP
#define SOL_IP IPPROTO_IP
#endif

#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

static inline int __nt_setsockopt(int fd, int level, int optname,
                                  const void* optval, socklen_t optlen)
{
  return setsockopt(fd, level, optname, (const char*) optval, (int) optlen);
}
#define setsockopt __nt_setsockopt


static inline int __nt_socket(int domain, int type, int protocol)
{
  return (int) socket(domain, type, protocol);
}
#define socket __nt_socket


static inline uint64_t monotonic_clock_freq(void)
{
  LARGE_INTEGER f;
  QueryPerformanceFrequency(&f);
  return f.QuadPart;
}


static inline uint64_t monotonic_clock(void)
{
  LARGE_INTEGER f;
  QueryPerformanceCounter(&f);
  return f.QuadPart;
}


/**********************************************************************
 * Work-around lack of sleep() and usleep()
 */

static inline unsigned int __nt_sleep(unsigned int seconds)
{
  Sleep(seconds * 1000);
  return 0;
}
#define sleep __nt_sleep


typedef uint64_t useconds_t;

static inline int __nt_usleep(useconds_t usec)
{
  Sleep((DWORD)(usec / 1000));
  return 0;
}
#define usleep __nt_usleep


/**********************************************************************
 * Work-around lack of strcasecmp()
 */
#define strcasecmp _stricmp


/**********************************************************************
 * Use _strdup() rather than strdup()
 */
#define strdup _strdup


/**********************************************************************
 * Use _alloca() rather than alloca()
 */
#define alloca _alloca


/**********************************************************************
 * Work-around lack of pthreads.
 *
 * This is nowhere near a full implementation, extend as necessary.
 */

typedef void* pthread_mutexattr_t;
typedef CRITICAL_SECTION pthread_mutex_t;
#define PTHREAD_MUTEX_INITIALIZER NT_FEATURE_NOT_SUPPORTED

static inline int __nt_pthread_mutex_destroy(pthread_mutex_t* mutex)
{
  DeleteCriticalSection((PCRITICAL_SECTION) mutex);
  return 0;
}
#define pthread_mutex_destroy __nt_pthread_mutex_destroy

static inline int __nt_pthread_mutex_init(pthread_mutex_t* mutex, 
                                          const pthread_mutexattr_t* attr)
{
  if (attr)
    return EINVAL;
  InitializeCriticalSection((PCRITICAL_SECTION) mutex);
  return 0;
}
#define pthread_mutex_init __nt_pthread_mutex_init


static inline int __nt_pthread_mutex_lock(pthread_mutex_t* mutex)
{
  EnterCriticalSection((PCRITICAL_SECTION) mutex);
  return 0;
}
#define pthread_mutex_lock __nt_pthread_mutex_lock


static inline int __nt_pthread_mutex_trylock(pthread_mutex_t* mutex)
{
  return TryEnterCriticalSection((PCRITICAL_SECTION) mutex) ? 0 : EBUSY;
}
#define pthread_mutex_trylock __nt_pthread_mutex_trylock


static inline int __nt_pthread_mutex_unlock(pthread_mutex_t* mutex)
{
  LeaveCriticalSection((PCRITICAL_SECTION) mutex);
  return 0;
}
#define pthread_mutex_unlock __nt_pthread_mutex_unlock


struct timespec {
  time_t  tv_sec;
  long    tv_nsec;
};

typedef enum clockid_e {
  CLOCK_REALTIME = 0,
} clockid_t;

static inline int __nt_clock_gettime(clockid_t clk_id, struct timespec* tp)
{
  if (clk_id != CLOCK_REALTIME)
    return EINVAL;
  if (!tp)
    return EFAULT;
  /* Huge hack, we only use this for working out the absolute time for a
   * relative pthread_cond_timedwait() so we can cheat and fill in zero
   * to make the time relative.
   */
  tp->tv_sec = 0;
  tp->tv_nsec = 0;
  return 0;
}
#define clock_gettime __nt_clock_gettime


typedef void* pthread_condattr_t;
typedef CONDITION_VARIABLE pthread_cond_t;
#define PTHREAD_COND_INITIALIZER NT_FEATURE_NOT_SUPPORTED

static inline int pthread_cond_broadcast(pthread_cond_t* cond)
{
  WakeAllConditionVariable((PCONDITION_VARIABLE) cond);
  return 0;
}
#define pthread_cond_broadcast __nt_pthread_cond_broadcast


static inline int __nt_pthread_cond_destroy(pthread_cond_t* cond)
{
  return 0;
}
#define pthread_cond_destroy __nt_pthread_cond_destroy

static inline int __nt_pthread_cond_init(pthread_cond_t* cond, 
                                         const pthread_condattr_t* attr)
{
  if (attr)
    return EINVAL;
  InitializeConditionVariable((PCONDITION_VARIABLE) cond);
  return 0;
}
#define pthread_cond_init __nt_pthread_cond_init


static inline int __nt_pthread_cond_signal(pthread_cond_t* cond)
{
  WakeConditionVariable((PCONDITION_VARIABLE) cond);
  return 0;
}
#define pthread_cond_signal __nt_pthread_cond_signal


static inline int __nt_pthread_cond_wait(pthread_cond_t* cond,
                                         pthread_mutex_t* mutex)
{
  (VOID) SleepConditionVariableCS((PCONDITION_VARIABLE) cond,
                                  (PCRITICAL_SECTION) mutex, INFINITE);
  return 0;
}
#define pthread_cond_wait __nt_pthread_cond_wait


static inline int __nt_pthread_cond_timedwait(pthread_cond_t* cond, 
                                              pthread_mutex_t* mutex,
                                              const struct timespec* abstime)
{
  DWORD ms;
  if (!abstime)
    return EINVAL;
  /* Huge hack, abstime is effectively relative as clock_gettime always
   * outputs a zero timespec!
   */
  ms = (DWORD)((abstime->tv_sec * 1000) + (abstime->tv_nsec / 1000000));
  return SleepConditionVariableCS((PCONDITION_VARIABLE) cond,
                                  (PCRITICAL_SECTION) mutex, ms ) ?
         0 : ETIMEDOUT;
}
#define pthread_cond_timedwait __nt_pthread_cond_timedwait


typedef HANDLE pthread_t;
typedef void* pthread_attr_t;
struct __nt_pthread_start_args_wrapper {
  void* (*start_routine)(void*);
  void* arg;
};


static unsigned __stdcall __nt_pthread_start_routine_wrapper(void* arglist)
{
  struct __nt_pthread_start_args_wrapper real_args;
  if (arglist) {
    real_args = *((struct __nt_pthread_start_args_wrapper*) arglist);
    free(arglist);
    real_args.start_routine(real_args.arg);
  }
  _endthreadex(0);
  return 0;
}

static inline int __nt_pthread_create(pthread_t* thread,
                                      const pthread_attr_t* attr,
                                      void* (*start_routine)(void*), void *arg)
{
  struct __nt_pthread_start_args_wrapper* real_args;
  if (attr)
    return EINVAL;
  real_args = (struct __nt_pthread_start_args_wrapper*)
              malloc(sizeof(struct __nt_pthread_start_args_wrapper));
  if (!real_args)
    return EAGAIN;
  real_args->start_routine = start_routine;
  real_args->arg = arg;
  *thread = (pthread_t) _beginthreadex(NULL, 0,
                                       __nt_pthread_start_routine_wrapper,
                                       (void*) real_args, 0, NULL);
  return (*thread) ? 0 : errno;
}
#define pthread_create __nt_pthread_create


#endif  /* __SFNETTEST_WIN32_H__ */
