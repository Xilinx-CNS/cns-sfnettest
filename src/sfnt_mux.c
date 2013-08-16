/**************************************************************************\
*    Filename: sfnt_mux.c
*      Author: David Riddoch <driddoch@solarflare.com>
* Description: Muxer convenience routines.
*   Copyright: (C) 2005-2012 Solarflare Communications Inc.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License version 2 as published
* by the Free Software Foundation, incorporated herein by reference.
\**************************************************************************/

#include "sfnettest.h"


#define return_now(rc, flags, timeout)                                  \
  ( (rc) > 0 ||                                                         \
    ((rc) == 0 && !((flags) & NT_MUX_SPIN)) ||                          \
    ((rc) < 0 && (!((flags) & NT_MUX_CONTINUE_ON_EINTR) || errno != EINTR)) \
  )


static inline uint64_t get_tsc(void)
{
  uint64_t tsc;
  sfnt_tsc(&tsc);
  return tsc;
}


static uint64_t calc_tsc_timeout(const struct sfnt_tsc_params* tscp,
                                 int timeout_ms)
{
  uint64_t tsc_timeout;
  if( timeout_ms > 0 ) {
    sfnt_tsc(&tsc_timeout);
    tsc_timeout += sfnt_msec_tsc(tscp, timeout_ms);
  }
  else
    tsc_timeout = 0;
  return tsc_timeout;
}


#if NT_HAVE_POLL
int sfnt_poll(struct pollfd* fds, nfds_t nfds, int timeout_ms,
	      const struct sfnt_tsc_params* tscp, enum sfnt_mux_flags flags)
{
  int use_timeout_ms = (flags & NT_MUX_SPIN) ? 0 : timeout_ms;
  uint64_t tsc_now, tsc_timeout;
  int rc;

  rc = poll(fds, nfds, use_timeout_ms);
  if( return_now(rc, flags, timeout_ms) )
    return rc;

  /* NB. We will extend the timeout if the above call is interrupted,
   * because we didn't take a timestamp before the first call to poll().  I
   * am willing to accept that to avoid the cost of grabbing a timestamp
   * before poll().
   */
  tsc_timeout = calc_tsc_timeout(tscp, timeout_ms);

  while( 1 ) {
    rc = poll(fds, nfds, use_timeout_ms);
    if( return_now(rc, flags, timeout_ms) )
      break;
    if( rc < 0 ) {  /* EINTR && NT_MUX_CONTINUE_ON_EINTR */
      if( use_timeout_ms > 0 ) {
        if( (tsc_now = get_tsc()) < tsc_timeout )
          use_timeout_ms = sfnt_tsc_msec(tscp, tsc_timeout - tsc_now);
        else
          use_timeout_ms = 1;
        use_timeout_ms = use_timeout_ms ? use_timeout_ms : 1;
      }
    }
    /* rc == 0 && NT_MUX_SPIN */
    else if( tsc_timeout && get_tsc() >= tsc_timeout ) {
      break;
    }
  }

  return rc;
}
#endif


#if NT_HAVE_EPOLL
int sfnt_epoll_wait(int epfd, struct epoll_event* events, int maxevents,
		    int timeout_ms, const struct sfnt_tsc_params* tscp,
		    enum sfnt_mux_flags flags)
{
  int use_timeout_ms = (flags & NT_MUX_SPIN) ? 0 : timeout_ms;
  uint64_t tsc_now, tsc_timeout;
  int rc;

  rc = epoll_wait(epfd, events, maxevents, use_timeout_ms);
  if( return_now(rc, flags, timeout_ms) )
    return rc;

  /* NB. We will extend the timeout if the above call is interrupted,
   * because we didn't take a timestamp before the first call to poll().  I
   * am willing to accept that to avoid the cost of grabbing a timestamp
   * before poll().
   */
  tsc_timeout = calc_tsc_timeout(tscp, timeout_ms);

  while( 1 ) {
    rc = epoll_wait(epfd, events, maxevents, use_timeout_ms);
    if( return_now(rc, flags, timeout_ms) )
      break;
    if( rc < 0 ) {  /* EINTR && NT_MUX_CONTINUE_ON_EINTR */
      if( use_timeout_ms > 0 ) {
        if( (tsc_now = get_tsc()) < tsc_timeout )
          use_timeout_ms = sfnt_tsc_msec(tscp, tsc_timeout - tsc_now);
        else
          use_timeout_ms = 1;
        use_timeout_ms = use_timeout_ms ? use_timeout_ms : 1;
      }
    }
    /* rc == 0 && NT_MUX_SPIN */
    else if( tsc_timeout && get_tsc() >= tsc_timeout ) {
      break;
    }
  }

  return rc;
}
#endif


int sfnt_select(int nfds, fd_set* readfds, fd_set* writefds,
		fd_set* exceptfds, const struct sfnt_tsc_params* tscp,
		int timeout_ms, enum sfnt_mux_flags flags)
{
  fd_set readfds_save, writefds_save, exceptfds_save;
  struct timeval* timeout = NULL;
  uint64_t tsc_timeout;
  struct timeval timeout_s;
  int rc, fds_bytes;

  if( timeout_ms > 0 && ! (flags & NT_MUX_SPIN) ) {
    timeout_s.tv_sec = timeout_ms / 1000;
    timeout_s.tv_usec = (timeout_ms % 1000) * 1000;
  }
  else {
    timeout_s.tv_sec = 0;
    timeout_s.tv_usec = 0;
  }
  if( (flags & NT_MUX_SPIN) || timeout_ms >= 0 )
    timeout = &timeout_s;

  if( timeout_ms != 0 && (flags & (NT_MUX_SPIN | NT_MUX_CONTINUE_ON_EINTR)) ) {
    /* Grab a copy in case we need to call select() more than once. */
    fds_bytes = ((nfds + __NFDBITS -1) / __NFDBITS) * (__NFDBITS / 8);
    if( readfds != NULL )
      memcpy(__FDS_BITS(&readfds_save), __FDS_BITS(readfds), fds_bytes);
    if( writefds != NULL )
      memcpy(__FDS_BITS(&writefds_save), __FDS_BITS(writefds), fds_bytes);
    if( exceptfds != NULL )
      memcpy(__FDS_BITS(&exceptfds_save), __FDS_BITS(exceptfds), fds_bytes);
  }

  rc = select(nfds, readfds, writefds, exceptfds, timeout);
  if( return_now(rc, flags, timeout_ms) )
    return rc;

  tsc_timeout = calc_tsc_timeout(tscp, timeout_ms);

  while( 1 ) {
    if( readfds != NULL )
      memcpy(__FDS_BITS(readfds), __FDS_BITS(&readfds_save), fds_bytes);
    if( writefds != NULL )
      memcpy(__FDS_BITS(writefds), __FDS_BITS(&writefds_save), fds_bytes);
    if( exceptfds != NULL )
      memcpy(__FDS_BITS(exceptfds), __FDS_BITS(&exceptfds_save), fds_bytes);
    rc = select(nfds, readfds, writefds, exceptfds, timeout);
    if( return_now(rc, flags, timeout_ms) )
      break;
    if( rc < 0 ) {  /* EINTR && NT_MUX_CONTINUE_ON_EINTR */
      /* Linux select() will decrease timeout as needed.  Other OSs might
       * need some code here, but not terribly important as timeout
       * extension doesn't usually have significant side effects.
       */
    }
    /* rc == 0 && NT_MUX_SPIN */
    else if( tsc_timeout && get_tsc() >= tsc_timeout ) {
      break;
    }
  }

  return rc;
}
