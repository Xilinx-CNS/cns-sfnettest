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

#if NT_HAVE_POLL
int sfnt_poll(struct pollfd* fds, nfds_t nfds, int timeout_ms,
	      const struct sfnt_tsc_params* _tsc, enum sfnt_mux_flags flags)
{
  int use_timeout_ms = (flags & NT_MUX_SPIN) ? 0 : timeout_ms;
  uint64_t tsc_now, tsc_timeout;
  int rc;

  sfnt_tsc(&tsc_timeout);

  /* Initial poll() */
  rc = poll(fds, nfds, use_timeout_ms);
  if( rc > 0 || (rc < 0 && errno != EINTR) || timeout_ms == 0 )
    return rc;

  tsc_timeout += sfnt_msec_tsc(_tsc, timeout_ms);

  /* Loop for EINTR and EAGAIN handling */
  do {
    /* TODO: reduce timeout on EINTR */
    rc = poll(fds, nfds, use_timeout_ms);

    if( rc != 0 && timeout_ms > 0 ) {
      sfnt_tsc(&tsc_now);
      if( tsc_now >= tsc_timeout ) {
	errno = ETIMEDOUT;
	return -1;
      }
    }
  } while( (rc == 0 && (flags & NT_MUX_SPIN)) || (rc < 0 && errno == EINTR) );

  return rc;
}
#endif


#if NT_HAVE_EPOLL
int sfnt_epoll_wait(int epfd, struct epoll_event* events, int maxevents,
		    int timeout_ms, const struct sfnt_tsc_params* _tsc,
		    enum sfnt_mux_flags flags)
{
  int use_timeout_ms = (flags & NT_MUX_SPIN) ? 0 : timeout_ms;
  uint64_t tsc_now, tsc_timeout;
  int rc;

  sfnt_tsc(&tsc_timeout);

  /* Initial epoll_wait() */
  rc = epoll_wait(epfd, events, maxevents, use_timeout_ms);
  if( rc > 0 || (rc < 0 && errno != EINTR) || timeout_ms == 0 )
    return rc;

  tsc_timeout += sfnt_msec_tsc(_tsc, timeout_ms);

  /* Loop for EINTR and EAGAIN handling */
  do {
    /* TODO: reduce timeout on EINTR */
    rc = epoll_wait(epfd, events, maxevents, use_timeout_ms);

    if( rc != 0 && timeout_ms > 0 ) {
      sfnt_tsc(&tsc_now);
      if( tsc_now >= tsc_timeout ) {
	errno = ETIMEDOUT;
	return -1;
      }
    }
  } while( (rc == 0 && (flags & NT_MUX_SPIN)) || (rc < 0 && errno == EINTR) );

  return rc;
}
#endif


int sfnt_select(int nfds, fd_set *readfds, fd_set *writefds,
		fd_set *exceptfds, const struct sfnt_tsc_params* _tsc,
		int timeout_ms, enum sfnt_mux_flags flags)
{
  struct timeval *timeout = NULL;
  struct timeval _timeout;
  uint64_t tsc_now, tsc_timeout;
  int rc;

  _timeout.tv_sec = timeout_ms / 1000;
  _timeout.tv_usec = (timeout_ms % 1000) * 1000;
  timeout = (timeout_ms == -1) ? NULL : &_timeout;

  sfnt_tsc(&tsc_timeout);

  /* Initial select() */
  rc = select(nfds, readfds, writefds, exceptfds, timeout);
  if( rc > 0 || (rc < 0 && errno != EINTR) ||
      (timeout && timeout->tv_sec == 0 && timeout->tv_usec ==0 ) )
    return rc;

  if( timeout ) {
    tsc_timeout += sfnt_msec_tsc(_tsc, timeout->tv_sec * 1000);
    tsc_timeout += sfnt_usec_tsc(_tsc, timeout->tv_usec);
  }

  /* Loop for EINTR and EAGAIN handling */
  do {
    /* NB: linux will decrease timeout */
    rc = select(nfds, readfds, writefds, exceptfds, timeout);

    if( rc != 0 && timeout ) {
      sfnt_tsc(&tsc_now);
      if( tsc_now >= tsc_timeout ) {
	errno = ETIMEDOUT;
	return -1;
      }
    }
  } while( (rc == 0 && (flags & NT_MUX_SPIN)) || (rc < 0 && errno == EINTR) );

  return rc;
}
