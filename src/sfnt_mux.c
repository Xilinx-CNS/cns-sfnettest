/**************************************************************************\
*    Filename: sfnt_mux.c
*      Author: David Riddoch <driddoch@solarflare.com>
* Description: Muxer convenience routines.
*   Copyright: (C) 2005-2011 Solarflare Communications Inc.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License version 2 as published
* by the Free Software Foundation, incorporated herein by reference.
\**************************************************************************/

#include "sfnettest.h"


int sfnt_poll(struct pollfd* fds, nfds_t nfds, int timeout,
            enum sfnt_mux_flags flags)
{
  /* TODO: support timeout when spinning. */
  int use_timeout = (flags & NT_MUX_SPIN) ? 0 : timeout;
  int rc;
  rc = poll(fds, nfds, use_timeout);
  if( rc > 0 || (rc < 0 && errno != EINTR) || timeout == 0 )
    return rc;
  do
    rc = poll(fds, nfds, use_timeout);
  while( (rc == 0 && (flags & NT_MUX_SPIN)) || (rc < 0 && errno == EINTR) );
  return rc;
}


int sfnt_epoll_wait(int epfd, struct epoll_event* events,
                  int maxevents, int timeout, enum sfnt_mux_flags flags)
{
  /* TODO: support timeout when spinning. */
  int use_timeout = (flags & NT_MUX_SPIN) ? 0 : timeout;
  int rc;
  rc = epoll_wait(epfd, events, maxevents, use_timeout);
  if( rc > 0 || (rc < 0 && errno != EINTR) || timeout == 0 )
    return rc;
  do
    rc = epoll_wait(epfd, events, maxevents, use_timeout);
  while( (rc == 0 && (flags & NT_MUX_SPIN)) || (rc < 0 && errno == EINTR) );
  return rc;
}
