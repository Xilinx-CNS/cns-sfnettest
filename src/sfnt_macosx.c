/**************************************************************************\
*    Filename: sfnt_macosx.c
*      Author: David Riddoch <driddoch@solarflare.com>
* Description: Compatibility shims for MacOSX.
*   Copyright: (C) 2012-2012 Solarflare Communications Inc.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License version 2 as published
* by the Free Software Foundation, incorporated herein by reference.
\**************************************************************************/

#include "sfnettest.h"


int clock_gettime(clockid_t clk_id, struct timespec* ts)
{
  static int inited;
  static clock_serv_t cs;
  mach_timespec_t mts;
  kern_return_t kr;

  if( ! inited ) {
    inited = 1;
    NT_TRY3(kr, KERN_SUCCESS,
            host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cs));
  }
  NT_TRY3(kr, KERN_SUCCESS, clock_get_time(cs, &mts));
  ts->tv_sec = mts.tv_sec;
  ts->tv_nsec = mts.tv_nsec;
  return 0;
}
