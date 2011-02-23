/**************************************************************************\
*    Filename: sfnt_affinity.c
*      Author: David Riddoch <driddoch@solarflare.com>
* Description: Routines for handling CPU affinity.
*   Copyright: (C) 2005-2011 Solarflare Communications Inc.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License version 2 as published
* by the Free Software Foundation, incorporated herein by reference.
\**************************************************************************/

#define _GNU_SOURCE
#include "sfnettest.h"
#include <sched.h>


int sfnt_cpu_affinity_set(int core_i)
{
  cpu_set_t cset;
  NT_ASSERT(core_i >= 0);
  NT_ASSERT(core_i < CPU_SETSIZE);
  CPU_ZERO(&cset);
  CPU_SET(core_i, &cset);
  return sched_setaffinity(0, sizeof(cset), &cset);
}
