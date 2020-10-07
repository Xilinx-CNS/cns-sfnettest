/**************************************************************************\
*    Filename: sfnt_affinity.c
*      Author: David Riddoch <driddoch@solarflare.com>
* Description: Routines for handling CPU affinity.
*   Copyright: (C) 2005-2012 Solarflare Communications Inc.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License version 2 as published
* by the Free Software Foundation, incorporated herein by reference.
\**************************************************************************/

#define _GNU_SOURCE
#include "sfnettest.h"


#if defined(__linux__)
int sfnt_cpu_affinity_set(int core_i)
{
  cpu_set_t cset;
  NT_ASSERT(core_i >= 0);
  NT_ASSERT(core_i < CPU_SETSIZE);
  CPU_ZERO(&cset);
  CPU_SET(core_i, &cset);
  return sched_setaffinity(0, sizeof(cset), &cset);
}
#elif defined(_WIN32)
int sfnt_cpu_affinity_set(int core_i)
{
  DWORD_PTR mask = 1ULL << core_i;
  NT_ASSERT(core_i >= 0);
  NT_ASSERT(core_i < MAXIMUM_PROC_PER_GROUP);
  return SetThreadAffinityMask(GetCurrentThread(), mask) ? 0 : -1;
}
#elif defined(__FreeBSD__)
int sfnt_cpu_affinity_set(int core_i)
{
  cpuset_t cset;
  NT_ASSERT(core_i >= 0);
  NT_ASSERT(core_i < CPU_SETSIZE);
  CPU_ZERO(&cset);
  CPU_SET(core_i, &cset);
  return cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1,
                            sizeof(cset), &cset);
}
#else
int sfnt_cpu_affinity_set(int core_i)
{
  sfnt_err("ERROR: Process/thread affinity not currently supported on this "
	   "platform\nPlease rerun with --affinity 'any;any'\n");
  sfnt_fail_test();
  /* not reached */
  return -1;
}
#endif
