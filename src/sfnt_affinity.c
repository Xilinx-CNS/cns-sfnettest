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
