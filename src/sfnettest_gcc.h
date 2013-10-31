/**************************************************************************\
*    Filename: sfnettest_gcc.c
*      Author: David Riddoch <driddoch@solarflare.com>
* Description: Compatibility layer for GCC compiler.
*   Copyright: (C) 2005-2012 Solarflare Communications Inc.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License version 2 as published
* by the Free Software Foundation, incorporated herein by reference.
\**************************************************************************/

#ifndef __NETTEST_GCC_H__
#define __NETTEST_GCC_H__

#include <inttypes.h>


#ifdef __x86_64__
static inline void sfnt_tsc(uint64_t* pval) {
  uint64_t low, high;
  __asm__ __volatile__("rdtsc" : "=a" (low) , "=d" (high));             
  *pval = (high << 32) | low;
}
#elif defined(__i386__)
# define sfnt_tsc(pval)  __asm__ __volatile__("rdtsc" : "=A" (*(pval)))
#elif defined(__PPC__)
static inline void sfnt_tsc(uint64_t* pval) {
  uint64_t upper, lower, tmp;
  __asm__ volatile(
                   "0:                  \n"
                   "\tmftbu   %0        \n"
                   "\tmftb    %1        \n"
                   "\tmftbu   %2        \n"
                   "\tcmpw    %2,%0     \n"
                   "\tbne     0b        \n"
                   : "=r"(upper),"=r"(lower),"=r"(tmp)
                   );
  *pval = (upper << 32) | lower;
}
#else
# error Unknown processor.
#endif


#endif  /* __NETTEST_GCC_H__ */
