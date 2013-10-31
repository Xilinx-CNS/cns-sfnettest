/**************************************************************************\
*    Filename: sfnettest_msvc.h
*      Author: Andrew Lee <alee@solarflare.com>
* Description: Compatibility layer for MSVC compiler.
*   Copyright: (C) 2012 Solarflare Communications Inc.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License version 2 as published
* by the Free Software Foundation, incorporated herein by reference.
\**************************************************************************/

#ifndef __NETTEST_MSVC_H__
#define __NETTEST_MSVC_H__

#include <intrin.h>

/**********************************************************************
 * Setup compiler specific language extensions
 */
#define NT_PRINTF_LIKE(a, b)

#ifndef inline
# define inline __inline
#endif

#ifndef __func__
#define __func__ __FUNCTION__
#endif

/**********************************************************************
 * Work-around the lack of inttypes.h
 *
 * This is incomplete, extend as necessary.
 */
#define PRId8   "d"
#define PRId16  "hd"
#define PRId32  "I32d"
#define PRId64  "I64d"
#define PRIdPTR "Id"

#define PRIi8   "i"
#define PRIi16  "hi"
#define PRIi32  "I32i"
#define PRIi64  "I64i"
#define PRIiPTR "Ii"

#define PRIo8   "o"
#define PRIo16  "ho"
#define PRIo32  "I32o"
#define PRIo64  "I64o"
#define PRIoPTR "Io"

#define PRIu8   "u"
#define PRIu16  "hu"
#define PRIu32  "I32u"
#define PRIu64  "I64u"
#define PRIuPTR "Iu"

#define PRIx8   "x"
#define PRIx16  "hx"
#define PRIx32  "I32x"
#define PRIx64  "I64x"
#define PRIxPTR "Ix"

#define PRIX8   "X"
#define PRIX16  "hX"
#define PRIX32  "I32X"
#define PRIX64  "I64X"
#define PRIXPTR "IX"


/**********************************************************************
 * Read the timestamp counter using compiler intrinsics to avoid
 * inline assembler which isn't available in 64-bit builds.
 */

#pragma intrinsic(__rdtsc)

static inline void sfnt_tsc(uint64_t* pval) {
  uint64_t tsc;

  tsc = __rdtsc();
  *pval = tsc;
}

#endif  /* __NETTEST_MSVC_H__ */
