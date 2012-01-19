/**************************************************************************\
*    Filename: sfnt_stats.c
*      Author: David Riddoch <driddoch@solarflare.com>
* Description: Routines for computing statistics.
*   Copyright: (C) 2005-2012 Solarflare Communications Inc.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License version 2 as published
* by the Free Software Foundation, incorporated herein by reference.
\**************************************************************************/

#include "sfnettest.h"


int sfnt_qsort_compare_int(const void* pa, const void* pb)
{
  const int* a = pa;
  const int* b = pb;
  return *a - *b;
}


void sfnt_iarray_mean_and_limits(const int* start, const int* end,
                               int* mean_out, int* min_out, int* max_out)
{
  int min, max;
  int64_t sum;
  const int* i;

  NT_ASSERT(end - start > 0);

  sum = 0;
  min = max = *start;

  for( i = start; i != end; ++i ) {
    if( *i < min )  min = *i;
    else
    if( *i > max )  max = *i;
    sum += *i;
  }

  if( mean_out )  *mean_out = (int) (sum / (end - start));
  if( min_out  )  *min_out  = min;
  if( max_out  )  *max_out  = max;
}


void sfnt_iarray_variance(const int* start, const int* end,
                        int mean, int64_t* variance_out)
{
  int64_t sumsq, diff;
  const int* i;

  NT_ASSERT(end - start > 0);
  NT_ASSERT(variance_out);

  if( end - start < 2 ) {
    *variance_out = 0;
    return;
  }

  sumsq = 0;

  for( i = start; i != end; ++i ) {
    diff = *i - mean;
    sumsq += diff * diff;
  }

  *variance_out = sumsq / (end - start - 1);
}
