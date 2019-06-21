/**************************************************************************\
*    Filename: sfnt_tsc.c
*      Author: David Riddoch <driddoch@solarflare.com>
* Description: Measure CPU clock frequency.
*   Copyright: (C) 2005-2012 Solarflare Communications Inc.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License version 2 as published
* by the Free Software Foundation, incorporated herein by reference.
\**************************************************************************/

#include "sfnettest.h"


static void measure_begin(struct sfnt_tsc_measure* measure)
{
  uint64_t t_s;
  uint64_t tsc_s, tsc_e2;
  uint64_t tsc_gtod, min_tsc_gtod;
  int n;

  sfnt_tsc(&tsc_s);
  t_s = monotonic_clock();
  sfnt_tsc(&tsc_e2);
  min_tsc_gtod = tsc_e2 - tsc_s;
  n = 0;
  do {
    sfnt_tsc(&tsc_s);
    t_s = monotonic_clock();
    sfnt_tsc(&tsc_e2);
    tsc_gtod = tsc_e2 - tsc_s;
    if( tsc_gtod < min_tsc_gtod )
      min_tsc_gtod = tsc_gtod;
  } while( ++n < 20 || (tsc_gtod > min_tsc_gtod * 2 && n < 100) );

  measure->min_tsc_gtod = min_tsc_gtod;
  measure->t_s = t_s;
  measure->tsc_s = tsc_s;
}


static uint64_t measure_end(const struct sfnt_tsc_measure* measure,
                                     int interval_usec)
{
  uint64_t t_s = measure->t_s;
  uint64_t min_tsc_gtod = measure->min_tsc_gtod;
  uint64_t tsc_s = measure->tsc_s;
  uint64_t t_freq = monotonic_clock_freq();
  uint64_t t_interval = interval_usec * t_freq / 1000000;
  uint64_t t_e;
  uint64_t tsc_e, tsc_e2;
  uint64_t tsc_gtod, ticks;
  int n = 0, skew = 0;

  do {
    sfnt_tsc(&tsc_e);
    t_e = monotonic_clock();
    sfnt_tsc(&tsc_e2);
    if( tsc_e2 < tsc_e ) {
      skew = 1;
      break;
    }
    tsc_gtod = tsc_e2 - tsc_e;
    ticks = t_e - t_s;
  } while( ++n < 20 || ticks < t_interval || tsc_gtod > min_tsc_gtod * 2 );

  /* ?? TODO: handle this better */
  NT_TEST(skew == 0);

  return (tsc_e - tsc_s) * t_freq / ticks;
}


static uint64_t measure_hz(int interval_usec)
{
  struct sfnt_tsc_measure measure;
  measure_begin(&measure);
  return measure_end(&measure, interval_usec);
}


static uint64_t measure_tsc(void)
{
  return 0;  /* ?? TODO */
}


int sfnt_tsc_get_params(struct sfnt_tsc_params* params)
{
  params->hz = measure_hz(100000);
  params->tsc_cost = measure_tsc();

  return 0;
}


void sfnt_tsc_get_params_begin(struct sfnt_tsc_measure* measure)
{
  measure_begin(measure);
}


int sfnt_tsc_get_params_end(const struct sfnt_tsc_measure* measure,
                            struct sfnt_tsc_params* params, int interval_usec)
{
  params->hz = measure_end(measure, interval_usec);
  params->tsc_cost = measure_tsc();

  return 0;
}


int64_t sfnt_tsc_msec(const struct sfnt_tsc_params* params, int64_t tsc)
{
  return tsc * 1000 / params->hz;
}


int64_t sfnt_tsc_usec(const struct sfnt_tsc_params* params, int64_t tsc)
{
  return tsc * 1000000 / params->hz;
}


int64_t sfnt_tsc_nsec(const struct sfnt_tsc_params* params, int64_t tsc)
{
  return tsc * 1000000000 / params->hz;
}


int64_t sfnt_msec_tsc(const struct sfnt_tsc_params* params, int64_t msecs)
{
  return params->hz * msecs / 1000;
}


int64_t sfnt_usec_tsc(const struct sfnt_tsc_params* params, int64_t usecs)
{
  return params->hz * usecs / 1000000;
}


int64_t sfnt_nsec_tsc(const struct sfnt_tsc_params* params, int64_t nsecs)
{
  return params->hz * nsecs / 1000000000;
}


void sfnt_tsc_usleep(const struct sfnt_tsc_params* params, int64_t usecs)
{
  uint64_t start, stop, spin_stop;
  spin_stop = sfnt_usec_tsc(params, usecs);
  sfnt_tsc(&start);
  do {
    sfnt_tsc(&stop);
  } while( stop - start < spin_stop );
}
