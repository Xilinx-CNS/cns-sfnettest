#include "sfnettest.h"


static uint64_t measure_hz(int interval_usec)
{
  struct timeval tv_s, tv_e;
  uint64_t tsc_s, tsc_e, tsc_e2;
  uint64_t tsc_gtod, min_tsc_gtod, usec;
  int n, skew = 0;

  sfnt_tsc(&tsc_s);
  gettimeofday(&tv_s, NULL);
  sfnt_tsc(&tsc_e2);
  min_tsc_gtod = tsc_e2 - tsc_s;
  n = 0;
  do {
    sfnt_tsc(&tsc_s);
    gettimeofday(&tv_s, NULL);
    sfnt_tsc(&tsc_e2);
    tsc_gtod = tsc_e2 - tsc_s;
  } while( ++n < 5 || (tsc_gtod > min_tsc_gtod * 5 / 4 && n < 100) );

  do {
    sfnt_tsc(&tsc_e);
    gettimeofday(&tv_e, NULL);
    sfnt_tsc(&tsc_e2);
    if( tsc_e2 < tsc_e ) {
      skew = 1;
      break;
    }
    tsc_gtod = tsc_e2 - tsc_e;
    if( tsc_gtod < min_tsc_gtod )
      min_tsc_gtod = tsc_gtod;
    usec = (tv_e.tv_sec - tv_s.tv_sec) * (uint64_t) 1000000;
    usec += tv_e.tv_usec - tv_s.tv_usec;
  } while( usec < interval_usec || tsc_gtod > min_tsc_gtod * 5 / 4 );

  /* ?? TODO: handle this better */
  NT_TEST(skew == 0);

  return (tsc_e - tsc_s) * 1000000 / usec;
}


static uint64_t measure_tsc(void)
{
  return 0;  /* ?? TODO */
}


int sfnt_tsc_get_params(struct sfnt_tsc_params* params)
{
  measure_hz(100000);
  params->hz = measure_hz(100000);
  params->tsc_cost = measure_tsc();

  return 0;
}


int64_t sfnt_tsc_usec(const struct sfnt_tsc_params* params, int64_t tsc)
{
  return tsc * 1000000 / params->hz;
}


int64_t sfnt_tsc_nsec(const struct sfnt_tsc_params* params, int64_t tsc)
{
  return tsc * 1000000000 / params->hz;
}
