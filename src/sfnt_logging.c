#include "sfnettest.h"


void sfnt_vflog(FILE* file, const char* fmt, va_list args)
{
  vfprintf(file, fmt, args);
}


void sfnt_flog(FILE* file, const char* fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  sfnt_vflog(file, fmt, args);
  va_end(args);
}


void sfnt_verr(const char* fmt, va_list args)
{
  vfprintf(stderr, fmt, args);
}


void sfnt_vout(const char* fmt, va_list args)
{
  vfprintf(stdout, fmt, args);
}


void sfnt_err(const char* fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  sfnt_verr(fmt, args);
  va_end(args);
}


void sfnt_out(const char* fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  sfnt_vout(fmt, args);
  va_end(args);
}
