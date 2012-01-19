/**************************************************************************\
*    Filename: sfnt_logging.c
*      Author: David Riddoch <driddoch@solarflare.com>
* Description: Logging support.
*   Copyright: (C) 2005-2012 Solarflare Communications Inc.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License version 2 as published
* by the Free Software Foundation, incorporated herein by reference.
\**************************************************************************/

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
