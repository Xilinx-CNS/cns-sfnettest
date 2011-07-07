/**************************************************************************\
*    Filename: sfnt_sysinfo.c
*      Author: David Riddoch <driddoch@solarflare.com>
* Description: Routines for logging system info.
*   Copyright: (C) 2005-2011 Solarflare Communications Inc.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License version 2 as published
* by the Free Software Foundation, incorporated herein by reference.
\**************************************************************************/

#include "sfnettest.h"


void sfnt_dump_ver_info(FILE* f, const char* pf)
{
  sfnt_flog(f, "%sversion: %s\n", pf, SFNT_VERSION);
  sfnt_flog(f, "%ssrc: %s\n", pf, SFNT_SRC_CSUM);
}


void sfnt_dump_sys_info(const struct sfnt_tsc_params* tsc_opt)
{
#ifndef _WIN32
  const char* ld_preload;
  int rc;

  if( sfnt_cmd_line )
    sfnt_out("# cmdline: %s\n", sfnt_cmd_line);
  sfnt_dump_ver_info(stdout, "# ");
  rc = system("date | sed 's/^/# date: /'");
  rc = system("uname -a | sed 's/^/# uname: /'");
  rc = system("cat /proc/cpuinfo | grep 'model name'"
              " | head -1 | sed 's/^/# cpu: /'");
  rc = system("lspci -d 1924: | sed 's/^/# sfnics: /'");
  rc = system("grep MemTotal /proc/meminfo | sed 's/^/# ram: /'");
  if( tsc_opt != NULL )
    sfnt_out("# tsc_hz: %"PRId64"\n", tsc_opt->hz);
  if( (ld_preload = getenv("LD_PRELOAD")) )
    sfnt_out("# LD_PRELOAD=%s\n", ld_preload);
#endif
}


#ifndef _WIN32
/* If the onload library is present, and defines onload_version, then this
 * will resolve to the onload library.  Otherwise &onload_version will be
 * null (because it is weak and undefined).
 */
extern const char*const onload_version __attribute__((weak));
extern char** environ;
#endif


int sfnt_onload_is_active(void)
{
#ifndef _WIN32
  const char* ld_preload;
  if( &onload_version )
    return 1;
  ld_preload = getenv("LD_PRELOAD");
  if( ld_preload == NULL )
    return 0;
  return strstr(ld_preload, "libcitransport") != NULL
    ||   strstr(ld_preload, "libonload") != NULL;
#else
  return 0;
#endif
}


void sfnt_onload_info_dump(FILE* f, const char* pf)
{
#ifndef _WIN32
  char** p;

  if( &onload_version )
    sfnt_flog(f, "%sonload_version=%s\n", pf, onload_version);
  if( sfnt_onload_is_active() )
    for( p = environ; *p != NULL; ++p )
      if( strncmp("EF_", *p, 3) == 0 )
        sfnt_flog(f, "%s%s\n", pf, *p);
#endif
}
