/**************************************************************************\
*    Filename: sfnt_sysinfo.c
*      Author: David Riddoch <driddoch@solarflare.com>
* Description: Routines for logging system info.
*   Copyright: (C) 2005-2012 Solarflare Communications Inc.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License version 2 as published
* by the Free Software Foundation, incorporated herein by reference.
\**************************************************************************/

#include "sfnettest.h"


extern char** environ;


#if NT_SUPPORTS_ONLOAD
/* If the onload library is present, and defines onload_version, then this
 * will resolve to the onload library.  Otherwise &onload_version will be
 * null (because it is weak and undefined).
 */
extern const char*const onload_version __attribute__((weak));
#endif


void sfnt_dump_ver_info(FILE* f, const char* pf)
{
  sfnt_flog(f, "%sversion: %s\n", pf, SFNT_VERSION);
  sfnt_flog(f, "%ssrc: %s\n", pf, SFNT_SRC_CSUM);
}


#if NT_SUPPORTS_ONLOAD
static int sfnt_onload_is_active(void)
{
  const char* ld_preload;
  if( &onload_version )
    return 1;
  ld_preload = getenv("LD_PRELOAD");
  if( ld_preload == NULL )
    return 0;
  return strstr(ld_preload, "libcitransport") != NULL
    ||   strstr(ld_preload, "libonload") != NULL;
}
#endif


#if defined(__unix__) || defined(__APPLE__)
static void sfnt_dump_env_with_prefix(FILE* f, const char* pf,
                                      const char* env_prefix)
{
  int env_prefix_len = strlen(env_prefix);
  char** p;
  for( p = environ; *p != NULL; ++p )
    if( strncmp(env_prefix, *p, env_prefix_len) == 0 )
      sfnt_flog(f, "%s%s\n", pf, *p);
}
#endif


static void sfnt_onload_info_dump(FILE* f, const char* pf)
{
#if NT_SUPPORTS_ONLOAD
  if( &onload_version )
    sfnt_flog(f, "%sonload_version=%s\n", pf, onload_version);
  if( sfnt_onload_is_active() )
    sfnt_dump_env_with_prefix(f, pf, "EF_");
#endif
}


void sfnt_dump_sys_info(const struct sfnt_tsc_params* tsc_opt)
{
  const char* ld_preload;

  if( sfnt_cmd_line )
    sfnt_out("# cmdline: %s\n", sfnt_cmd_line);
  sfnt_dump_ver_info(stdout, "# ");
  if( ! getenv("SFNT_AVOID_FORK") ) {
#if defined(__unix__) || defined(__APPLE__)
    system("date | sed 's/^/# date: /'");
    system("uname -a | sed 's/^/# uname: /'");
#endif
#ifdef __linux__
    system("cat /proc/cpuinfo | grep 'model name'"
           " | head -1 | sed 's/^/# cpu: /'");
    system("/sbin/lspci | grep -i net | sed 's/^/# lspci: /'");
    system("for if in $(cd /sys/class/net && /bin/ls); do"
           " ethtool -i $if 2>/dev/null | egrep 'bus-info|driver|^vers'"
           " | sed \"s/^/# $if: /\"; done");
    system("grep MemTotal /proc/meminfo | sed 's/^/# ram: /'");
#endif
  }
  if( tsc_opt != NULL )
    sfnt_out("# tsc_hz: %"PRId64"\n", tsc_opt->hz);
#if defined(__unix__) || defined(__APPLE__)
  if( (ld_preload = getenv("LD_PRELOAD")) ) {
    sfnt_out("# LD_PRELOAD=%s\n", ld_preload);
    if( strstr(ld_preload, "libvma") )
      sfnt_dump_env_with_prefix(stdout, "# ", "VMA_");
  }
#endif
  sfnt_onload_info_dump(stdout, "# ");
}
