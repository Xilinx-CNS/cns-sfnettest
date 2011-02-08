#include "sfnettest.h"


void sfnt_dump_sys_info(const struct sfnt_tsc_params* tsc)
{
#ifndef _WIN32
  int rc;

  if( sfnt_cmd_line )
    sfnt_out("# cmdline: %s\n", sfnt_cmd_line);
  sfnt_out("# version: %s\n", SFNT_VERSION);
  sfnt_out("# src: %s\n", SFNT_SRC_CSUM);
  rc = system("date | sed 's/^/# date: /'");
  rc = system("uname -a | sed 's/^/# uname: /'");
  rc = system("cat /proc/cpuinfo | grep 'model name'"
              " | head -1 | sed 's/^/# cpu: /'");
  rc = system("lspci -d 1924: | sed 's/^/# sfnics: /'");
  rc = system("grep MemTotal /proc/meminfo | sed 's/^/# ram: /'");
  sfnt_out("# tsc_hz: %"PRId64"\n", tsc->hz);
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
  const char* ld_preload;
  char** p;

  ld_preload = getenv("LD_PRELOAD");
  if( ld_preload )
    fprintf(f, "%sLD_PRELOAD=%s\n", pf, ld_preload);
  if( &onload_version )
    fprintf(f, "%sonload_version=%s\n", pf, onload_version);
  if( sfnt_onload_is_active() )
    for( p = environ; *p != NULL; ++p )
      if( strncmp("EF_", *p, 3) == 0 )
        fprintf(f, "%s%s\n", pf, *p);
#endif
}
