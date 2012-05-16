/**************************************************************************\
*    Filename: sfnt_cmd_line.c
*      Author: David Riddoch <driddoch@solarflare.com>
* Description: Command line processing.
*   Copyright: (C) 2005-2012 Solarflare Communications Inc.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License version 2 as published
* by the Free Software Foundation, incorporated herein by reference.
\**************************************************************************/

#include "sfnettest.h"


const char* sfnt_app_name;
char*       sfnt_cmd_line;

int         sfnt_quiet;
int         sfnt_verbose;
static int  sfnt_version;

static const struct sfnt_cmd_line_opt* cmd_line_opts;
static int                             cmd_line_opts_n;
static const char*                     usage_str;


static int parse_cfg_opt(int argc, char** argv, const char* context);
static void parse_cfg_string(char* s);


static struct sfnt_cmd_line_opt std_opts[] = {
  SFNT_CLAS('?', "help",    USAGE, NULL,           "this message"),
  SFNT_CLAS('q', "quiet",   FLAG,  &sfnt_quiet,    "quiet"),
  SFNT_CLAS('v', "verbose", FLAG,  &sfnt_verbose,  "verbose"),
  SFNT_CLAS(  0, "version", FLAG,  &sfnt_version,  "print version and exit"),
};
#define N_STD_OPTS  (sizeof(std_opts) / sizeof(std_opts[0]))


static void sfnt_app_startup(int argc, char* argv[])
{
  if( sfnt_app_name )
    return;

  if( argc > 0 ) {
    int i, n = 0;
    char* p;
    for( i = 0; i < argc; ++i )
      n += strlen(argv[i]) + 1;
    sfnt_cmd_line = malloc(n);
    if( sfnt_cmd_line ) {
      p = sfnt_cmd_line;
      for( i = 0; i < argc; ++i )
        p += sprintf(p, "%s%s", i == 0 ? "":" ", argv[i]);
      NT_TEST(p == sfnt_cmd_line + n - 1);
    }

    if( argc >= 1 && argv && argv[0] ) {
      sfnt_app_name = argv[0] + strlen(argv[0]);
      while( sfnt_app_name > argv[0] &&
	     sfnt_app_name[-1] != '/' && sfnt_app_name[-1] != '\\' )
	--sfnt_app_name;
    }
    else
      sfnt_app_name = "";

#if 0
    if( strlen(sfnt_app_name) < (LOG_PREFIX_BUF_SIZE - 5) ) {
      strcpy(log_prefix_buf, sfnt_app_name);
      strcat(log_prefix_buf, ": ");
      ci_set_log_prefix(log_prefix_buf);
    }
#endif
  }
}


static void chomp_arg(int* argc, char* argv[], int n)
{
  assert(*argc >= n);
  (*argc) -= n;
  memmove(argv, argv + n, (*argc) * sizeof(argv[0]));
}


void sfnt_app_getopt(const char* usage, int* argc, char* argv[],
                     const struct sfnt_cmd_line_opt* opts, int n_opts)
{
  char* s;

  NT_TEST(opts || n_opts == 0);

  sfnt_app_startup(argc ? *argc : 0, argv);

  cmd_line_opts = opts;
  cmd_line_opts_n = n_opts;
  usage_str = usage;

  /* look in the environment first */
  if( (s = getenv("SFNT_OPTS")) )
    parse_cfg_string(s);

  if( argc ) {
    --(*argc);  ++argv;

    while( *argc > 0 ) {
      /* end of options? */
      if( argv[0][0] != '-' )       break;
      if( !strcmp("--", argv[0]) )  break;

      chomp_arg(argc, argv, parse_cfg_opt(*argc, argv, "command line"));
    }

    ++(*argc);
  }

#if 0
  if( ci_cfg_hang_on_fail  )  ci_fail_stop_fn = ci_fail_hang;
  if( ci_cfg_segv_on_fail  )  ci_fail_stop_fn = ci_fail_bomb;
# ifdef __unix__
  if( ci_cfg_stop_on_fail  )  ci_fail_stop_fn = ci_fail_stop;
  if( ci_cfg_abort_on_fail )  ci_fail_stop_fn = ci_fail_abort;
# endif
#endif

  if( sfnt_version ) {
    sfnt_dump_ver_info(stdout, "");
    exit(0);
  }
}


void sfnt_opt_usage(FILE* f, const struct sfnt_cmd_line_opt* opts, int n_opts)
{
  const struct sfnt_cmd_line_opt* a;
  const char* usage;

  for( a = opts; a != opts + n_opts; ++a ) {
    NT_ASSERT(a->long_name || a->short_name);
    usage = a->usage ? a->usage : "";
    if( a->long_name && a->short_name )
      sfnt_flog(f, "  -%c --%-20s -- %s\n", a->short_name, a->long_name,usage);
    else if( a->long_name )
      sfnt_flog(f, "     --%-20s -- %s\n", a->long_name, usage);
    else
      sfnt_flog(f, "  -%c   %-20s -- %s\n", a->short_name, "", usage);
  }
}


static void sfnt_usage_fn_default(FILE* f, const char* fmt, va_list args)
{
  if( fmt != NULL ) {
    sfnt_flog(f, "\n");
    sfnt_vflog(f, fmt, args);
    sfnt_flog(f, "\n");
  }
  sfnt_flog(f, "\n");
  sfnt_flog(f, "usage:\n");
  sfnt_flog(f, "  %s [options] %s\n", sfnt_app_name, (usage_str?usage_str:""));
  if( cmd_line_opts && cmd_line_opts_n ) {
    sfnt_flog(f, "\n");
    sfnt_flog(f, "options:\n");
    sfnt_opt_usage(f, cmd_line_opts, cmd_line_opts_n);
  }
  sfnt_flog(f, "\n");
  sfnt_flog(f, "standard options:\n");
  sfnt_opt_usage(f, std_opts, N_STD_OPTS);
  sfnt_flog(f, "\n");
}


static void (*sfnt_usage_fn)(FILE*, const char*, va_list)
  = sfnt_usage_fn_default;


static void sfnt_usage(FILE* file, const char* fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  sfnt_usage_fn(file, fmt, args);
  va_end(args);
}


void sfnt_fail_usage(const char* fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  sfnt_usage_fn(stderr, fmt, args);
  va_end(args);
  exit(1);
}


static void bad_cla(const char* context, const char* cla, const char* msg)
{
  sfnt_err("ERROR: bad %s option: %s\n", context, cla);
  if( msg )  sfnt_err("ERROR: %s\n", msg);
  sfnt_fail_usage("bad option");
}


static int sizeof_cla_type(enum sfnt_cla_type type)
{
  switch( type ) {
  case SFNT_CLAT_FLAG:
  case SFNT_CLAT_INT:
  case SFNT_CLAT_UINT:
    return sizeof(int);
  case SFNT_CLAT_STR:
    return sizeof(char*);
  case SFNT_CLAT_INT64:
  case SFNT_CLAT_UINT64:
    return sizeof(uint64_t);
  case SFNT_CLAT_FLOAT:
    return sizeof(float);
  default:
    NT_TEST(0);
    return 0;
  }
}


static void cla_get_val(const char* context, const char* opt_name,
                        const struct sfnt_cmd_line_opt* a,
                        int i, const char* val)
{
  switch( a->type ) {
  case SFNT_CLAT_FLAG:
    if( val ) {
      if( sscanf(val, "%d", &((int*) a->value)[i]) != 1 )
	bad_cla(context, opt_name, "expected integer or nothing");
    }
    else
      ++((int*) a->value)[i];
    break;
  case SFNT_CLAT_INT:
    if( !val || sscanf(val, "%i", &((int*) a->value)[i]) != 1 )
      bad_cla(context, opt_name, "expected integer");
    break;
  case SFNT_CLAT_UINT:
    if( !val || sscanf(val, "%i", &((int*) a->value)[i]) != 1 ||
        ((int*) a->value)[i] < 0 )
      bad_cla(context, opt_name, "expected unsigned integer");
    break;
  case SFNT_CLAT_INT64:
    if( !val || sscanf(val, "%lli", &((long long int*) a->value)[i]) != 1 )
      bad_cla(context, opt_name, "expected 64bit integer");
    break;
  case SFNT_CLAT_UINT64:
    if( !val || sscanf(val, "%lli", &((long long int*) a->value)[i]) != 1 ||
        ((long long int*) a->value)[i] < 0 )
      bad_cla(context, opt_name, "expected unsigned 64bit integer");
    break;
  case SFNT_CLAT_FLOAT:
    if( !val || sscanf(val, "%f", &((float*) a->value)[i]) != 1 )
      bad_cla(context, opt_name, "expected number");
    break;
  case SFNT_CLAT_STR:
    ((char**) a->value)[i] = strdup(val ? val : "");
    break;
  case SFNT_CLAT_USAGE:
    sfnt_usage(stdout, NULL);
    exit(0);
    break;
  case SFNT_CLAT_FN:
    assert(a->fn);
    a->fn(val, a);
    break;
#if 0
  case SFNT_CLAT_IRANGE:
    {
      int *v;
      v = (int*) a->value;
      if( sscanf(val, " %i - %i", v, v + 1) != 2 ) {
	if( sscanf(val, " %i", v) == 1 )
	  v[1] = v[0];
	else
	  bad_cla(context, opt_name, "expected integer or range");
      }
    }
    break;
#endif
  default:
    sfnt_err("%s: unknown config option type %u\n", __FUNCTION__, a->type);
    sfnt_abort();
    break;
  }
}


static const struct sfnt_cmd_line_opt* find_cfg_desc(const char* opt,
                                          const struct sfnt_cmd_line_opt* opts,
                                          int                n_opts,
                                          const char**       pval)
{
  const struct sfnt_cmd_line_opt* a;
  int len;

  *pval = 0;

  for( a = opts; a != opts + n_opts; ++a ) {
    NT_ASSERT(a->short_name || a->long_name);
    if( opt[1] == '-' ) {  /* its in long format */
      if( a->long_name == NULL )
        continue;
      len = strlen(a->long_name);
      if( !strncmp(opt + 2, a->long_name, len) ) {
	if( opt[2 + len] == '=' ) {
	  *pval = opt + 2 + len + 1;
	  return a;
	}
	else if( opt[2 + len] == 0 ) {
	  *pval = opt + 2 + len;
	  return a;
	}
      }
    }
    else {  /* its in short format */
      if( opt[1] == a->short_name ) {
	*pval = opt + 2;
	return a;
      }
    }
  }
  return 0;
}


static int parse_cfg_opt(int argc, char** argv, const char* context)
{
  const struct sfnt_cmd_line_opt* a;
  const char* opt_name = argv[0];
  const char* val = NULL;
  int i, result = 1;

  /* is it "-" ? */
  if( opt_name[1] == '\0' )
    bad_cla(context, opt_name, "- is not allowed");

  /* find the option descriptor */
  a = NULL;
  if( cmd_line_opts )
    a = find_cfg_desc(opt_name, cmd_line_opts, cmd_line_opts_n, &val);
  if( a == NULL )
    a = find_cfg_desc(opt_name, std_opts, N_STD_OPTS, &val);
  if( a == NULL )
    bad_cla(context, opt_name, "unknown option");

  /* the option value (if required) may be part of this arg or the next */
  if( val == NULL || *val == '\0' ) {
    if( a->type == SFNT_CLAT_FLAG || a->type == SFNT_CLAT_USAGE ||
        argc == 1 ) {
      val = NULL;
    }
    else {
      val = argv[1];
      result = 2;
    }
  }

  if( val && a->num > 0 ) {
    char *p, *v = strdup(val);
    for( i = 0; i < a->num; ++i )
      if( (p = strchr(val, ';')) != NULL ) {
        *p = '\0';
        cla_get_val(context, opt_name, a, i, val);
        val = p + 1;
      }
      else {
        cla_get_val(context, opt_name, a, i, val);
        val = NULL;
        ++i;
        break;
      }
    if( val != NULL )
      bad_cla(context, opt_name, "too many values");
    if( a->flags & SFNT_CLAF_FILL ) {
      int siz = sizeof_cla_type(a->type);
      for( ; i < a->num; ++i )
        memcpy((char*) a->value + i*siz, (char*) a->value + (i-1)*siz, siz);
    }
    free(v);
  }
  else if( a->type == SFNT_CLAT_FLAG && a->num > 0 ) {
    /* Yuk, special case. */
    for( i = 0; i < a->num; ++i )
      ++((int*) a->value)[i];
  }
  else {
    cla_get_val(context, opt_name, a, 0, val);
    NT_TEST((a->flags & SFNT_CLAF_FILL) == 0);
  }

  return result;
}


static void parse_cfg_string(char* s)
{
  char* p;
  int argc;
  char** argv;

  argc = 0;
  p = s;
  for( ; ; ) {
    p += strspn(p, " ");
    if( *p == 0 )
      break;
    argc += 1;
    p += strcspn(p, " ");
  }

  argv = malloc(argc * sizeof(char*));
  argc = 0;
  p = s;
  for( ; ; ) {
    p += strspn(p, " ");
    if( *p == 0 )
      break;
    argv[argc++] = p;
    p += strcspn(p, " ");
    *p = 0;
  }

  while( argc > 0 )
    chomp_arg(&argc, argv, parse_cfg_opt(argc, argv, "CI_OPTS"));

  free(argv);
}
