/**************************************************************************\
*    Filename: sfnt_int_list.c
*      Author: David Riddoch <driddoch@solarflare.com>
* Description: Routines for handling lists of integers.
*   Copyright: (C) 2005-2011 Solarflare Communications Inc.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License version 2 as published
* by the Free Software Foundation, incorporated herein by reference.
\**************************************************************************/

#include "sfnettest.h"
#include <ctype.h>


static void skip_int(const char** ps)
{
  while( isdigit(**ps) )
    ++(*ps);
}


static void skip_int_range(const char** ps)
{
  skip_int(ps);
  assert(**ps == '-');
  ++(*ps);
  skip_int(ps);
}


int sfnt_parse_int_list(const char* int_list_str,
                      int** int_list_out, int* int_list_len_out)
{
  int low, high;
  int len = 0;
  int rc;

  *int_list_out = NULL;
  *int_list_len_out = 0;

  while( int_list_str[0] ) {
    if( int_list_str[0] == ',' ) {
      ++int_list_str;
      continue;
    }
    if( sscanf(int_list_str, "%u-%u", &low, &high) == 2 ) {
      if( high < low ) {
        rc = -EINVAL;
        goto fail;
      }
      *int_list_len_out += high - low + 1;
      *int_list_out = realloc(*int_list_out, *int_list_len_out * sizeof(int));
      while( low <= high )
        (*int_list_out)[len++] = low++;
      assert(len == *int_list_len_out);
      skip_int_range(&int_list_str);
    }
    else if( sscanf(int_list_str, "%u-%u", &low, &high) == 1 ) {
      *int_list_len_out += 1;
      *int_list_out = realloc(*int_list_out, *int_list_len_out * sizeof(int));
      (*int_list_out)[len++] = low;
      skip_int(&int_list_str);
    }
    else {
      rc = -EINVAL;
      goto fail;
    }
  }

  return 0;

 fail:
  free(*int_list_out);
  *int_list_out = NULL;
  return rc;
}
