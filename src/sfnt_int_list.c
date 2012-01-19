/**************************************************************************\
*    Filename: sfnt_int_list.c
*      Author: David Riddoch <driddoch@solarflare.com>
* Description: Routines for handling lists of integers.
*   Copyright: (C) 2005-2012 Solarflare Communications Inc.
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


static void skip_int_range2(const char** ps)
{
  skip_int_range(ps);
  ++(*ps);
  skip_int(ps);
}


void sfnt_ilist_init(struct sfnt_ilist* ilist)
{
  ilist->alloc_len = 8;
  ilist->len = 0;
  ilist->list = malloc(ilist->alloc_len * sizeof(int));
}


void sfnt_ilist_append(struct sfnt_ilist* ilist, int i)
{
  NT_ASSERTi3(ilist->len, <=, ilist->alloc_len);
  if( ilist->len == ilist->alloc_len ) {
    ilist->alloc_len *= 2;
    ilist->list = realloc(ilist->list, ilist->alloc_len * sizeof(int));
  }
  ilist->list[ilist->len++] = i;
}


int sfnt_ilist_parse(struct sfnt_ilist* ilist, const char* int_list_str)
{
  int low, high, step;
  int rc;

  sfnt_ilist_init(ilist);

  while( int_list_str[0] ) {
    if( int_list_str[0] == ',' ) {
      ++int_list_str;
      continue;
    }
    if( sscanf(int_list_str, "%u-%u+%u", &low, &high, &step) == 3 ) {
      if( high < low )
        goto fail_einval;
      do
        sfnt_ilist_append(ilist, low);
      while( (low += step) <= high );
      skip_int_range2(&int_list_str);
    }
    else if( sscanf(int_list_str, "%u-%ux%u", &low, &high, &step) == 3 ) {
      if( high < low )
        goto fail_einval;
      do
        sfnt_ilist_append(ilist, low);
      while( (low *= step) <= high );
      skip_int_range2(&int_list_str);
    }
    else if( sscanf(int_list_str, "%u-%u", &low, &high) == 2 ) {
      if( high < low )
        goto fail_einval;
      while( low <= high )
        sfnt_ilist_append(ilist, low++);
      skip_int_range(&int_list_str);
    }
    else if( sscanf(int_list_str, "%u-%u", &low, &high) == 1 ) {
      sfnt_ilist_append(ilist, low);
      skip_int(&int_list_str);
    }
    else {
      goto fail_einval;
    }
  }

  return 0;

 fail_einval:
  rc = -EINVAL;
  free(ilist->list);
  return rc;
}
