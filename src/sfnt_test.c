/**************************************************************************\
*    Filename: sfnt_test.c
*      Author: David Riddoch <driddoch@solarflare.com>
* Description: Test support routines.
*   Copyright: (C) 2005-2011 Solarflare Communications Inc.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License version 2 as published
* by the Free Software Foundation, incorporated herein by reference.
\**************************************************************************/

#include "sfnettest.h"


void sfnt_abort(void)
{
  abort();
}


void sfnt_fail_test(void)
{
  sfnt_err("ERROR: Test failed.\n");
  abort();
}


void sfnt_fail_setup(void)
{
  sfnt_err("ERROR: Test setup failed.\n");
  abort();
}
