/**************************************************************************\
*    Filename: sfnt_fd.c
*      Author: David Riddoch <driddoch@solarflare.com>
* Description: Convenience routines for managing file descriptors.
*   Copyright: (C) 2005-2011 Solarflare Communications Inc.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License version 2 as published
* by the Free Software Foundation, incorporated herein by reference.
\**************************************************************************/

#include "sfnettest.h"
#include <sys/ioctl.h>


int sfnt_fd_set_nonblocking(int fd)
{
  int nonblock = 1;
  return ioctl(fd, FIONBIO, &nonblock);
}


int sfnt_fd_set_blocking(int fd)
{
  int nonblock = 0;
  return ioctl(fd, FIONBIO, &nonblock);
}
