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
