#ifndef __NETTEST_UNIX_H__
#define __NETTEST_UNIX_H__


#define NT_HAVE_POLL    0
#define NT_HAVE_EPOLL   0


#define NT_PRINTF_LIKE(a, b)


#ifndef SOL_IP
#define SOL_IP 0
#endif


/**********************************************************************
 * Work-around WIN32 breakage of sockets interface.
 */

static __inline ssize_t __nt_recv(int fd, void* buf, size_t len, int flags)
{
  return recv(fd, (char*) buf, len, flags);
}
#define recv __nt_recv


#endif  /* __NETTEST_UNIX_H__ */
