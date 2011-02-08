#ifndef __NETTEST_UNIX_H__
#define __NETTEST_UNIX_H__

#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <endian.h>


#define NT_HAVE_POLL    1
#define NT_HAVE_EPOLL   1


#ifdef __GNUC__
# define NT_PRINTF_LIKE(a, b)  __attribute__((format(printf,a,b)))
#else
# define NT_PRINTF_LIKE(a, b)
#endif


#define NT_LITTLE_ENDIAN  (__BYTE_ORDER == __LITTLE_ENDIAN)


#endif  /* __NETTEST_UNIX_H__ */
