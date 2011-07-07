/**************************************************************************\
*    Filename: sfnettest.c
*      Author: David Riddoch <driddoch@solarflare.com>
* Description: sfnettest support library interface.
*   Copyright: (C) 2005-2011 Solarflare Communications Inc.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License version 2 as published
* by the Free Software Foundation, incorporated herein by reference.
\**************************************************************************/

#ifndef __NETTEST_H__
#define __NETTEST_H__

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>
#include <math.h>
#include <errno.h>

#ifdef __unix__
# include "sfnettest_unix.h"
#elif defined(_WIN32)
# include "sfnettest_win32.h"
#else
# error "Unknown platform"
#endif

#ifdef __GNUC__
# include "sfnettest_gcc.h"
#endif


/**********************************************************************
 * Command line arg handling.
 */

struct sfnt_cmd_line_opt {
  char         short_name;
  const char*  long_name;
  unsigned int type;
# define NT_CLO_FLAG   1
# define NT_CLO_INT    2
# define NT_CLO_UINT   3
# define NT_CLO_STR    4
# define NT_CLO_USAGE  5
# define NT_CLO_FN     6
# define NT_CLO_IRANGE 7
# define NT_CLO_INT64  8
# define NT_CLO_UINT64 9
# define NT_CLO_FLOAT  10
  void*        value;
  const char*  usage;
  void       (*fn)(const char*, const struct sfnt_cmd_line_opt*);
};


/* Options that are always supported. */
extern int sfnt_quiet;
extern int sfnt_verbose;

/* These are initialised by sfnt_app_getopt(). */
extern const char* sfnt_app_name;
extern char* sfnt_cmd_line;


/* Parse the command line for config options and specify a basic usage
 * message.  All arguments are optional.
 */
extern void sfnt_app_getopt(const char* usage, int* argc, char* argv[],
                          const struct sfnt_cmd_line_opt*, int how_many);

/* Print usage message to stderr and exit with error status. */
extern void sfnt_fail_usage(const char* err_msg, ...) NT_PRINTF_LIKE(1,2);

#if 0  /*??*/
/* Replace the usage function. */
extern void sfnt_usage_fn_set(void (*fn)(FILE*, const char*, ...));
#endif


/**********************************************************************
 * Logging etc.
 */

extern void sfnt_flog(FILE*, const char* fmt, ...) NT_PRINTF_LIKE(2,3);
extern void sfnt_vflog(FILE*, const char* fmt, va_list args);

extern void sfnt_verr(const char* fmt, va_list args);
extern void sfnt_vout(const char* fmt, va_list args);
extern void sfnt_err(const char* fmt, ...) NT_PRINTF_LIKE(1,2);
extern void sfnt_out(const char* fmt, ...) NT_PRINTF_LIKE(1,2);


/**********************************************************************
 * Runtime checks, failure paths etc.
 */

extern void sfnt_abort(void);
extern void sfnt_fail_test(void);


#define __NT_TEST(x, fail_fn)                           \
do {                                                    \
  if( ! (x) ) {                                         \
    sfnt_err("ERROR: at %s:%d\n", __FILE__, __LINE__);  \
    sfnt_err("ERROR: NT_ASSERT(%s) failed\n", #x);      \
    fail_fn();                                          \
  }                                                     \
} while(0)

#define __NT_TESTi3(a, op, b, fail_fn)                                  \
do {                                                                    \
  int __a = (a);                                                        \
  int __b = (b);                                                        \
  if( ! (__a op __b) ) {                                                \
    sfnt_err("ERROR: at %s:%d\n", __FILE__, __LINE__);                  \
    sfnt_err("ERROR: (%s, %s, %s) failed\n", #a, #op, #b);              \
    sfnt_err("ERROR: %s=%d %s=%d errno=(%d %s)\n", #a, __a, #b, __b,    \
           errno, strerror(errno));                                     \
    fail_fn();                                                          \
  }                                                                     \
} while(0)


#define NT_ASSERT(x)              __NT_TEST(x, sfnt_abort)
#define NT_ASSERTi3(a, op, b)     __NT_TESTi3(a, op, b, sfnt_abort)

#define NT_TEST(x)                __NT_TEST(x, sfnt_fail_test)
#define NT_TESTi3(a, op, b)       __NT_TESTi3(a, op, b, sfnt_fail_test)

#define NT_TRY(x)                                               \
do {                                                            \
  int __rc;                                                     \
  if( ((__rc) = (x)) < 0 ) {                                    \
    sfnt_err("ERROR: at %s:%d\n", __FILE__, __LINE__);          \
    sfnt_err("ERROR: %s failed\n", #x);                         \
    sfnt_err("ERROR: rc=%d errno=(%d %s)\n", (int) (__rc),      \
           errno, strerror(errno));                             \
    sfnt_fail_test();                                           \
  }                                                             \
} while(0)

#define NT_TRY2(rc, x)                                  \
do {                                                    \
  if( ((rc) = (x)) < 0 ) {                              \
    sfnt_err("ERROR: at %s:%d\n", __FILE__, __LINE__);  \
    sfnt_err("ERROR: %s failed\n", #x);                 \
    sfnt_err("ERROR: rc=%d errno=(%d %s)\n",            \
           (int) (rc), errno, strerror(errno));         \
    sfnt_fail_test();                                   \
  }                                                     \
} while(0)


/**********************************************************************
 * Information about the test environment.
 */

/* Dump generic information about the test environment.
 *
 * [tsc_opt] can be NULL.
 */
struct sfnt_tsc_params;
extern void sfnt_dump_sys_info(const struct sfnt_tsc_params* tsc_opt);

/* Return true if the onload transport library is linked to this
 * application, or present in LD_PRELOAD.
 *
 * This is slightly unreliable -- it can return false for old versions of
 * onload when it is linked via /etc/ld.so.preload.  Also it can return
 * true if onload is present in LD_PRELOAD but for some reason not linked.
 */
extern int sfnt_onload_is_active(void);

/* Dump info about onload-related execution environment to given stream.
 * Includes value of LD_PRELOAD, onload version (if available) and onload
 * configuration options in the environment.
 */
extern void sfnt_onload_info_dump(FILE* f, const char* prefix);


/**********************************************************************
 * Time measurement.
 */

struct sfnt_tsc_params {
  uint64_t  hz;
  uint64_t  tsc_cost;
};

/* Measure the speed of the CPU, in the units returned by sfnt_tsc(), and the
 * cost of sfnt_tsc().
 */
extern int sfnt_tsc_get_params(struct sfnt_tsc_params*);

/* Convert tsc delta to microseconds. */
extern int64_t sfnt_tsc_usec(const struct sfnt_tsc_params*, int64_t tsc);

/* Convert tsc delta to nanoseconds. */
extern int64_t sfnt_tsc_nsec(const struct sfnt_tsc_params*, int64_t tsc);


/**********************************************************************
 * Statistics.
 */

extern int sfnt_qsort_compare_int(const void* pa, const void* pb);

extern void sfnt_iarray_mean_and_limits(const int* start, const int* end,
                                      int* mean_out, int* min_out,
                                      int* max_out);

extern void sfnt_iarray_variance(const int* start, const int* end,
                               int mean, int64_t* variance_out);


/**********************************************************************
 * File / muxer convenience functions.
 */

extern int sfnt_fd_set_nonblocking(int fd);
extern int sfnt_fd_set_blocking(int fd);


enum sfnt_mux_flags {
  NT_MUX_SPIN     = 0x1,
};

/* Calls poll().  Adds option to spin and continues to wait if interrupted
 * by signal.
 */
extern int sfnt_poll(struct pollfd* fds, nfds_t nfds, int timeout,
                   enum sfnt_mux_flags flags);

/* Calls epoll_wait().  Adds option to spin and continues to wait if
 * interrupted by signal.
 */
extern int sfnt_epoll_wait(int epfd, struct epoll_event* events,
                         int maxevents, int timeout, enum sfnt_mux_flags flags);


/**********************************************************************
 * Socket convenience functions.
 */

/* Calls getaddrinfo().
 *
 * Port is determined as follows: Use [port_or_null] unless it is NULL.
 * Otherwise use [port_i_or_neg] unless it is negative.  Otherwise if
 * [host_or_hostport] has a ":port" suffix than that is used as the port.
 * Otherwise the port is 0.
 */
extern int sfnt_getaddrinfo(const char* host_or_hostport,
                            const char* port_or_null, int port_i_or_neg,
                            struct addrinfo**ai_out);

/* Get port number socket is bound to. */
extern int sfnt_get_port(int sock);

/* Bind socket to given port and INADDR_ANY. */
extern int sfnt_bind_port(int sock, int port);

/* Port selected as for sfnt_getaddrinfo(). */
extern int sfnt_bind(int sock, const char* host_or_hostport,
                     const char* port_or_null, int port_i_or_neg);

/* Port selected as for sfnt_getaddrinfo(). */
extern int sfnt_connect(int sock, const char* host_or_hostport,
                        const char* port_or_null, int port_i_or_neg);

/* Set the SO_BINDTODEVICE socket option.  [intf] must be an interface name
 * (eg. "eth3").
 */
extern int sfnt_so_bindtodevice(int sock, const char* intf);

/* Set the IP_MULTICAST_IF socket option.  [intf] may be an interface name
 * (eg. "eth3"), or a hostname or IP address of a local interface.
 */
extern int sfnt_ip_multicast_if(int sock, const char* intf);

/* Do setsockopt(IP_ADD_MEMBERSHIP).  [intf_opt] may be an interface name
 * (eg. "eth3"), or a hostname or IP address of a local interface, or NULL
 * (in which case the routing table is used to choose the interface).
 */
extern int sfnt_ip_add_membership(int sock, in_addr_t mcast_addr,
                                const char* intf_opt);

/* Set socket timeout.  [send_or_recv] must be SO_RCVTIMEO or SO_SNDTIMEO. */
extern int sfnt_sock_set_timeout(int sock, int send_or_recv, int millisec);

extern void sfnt_sock_put_int(int fd, int v);
extern int  sfnt_sock_get_int(int fd);
extern void  sfnt_sock_put_str(int fd, const char* str);
extern char* sfnt_sock_get_str(int fd);


/**********************************************************************
 * Byte swapping.
 */

#if NT_LITTLE_ENDIAN
# define NT_LE32(v)     (v)
# define NT_LE64(v)     (v)
#else
# error TODO
#endif


/**********************************************************************
 * Sequence-space comparisons.
 */

#define sfnt_int32_lt(a, b)      (((a) - (b)) & 0xf0000000)
#define sfnt_int32_gt(a, b)      sfnt_int32_lt((b), (a))
#define sfnt_int32_le(a, b)      (!sfnt_seq_lt((b), (a)))
#define sfnt_int32_ge(a, b)      (!sfnt_seq_lt((a), (b)))

#define sfnt_seq_eq(a, b, bits)  ((((a) - (b)) & ((1u << (bits)) - 1u)) == 0u)
#define sfnt_seq_neq(a, b, bits) (((a) - (b)) & ((1u << (bits)) - 1))
#define sfnt_seq_lt(a, b, bits)  (((a) - (b)) & (1u << ((bits) - 1)))
#define sfnt_seq_gt(a, b, bits)  sfnt_seq_lt((b), (a), (bits))
#define sfnt_seq_le(a, b, bits)  (!sfnt_seq_lt((b), (a), (bits)))
#define sfnt_seq_ge(a, b, bits)  (!sfnt_seq_lt((a), (b), (bits)))


/**********************************************************************
 * CPU affinity.
 */

/* Bind this thread to core [core_i]. */
extern int sfnt_cpu_affinity_set(int core_i);


/**********************************************************************
 * Misc. utility functions.
 */

/* Parse a string that (hopefully) contains a comma separated list of
 * non-negative integers and/or ranges.  Returns 0 on success, -EINVAL if
 * malformed, -ENOMEM if can't allocate memory.  Caller should free() the
 * returned memory when done with it.
 */
extern int sfnt_parse_int_list(const char* int_list_str,
                             int** int_list_out, int* int_list_len_out);


#endif  /* __NETTEST_H__ */
