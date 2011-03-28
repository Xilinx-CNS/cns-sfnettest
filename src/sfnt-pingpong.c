/**************************************************************************\
*    Filename: sfnt-pingpong.c
*      Author: David Riddoch <driddoch@solarflare.com>
* Description: Application to measure ping-pong latency.
*  Start date: 2005/03/06
*   Copyright: (C) 2005-2011 Solarflare Communications Inc.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License version 2 as published
* by the Free Software Foundation, incorporated herein by reference.
\**************************************************************************/

#include "sfnettest.h"


static int         cfg_port = 2048;
static int         cfg_connect;
static int         cfg_size = -1;
static int         cfg_spin;
static const char* cfg_muxer;
static const char* cfg_smuxer;
static int         cfg_rtt;
static const char* cfg_raw;
static float       cfg_percentile = 99;
static int         cfg_minmsg;
static int         cfg_maxmsg;
static int         cfg_minms = 1000;
static int         cfg_maxms = 3000;
static int         cfg_miniter = 1000;
static int         cfg_maxiter = 1000000;
static int         cfg_forkboth;
static const char* cfg_mcast;
static const char* cfg_mcast_intf;
static int         cfg_mcast_loop;
static const char* cfg_bindtodev;
static unsigned    cfg_n_pipe;
static unsigned    cfg_n_unixd;
static unsigned    cfg_n_unixs;
static unsigned    cfg_n_udp;
static unsigned    cfg_n_tcpc;
static unsigned    cfg_n_tcpl;
static const char* cfg_tcpc_serv;
static unsigned    cfg_mcast_sleep = 2;
static unsigned    cfg_timeout;
static const char* cfg_affinity;
static int         cfg_n_pings = 1;
static int         cfg_n_pongs = 1;
static int         cfg_nodelay;

static struct sfnt_cmd_line_opt cfg_opts[] = {
  {   0, "port",     NT_CLO_UINT, &cfg_port,   "server port#"                },
  {   0, "size",     NT_CLO_UINT, &cfg_size,   "single message size (bytes)" },
  {   0, "connect",  NT_CLO_FLAG, &cfg_connect,"connect() UDP socket"        },
  {   0, "spin",     NT_CLO_FLAG, &cfg_spin,   "spin on non-blocking recv()" },
  {   0, "muxer",    NT_CLO_STR,  &cfg_muxer,  "select, poll or epoll"       },
  {   0, "serv-muxer",NT_CLO_STR, &cfg_smuxer, "none, select, poll or epoll "
                                               "(same as client by default)"},
  {   0, "rtt",      NT_CLO_FLAG, &cfg_rtt,    "report round-trip-time"      },
  {   0, "raw",      NT_CLO_STR,  &cfg_raw,    "dump raw results to files"   },
  {   0, "percentile",NT_CLO_FLOAT,&cfg_percentile,"percentile"              },
  {   0, "minmsg",   NT_CLO_INT,  &cfg_minmsg, "min message size"            },
  {   0, "maxmsg",   NT_CLO_INT,  &cfg_maxmsg, "max message size"            },
  {   0, "minms",    NT_CLO_INT,  &cfg_minms,  "min time per msg size (ms)"  },
  {   0, "maxms",    NT_CLO_INT,  &cfg_maxms,  "max time per msg size (ms)"  },
  {   0, "miniter",  NT_CLO_INT,  &cfg_miniter,"min iterations for result"   },
  {   0, "maxiter",  NT_CLO_INT,  &cfg_maxiter,"max iterations for result"   },
  {   0, "mcast",    NT_CLO_STR,  &cfg_mcast,  "use multicast addressing"    },
  {   0, "mcastintf",NT_CLO_STR,  &cfg_mcast_intf,"set multicast interface"  },
  {   0, "mcastloop",NT_CLO_FLAG, &cfg_mcast_loop,"IP_MULTICAST_LOOP"        },
  {   0, "bindtodev",NT_CLO_STR,  &cfg_bindtodev, "SO_BINDTODEVICE"          },
  {   0, "forkboth", NT_CLO_FLAG, &cfg_forkboth,"fork client and server"     },
  {   0, "n-pipe",   NT_CLO_UINT, &cfg_n_pipe, "include pipes in fd set"     },
  {   0, "n-unix-d", NT_CLO_UINT, &cfg_n_unixd,"include unix dgram in fd set"},
  {   0, "n-unix-s", NT_CLO_UINT, &cfg_n_unixs,"include unix strm in fd set" },
  {   0, "n-udp",    NT_CLO_UINT, &cfg_n_udp,  "include UDP socks in fd set" },
  {   0, "n-tcpc",   NT_CLO_UINT, &cfg_n_tcpc, "include TCP socks in fd set" },
  {   0, "n-tcpl",   NT_CLO_UINT, &cfg_n_tcpl, "include TCP listeners in fds"},
  {   0, "tcpc-serv",NT_CLO_STR,  &cfg_tcpc_serv,"host:port for tcp conns"   },
  {   0, "timeout",  NT_CLO_UINT, &cfg_timeout,"socket SND?RECV timeout"     },
  {   0, "affinity", NT_CLO_STR,  &cfg_affinity,"<client-core>,<server-core>"},
  {   0, "n-pings",  NT_CLO_UINT, &cfg_n_pings, "number of ping messages"    },
  {   0, "n-pongs",  NT_CLO_UINT, &cfg_n_pongs, "number of pong messages"    },
  {   0, "nodelay",  NT_CLO_FLAG, &cfg_nodelay, "enable TCP_NODELAY"         },
};
#define N_CFG_OPTS (sizeof(cfg_opts) / sizeof(cfg_opts[0]))


struct stats {
  int mean;
  int min;
  int median;
  int max;
  int percentile;
  int stddev;
};


enum fd_type_flags {
  FDTF_SOCKET = 0x100,
  FDTF_LOCAL  = 0x200,
  FDTF_STREAM = 0x400,
};


enum fd_type {
  FDT_TCP     = 0 | FDTF_SOCKET | 0          | FDTF_STREAM,
  FDT_UDP     = 1 | FDTF_SOCKET | 0          | 0,
  FDT_PIPE    = 2 | 0           | FDTF_LOCAL | FDTF_STREAM,
  FDT_UNIX_S  = 3 | FDTF_SOCKET | FDTF_LOCAL | FDTF_STREAM,
  FDT_UNIX_D  = 4 | FDTF_SOCKET | FDTF_LOCAL | 0,
};


#define MAX_FDS            1024

static struct sfnt_tsc_params tsc;
static char           ppbuf[64 * 1024];

static enum fd_type   fd_type;
static int            the_fds[4];  /* used for pipes and unix sockets */
static int            affinity_core_i = -1;

static fd_set         select_fdset;
static int            select_fds[MAX_FDS];
static int            select_n_fds;
static int            select_max_fd;

static struct sockaddr_in  peer_sa;
static struct sockaddr*    to_sa;
static socklen_t           to_sa_len;

static int                 timeout_ms;

#if NT_HAVE_POLL
static struct pollfd       pfds[MAX_FDS];
static int                 pfds_n;
#endif

#if NT_HAVE_EPOLL
static int                 epoll_fd;
#endif

static ssize_t (*do_recv)(int, void*, size_t, int);
static ssize_t (*do_send)(int, const void*, size_t, int);

static ssize_t (*mux_recv)(int, void*, size_t, int);
static void (*mux_add)(int fd);


static void noop_add(int fd)
{
}

/**********************************************************************/

#define rfn_recv  recv


static ssize_t sfn_sendto(int fd, const void* buf, size_t len, int flags)
{
  return sendto(fd, buf, len, 0, to_sa, to_sa_len);
}


#define sfn_send  send


static ssize_t rfn_read(int fd, void* buf, size_t len, int flags)
{
  /* NB. To support non-blocking semantics caller must have set O_NONBLOCK. */
  int rc, got = 0, all = flags & MSG_WAITALL;
  do {
    if( (rc = read(fd, (char*) buf + got, len)) > 0 )
      got += rc;
  } while( all && got < len && rc > 0 );
  return got ? got : rc;
}


static ssize_t sfn_write(int fd, const void* buf, size_t len, int flags)
{
  return write(fd, buf, len);
}

/**********************************************************************/

static void select_init(void)
{
  NT_ASSERT(cfg_spin == 0);  /* spin not yet supported with select */
  FD_ZERO(&select_fdset);
}


static void select_add(int fd)
{
  NT_TEST(select_n_fds < MAX_FDS);
  select_fds[select_n_fds++] = fd;
  if( fd > select_max_fd )
    select_max_fd = fd;
}


static ssize_t select_recv(int fd, void* buf, size_t len, int flags)
{
  /* ?? TODO: spin variant */
  int i, rc, got = 0, all = flags & MSG_WAITALL;
  flags = (flags & ~MSG_WAITALL) | MSG_DONTWAIT;
  do {
    for( i = 0; i < select_n_fds; ++i )
      FD_SET(select_fds[i], &select_fdset);
    rc = select(select_max_fd + 1, &select_fdset, NULL, NULL, NULL);
    NT_TESTi3(rc, ==, 1);
    NT_TEST(FD_ISSET(fd, &select_fdset));
    if( (rc = do_recv(fd, (char*) buf + got, len - got, flags)) > 0 )
      got += rc;
  } while( all && got < len && rc > 0 );
  return got ? got : rc;
}

/**********************************************************************/

#if NT_HAVE_POLL

static void poll_add(int fd)
{
  NT_TEST(pfds_n < MAX_FDS);
  pfds[pfds_n].fd = fd;
  pfds[pfds_n].events = POLLIN;
  ++pfds_n;
}


static ssize_t poll_recv(int fd, void* buf, size_t len, int flags)
{
  int rc, got = 0, all = flags & MSG_WAITALL;
  flags = (flags & ~MSG_WAITALL) | MSG_DONTWAIT;
  do {
    rc = sfnt_poll(pfds, pfds_n, timeout_ms, cfg_spin ? NT_MUX_SPIN : 0);
    NT_TESTi3(rc, ==, 1);
    NT_TEST(pfds[0].revents & POLLIN);
    if( (rc = do_recv(fd, (char*) buf + got, len - got, flags)) > 0 )
      got += rc;
  } while( all && got < len && rc > 0 );
  return got ? got : rc;
}

#endif

/**********************************************************************/

#if NT_HAVE_EPOLL

static void epoll_init(void)
{
  NT_TRY2(epoll_fd, epoll_create(1));
}


static void epoll_add(int fd)
{
  struct epoll_event e;
  e.events = EPOLLIN /* ?? | EPOLLET */;
  NT_TRY(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &e));
}


static ssize_t epoll_recv(int fd, void* buf, size_t len, int flags)
{
  struct epoll_event e;
  int rc, got = 0, all = flags & MSG_WAITALL;
  flags = (flags & ~MSG_WAITALL) | MSG_DONTWAIT;
  do {
    rc = sfnt_epoll_wait(epoll_fd, &e, 1, timeout_ms, cfg_spin);
    NT_TESTi3(rc, ==, 1);
    NT_TEST(e.events & EPOLLIN);
    if( (rc = do_recv(fd, (char*) buf + got, len - got, flags)) > 0 )
      got += rc;
  } while( all && got < len && rc > 0 );
  return got ? got : rc;
}


static ssize_t epoll_mod_recv(int fd, void* buf, size_t len, int flags)
{
  struct epoll_event e;
  int rc, got = 0, all = flags & MSG_WAITALL;
  flags = (flags & ~MSG_WAITALL) | MSG_DONTWAIT;
  e.events = EPOLLIN;
  NT_TRY(epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &e));
  do {
    rc = sfnt_epoll_wait(epoll_fd, &e, 1, timeout_ms, cfg_spin);
    NT_TESTi3(rc, ==, 1);
    NT_TEST(e.events & EPOLLIN);
    if( (rc = do_recv(fd, (char*) buf + got, len - got, flags)) > 0 )
      got += rc;
  } while( all && got < len && rc > 0 );
  e.events = 0;
  NT_TRY(epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &e));
  return got ? got : rc;
}


static ssize_t epoll_adddel_recv(int fd, void* buf, size_t len, int flags)
{
  struct epoll_event e;
  int rc, got = 0, all = flags & MSG_WAITALL;
  flags = (flags & ~MSG_WAITALL) | MSG_DONTWAIT;
  e.events = EPOLLIN;
  NT_TRY(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &e));
  do {
    rc = sfnt_epoll_wait(epoll_fd, &e, 1, timeout_ms, cfg_spin);
    NT_TESTi3(rc, ==, 1);
    NT_TEST(e.events & EPOLLIN);
    if( (rc = do_recv(fd, (char*) buf + got, len - got, flags)) > 0 )
      got += rc;
  } while( all && got < len && rc > 0 );
  e.events = 0;
  NT_TRY(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, &e));
  return got ? got : rc;
}

#endif

/**********************************************************************/

static ssize_t spin_recv(int fd, void* buf, size_t len, int flags)
{
  int rc, got = 0, all = flags & MSG_WAITALL;
  flags = (flags & ~MSG_WAITALL) | MSG_DONTWAIT;
  do {
    while( (rc = do_recv(fd, (char*) buf + got, len - got, flags)) < 0 )
      if( errno != EAGAIN )
        goto out;
    got += rc;
  } while( all && got < len && rc > 0 );
 out:
  return got ? got : rc;
}

/**********************************************************************/

static void do_init(void)
{
  if( affinity_core_i >= 0 )
    if( sfnt_cpu_affinity_set(affinity_core_i) != 0 ) {
      sfnt_err("ERROR: Failed to set CPU affinity to core %d (%d %s)\n",
             affinity_core_i, errno, strerror(errno));
      sfnt_fail_test();
    }

  NT_TRY(sfnt_tsc_get_params(&tsc));

  if( fd_type == FDT_UDP && ! cfg_connect ) {
    do_recv = rfn_recv;
    do_send = sfn_sendto;
  }
  else if( fd_type & FDTF_SOCKET ) {
    do_recv = rfn_recv;
    do_send = sfn_send;
  }
  else {
    do_recv = rfn_read;
    do_send = sfn_write;
  }

  if( cfg_muxer == NULL || ! strcasecmp(cfg_muxer, "") ||
      ! strcasecmp(cfg_muxer, "none") ) {
    mux_recv = cfg_spin ? spin_recv : do_recv;
    mux_add = noop_add;
  }
  else if( ! strcasecmp(cfg_muxer, "select") ) {
    mux_recv = select_recv;
    mux_add = select_add;
    select_init();
  }
#if NT_HAVE_POLL
  else if( ! strcasecmp(cfg_muxer, "poll") ) {
    mux_recv = poll_recv;
    mux_add = poll_add;
  }
#endif
#if NT_HAVE_EPOLL
  else if( ! strcasecmp(cfg_muxer, "epoll") ) {
    mux_recv = epoll_recv;
    mux_add = epoll_add;
    epoll_init();
  }
  else if( ! strcasecmp(cfg_muxer, "epoll_mod") ) {
    mux_recv = epoll_mod_recv;
    mux_add = epoll_add;
    epoll_init();
  }
  else if( ! strcasecmp(cfg_muxer, "epoll_adddel") ) {
    mux_recv = epoll_adddel_recv;
    mux_add = noop_add;
    epoll_init();
  }
#endif
  else {
    sfnt_fail_usage("ERROR: Unknown muxer");
  }
}


static void do_ping(int read_fd, int write_fd, int sz)
{
  int i, rc;
  for( i = 0; i < cfg_n_pings; ++i ) {
    rc = do_send(write_fd, ppbuf, sz, 0);
    NT_TESTi3(rc, ==, sz);
  }
  for( i = 0; i < cfg_n_pongs; ++i ) {
    rc = mux_recv(read_fd, ppbuf, sz, MSG_WAITALL);
    NT_TESTi3(rc, ==, sz);
  }
}


static void do_pong(int read_fd, int write_fd, int sz)
{
  int i, rc;
  for( i = 0; i < cfg_n_pings; ++i ) {
    rc = mux_recv(read_fd, ppbuf, sz, MSG_WAITALL);
    NT_TESTi3(rc, ==, sz);
  }
  for( i = 0; i < cfg_n_pongs; ++i ) {
    rc = do_send(write_fd, ppbuf, sz, 0);
    NT_TESTi3(rc, ==, sz);
  }
}


static void add_fds(int us)
{
  unsigned i;
  int sock;

  mux_add(us);
#ifdef __unix__
  for( i = 0; i < cfg_n_pipe; ++i ) {
    int pfd[2];
    NT_TEST(pipe(pfd) == 0);
    mux_add(pfd[0]);
    if( ++i < cfg_n_pipe )
      /* Slightly dodgy that we're selecting on the "write" fd for read.
       * The write fd is never readable, so it does at least work, but I
       * suppose the performance might not be quite the same.  Advantage of
       * doing it this way is we don't waste file descriptors.
       */
      mux_add(pfd[1]);
  }
  for( i = 0; i < cfg_n_unixd; ++i ) {
    int fds[2];
    NT_TEST(socketpair(PF_UNIX, SOCK_DGRAM, 0, fds) == 0);
    mux_add(fds[0]);
    if( ++i < cfg_n_unixd )
      mux_add(fds[1]);
  }
  for( i = 0; i < cfg_n_unixs; ++i ) {
    int fds[2];
    NT_TEST(socketpair(PF_UNIX, SOCK_STREAM, 0, fds) == 0);
    mux_add(fds[0]);
    if( ++i < cfg_n_unixs )
      mux_add(fds[1]);
  }
#endif
  for( i = 0; i < cfg_n_udp; ++i ) {
    NT_TRY2(sock, socket(PF_INET, SOCK_DGRAM, 0));
    mux_add(sock);
  }
  for( i = 0; i < cfg_n_tcpc; ++i ) {
    NT_TRY2(sock, socket(PF_INET, SOCK_STREAM, 0));
    NT_TRY(sfnt_connect(sock, cfg_tcpc_serv, 0));
    mux_add(sock);
  }
  for( i = 0; i < cfg_n_tcpl; ++i ) {
    NT_TRY2(sock, socket(PF_INET, SOCK_STREAM, 0));
    NT_TRY(listen(sock, 1));
    mux_add(sock);
  }
}


static void bind_udp_sock(int us, int ss)
{
  struct sockaddr_in sa;
  socklen_t sa_len;

  if( fd_type != FDT_UDP )
    return;

  if( cfg_bindtodev )
    NT_TRY(sfnt_so_bindtodevice(us, cfg_bindtodev));

  if( cfg_mcast ) {
    sa.sin_family = AF_INET;
    sa.sin_port = 0;
    sa.sin_addr.s_addr = inet_addr(cfg_mcast);
    NT_TRY(bind(us, (struct sockaddr*) &sa, sizeof(sa)));
    if( cfg_mcast_intf )
      NT_TRY(sfnt_ip_multicast_if(us, cfg_mcast_intf));
    NT_TRY(sfnt_ip_add_membership(us, inet_addr(cfg_mcast), cfg_mcast_intf));
    NT_TRY(setsockopt(us, SOL_IP, IP_MULTICAST_LOOP,
                      &cfg_mcast_loop, sizeof(cfg_mcast_loop)));
    sleep(cfg_mcast_sleep);
  }
  else {
    /* Bind to same local interface as the setup socket. */
    sa_len = sizeof(sa);
    NT_TRY(getsockname(ss, (struct sockaddr*) &sa, &sa_len));
    sa.sin_port = 0;
    NT_TRY(bind(us, (struct sockaddr*) &sa, sizeof(sa)));
  }
}


static void exchange_addrs(int us, int ss)
{
  /* Tell client our address, and get their's. */

  struct sockaddr_in sa;
  socklen_t sa_len = sizeof(sa);

  NT_TRY(getsockname(us, (struct sockaddr*) &sa, &sa_len));
  NT_TEST(send(ss, &sa, sizeof(sa), 0) == sizeof(sa));
  NT_TEST(recv(ss, &peer_sa, sizeof(peer_sa), MSG_WAITALL) == sizeof(peer_sa));

  if( cfg_connect ) {
    NT_TRY(connect(us, (struct sockaddr*) &peer_sa, sizeof(peer_sa)));
    to_sa = NULL;
    to_sa_len = 0;
  }
  else {
    to_sa = (struct sockaddr*) &peer_sa;
    to_sa_len = sizeof(peer_sa);
  }
}


static void set_sock_timeouts(int sock)
{
  if( cfg_timeout ) {
    struct timeval tv;
    tv.tv_sec = cfg_timeout;
    tv.tv_usec = 0;
    NT_TRY(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)));
    NT_TRY(setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)));
  }
}


static int do_server2(int ss);


static int do_server(void)
{
  int sl, ss, one = 1;

  /* Open listening socket, and wait for client to connect. */
  NT_TRY2(sl, socket(PF_INET, SOCK_STREAM, 0));
  NT_TRY(setsockopt(sl, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)));
  NT_TRY(sfnt_bind_port(sl, cfg_port));
  NT_TRY(listen(sl, 1));
  if( ! sfnt_quiet )
    sfnt_err("%s: server: waiting for client to connect...\n", sfnt_app_name);
  NT_TRY2(ss, accept(sl, NULL, NULL));
  if( ! sfnt_quiet )
    sfnt_err("%s: server: client connected\n", sfnt_app_name);
  close(sl);
  sl = -1;

  return do_server2(ss);
}


static int do_server2(int ss)
{
  int sl, iter, msg_size;
  int read_fd, write_fd;

  sfnt_sock_put_str(ss, SFNT_VERSION);
  sfnt_sock_put_str(ss, SFNT_SRC_CSUM);

  fd_type = sfnt_sock_get_int(ss);
  cfg_connect = sfnt_sock_get_int(ss);
  cfg_spin = sfnt_sock_get_int(ss);
  cfg_muxer = sfnt_sock_get_str(ss);
  cfg_mcast_loop = sfnt_sock_get_int(ss);
  cfg_n_pipe = sfnt_sock_get_int(ss);
  cfg_n_udp = sfnt_sock_get_int(ss);
  cfg_n_tcpc = sfnt_sock_get_int(ss);
  cfg_n_tcpl = sfnt_sock_get_int(ss);
  affinity_core_i = sfnt_sock_get_int(ss);
  cfg_n_pings = sfnt_sock_get_int(ss);
  cfg_n_pongs = sfnt_sock_get_int(ss);
  cfg_nodelay = sfnt_sock_get_int(ss);
  sfnt_sock_put_int(ss, sfnt_onload_is_active());

  /* Init after we've received config opts from client. */
  do_init();

  /* Create and bind/connect test socket. */
  switch( fd_type ) {
  case FDT_TCP: {
    struct sockaddr_in sa;
    socklen_t sa_len = sizeof(sa);
    NT_TRY2(sl, socket(PF_INET, SOCK_STREAM, 0));
    if( cfg_bindtodev )
      NT_TRY(sfnt_so_bindtodevice(sl, cfg_bindtodev));
    NT_TRY(listen(sl, 1));
    NT_TRY(getsockname(sl, (struct sockaddr*) &sa, &sa_len));
    sfnt_sock_put_int(ss, ntohs(sa.sin_port));
    NT_TRY2(read_fd, accept(sl, NULL, NULL));
    write_fd = read_fd;
    close(sl);
    sl = -1;
    break;
  }
  case FDT_UDP:
    NT_TRY2(read_fd, socket(PF_INET, SOCK_DGRAM, 0));
    bind_udp_sock(read_fd, ss);
    exchange_addrs(read_fd, ss);
    write_fd = read_fd;
    break;
  case FDT_PIPE:
    read_fd = the_fds[2];
    write_fd = the_fds[1];
    if( cfg_spin ) {
      sfnt_fd_set_nonblocking(read_fd);
      sfnt_fd_set_nonblocking(write_fd);
    }
    break;
  case FDT_UNIX_S:
  case FDT_UNIX_D:
    read_fd = write_fd = the_fds[1];
    break;
  }
  if( fd_type & FDTF_SOCKET )
    set_sock_timeouts(read_fd);
  add_fds(read_fd);

  while( 1 ) {
    iter = sfnt_sock_get_int(ss);
    if( iter == 0 )
      break;
    msg_size = sfnt_sock_get_int(ss);

    while( iter-- )
      do_pong(read_fd, write_fd, msg_size);
  }

  NT_TESTi3(recv(ss, ppbuf, 1, 0), ==, 0);

  return 0;
}


static void do_pings(int ss, int read_fd, int write_fd, int msg_size,
                     int iter, int* results)
{
  uint64_t start, stop;
  int i;

  sfnt_sock_put_int(ss, iter + 1);
  sfnt_sock_put_int(ss, msg_size);

  /* Touch to ensure resident. */
  memset(results, 0, iter * sizeof(results[0]));

  /* Ensure server is ready. */
  do_ping(read_fd, write_fd, msg_size);

  for( i = 0; i < iter; ++i ) {
    sfnt_tsc(&start);
    do_ping(read_fd, write_fd, msg_size);
    sfnt_tsc(&stop);
    results[i] = (int) sfnt_tsc_nsec(&tsc, stop - start - tsc.tsc_cost);
    if( ! cfg_rtt )
      results[i] /= 2;
  }
}


static void get_stats(struct stats* s, int* results, int results_n)
{
  int* results_end = results + results_n;
  int64_t variance;

  qsort(results, results_n, sizeof(int), &sfnt_qsort_compare_int);
  sfnt_iarray_mean_and_limits(results, results_end, &s->mean, &s->min, &s->max);

  s->median = results[results_n >> 1u];
  s->percentile = results[(int) (results_n * cfg_percentile / 100)];
  sfnt_iarray_variance(results, results_end, s->mean, &variance);
  s->stddev = (int) sqrt((double) variance);
}


static void write_raw_results(int msg_size, int* results, int results_n)
{
  char fname[strlen(cfg_raw) + 30];
  FILE* f;
  int i;
  sprintf(fname, "%s-%d.dat", cfg_raw, msg_size);
  if( (f = fopen(fname, "w")) == NULL ) {
    sfnt_err("ERROR: Could not open output file '%s'\n", fname);
    sfnt_fail_test();
  }
  for( i = 0; i < results_n; ++i )
    fprintf(f, "%d\n", results[i]);
  fclose(f);
}


static void do_test(int ss, int read_fd, int write_fd,
                    int msg_size, int* results)
{
  int n_this_time = cfg_miniter;
  struct timeval start, end;
  int ms, results_n = 0;
  struct stats s;

  gettimeofday(&start, NULL);

  do {
    if( results_n + n_this_time > cfg_maxiter )
      n_this_time = cfg_maxiter - results_n;

    do_pings(ss, read_fd, write_fd, msg_size,
             n_this_time, results + results_n);
    results_n += n_this_time;

    gettimeofday(&end, NULL);
    ms = (end.tv_sec - start.tv_sec) * 1000;
    ms += (end.tv_usec - start.tv_usec) / 1000;
  } while( (ms < cfg_maxms && results_n < cfg_maxiter) ||
           (ms < cfg_minms || results_n < cfg_miniter) );

  if( cfg_raw != NULL )
    write_raw_results(msg_size, results, results_n);
  get_stats(&s, results, results_n);
  printf("\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n", msg_size,
         s.mean, s.min, s.median, s.max, s.percentile, s.stddev, results_n);
  fflush(stdout);
}


static unsigned log2_le(unsigned n)
{
  unsigned order = 0;
  while( (1 << order) <= n )
    ++order;
  return order - 1;
}


static int next_msg_size(int prev_msg_size)
{
  if( fd_type & FDTF_STREAM )
    return prev_msg_size * 2;

  switch( prev_msg_size ) {
  case 0:
    return 1;
  case 1024:
    return 1472;  /* max udp msg size w/o fragmentation (w std MTU) */
  case 1472:
    return 1473;
  default:
    return 1 << (log2_le(prev_msg_size) + 1);
  }
}


static void send_opts_to_server(int ss, int server_core_i)
{
  sfnt_sock_put_int(ss, fd_type);
  sfnt_sock_put_int(ss, cfg_connect);
  sfnt_sock_put_int(ss, cfg_spin);
  sfnt_sock_put_str(ss, cfg_smuxer ? cfg_smuxer : cfg_muxer);
  sfnt_sock_put_int(ss, cfg_mcast_loop);
  sfnt_sock_put_int(ss, cfg_n_pipe);
  sfnt_sock_put_int(ss, cfg_n_udp);
  sfnt_sock_put_int(ss, cfg_n_tcpc);
  sfnt_sock_put_int(ss, cfg_n_tcpl);
  sfnt_sock_put_int(ss, server_core_i);
  sfnt_sock_put_int(ss, cfg_n_pings);
  sfnt_sock_put_int(ss, cfg_n_pongs);
  sfnt_sock_put_int(ss, cfg_nodelay);
}


static int try_connect(int sock, const char* hostport, int default_port)
{
  int max_attempts = 100;
  int rc, n_attempts = 0;
  while( 1 ) {
    rc = sfnt_connect(sock, hostport, default_port);
    if( rc == 0 || ++n_attempts == max_attempts || errno != ECONNREFUSED )
      return rc;
    if( n_attempts == 1 && ! sfnt_quiet )
      sfnt_err("%s: client: waiting for server to start\n", sfnt_app_name);
    usleep(100000);
  }
}


static int do_client2(int ss, const char* hostport, int local);


static int do_client(int argc, char* argv[])
{
  const char* hostport;
  const char* fd_type_s;
  pid_t pid;

  if( argc < 1 || argc > 2 )
    sfnt_fail_usage(0);
  fd_type_s = argv[0];
  if( ! strcasecmp(fd_type_s, "tcp") )
    fd_type = FDT_TCP;
  else if( ! strcasecmp(fd_type_s, "udp") )
    fd_type = FDT_UDP;
  else if( ! strcasecmp(fd_type_s, "pipe") )
    fd_type = FDT_PIPE;
  else if( ! strcasecmp(fd_type_s, "unix_stream") )
    fd_type = FDT_UNIX_S;
  else if( ! strcasecmp(fd_type_s, "unix_datagram") )
    fd_type = FDT_UNIX_D;
  else
    sfnt_fail_usage(0);

  if( cfg_muxer == NULL )
    cfg_muxer = "none";

  if( fd_type & FDTF_LOCAL ) {
    int ss[2];
    if( argc != 1 )
      sfnt_fail_usage(0);
    switch( fd_type ) {
    case FDT_PIPE:
      NT_TRY(pipe(the_fds));
      NT_TRY(pipe(the_fds + 2));
      break;
    case FDT_UNIX_S:
      NT_TRY(socketpair(PF_UNIX, SOCK_STREAM, 0, the_fds));
      break;
    case FDT_UNIX_D:
      NT_TRY(socketpair(PF_UNIX, SOCK_DGRAM, 0, the_fds));
      break;
    default:
      break;
    }
    NT_TRY(socketpair(PF_UNIX, SOCK_STREAM, 0, ss));
    NT_TRY2(pid, fork());
    if( pid == 0 ) {
      NT_TRY(close(ss[0]));
      sfnt_quiet = 1;
      return do_server2(ss[1]);
    }
    else {
      NT_TRY(close(ss[1]));
      return do_client2(ss[0], "localhost", 1);
    }
  }
  else {
    int ss, local, one = 1;
    if( argc == 2 ) {
      hostport = argv[1];
      local = 0;
    }
    else {
      NT_TRY2(pid, fork());
      if( pid == 0 ) {
        sfnt_quiet = 1;
        return do_server();
      }
      hostport = "localhost";
      local = 1;
    }
    NT_TRY2(ss, socket(PF_INET, SOCK_STREAM, 0));
    NT_TRY(setsockopt(ss, SOL_TCP, TCP_NODELAY, &one, sizeof(one)));
    NT_TRY(try_connect(ss, hostport, cfg_port));
    return do_client2(ss, hostport, local);
  }
}


static int do_client2(int ss, const char* hostport, int local)
{
  char* serv_csum;
  char* serv_ver;
  int server_core_i = -1;
  int read_fd, write_fd;
  int affinity_len;
  int server_onload;
  int msg_size;
  int* results;
  int* affinity;
  int one = 1;
  int rc;

  /* Ensure the other end is identical. */
  serv_ver  = sfnt_sock_get_str(ss);
  serv_csum = sfnt_sock_get_str(ss);
  if( strcmp(serv_ver, SFNT_VERSION) ) {
    sfnt_err("ERROR: Version mismatch: me=%s server=%s\n",
             SFNT_VERSION, serv_ver);
    sfnt_fail_test();
  }
  if( strcmp(serv_csum, SFNT_SRC_CSUM) ) {
    sfnt_err("ERROR: Source Checksum mismatch:\n");
    sfnt_err("ERROR:     me=%s\n", SFNT_SRC_CSUM);
    sfnt_err("ERROR: server=%s\n", serv_csum);
    sfnt_fail_test();
  }

  if( cfg_affinity == NULL ) {
    /* Set affinity by default.  Avoid core 0, which often has various OS
     * junk running on it that causes high jitter.  We'll get an error on
     * singe core boxes -- user will just have to set affinity explicitly.
     */
    if( local && cfg_spin )
      /* It is a very bad idea to pin two spinners onto the same core, as
       * they'll just fight each other for timeslices.
       */
      cfg_affinity = "1,2";
    else
      cfg_affinity = "1,1";
  }
  if( strcasecmp(cfg_affinity, "") && strcasecmp(cfg_affinity, "any") &&
      strcasecmp(cfg_affinity, "none") ) {
    rc = sfnt_parse_int_list(cfg_affinity, &affinity, &affinity_len);
    if( rc != 0 || affinity_len != 2 )
      sfnt_fail_usage("ERROR: Bad --affinity option");
    affinity_core_i = affinity[0];
    server_core_i = affinity[1];
  }

  do_init();

  send_opts_to_server(ss, server_core_i);
  server_onload = sfnt_sock_get_int(ss);

  /* Create and bind/connect test socket. */
  switch( fd_type ) {
  case FDT_TCP: {
    char host[strlen(hostport) + 1];
    char* p;
    strcpy(host, hostport);
    if( (p = strchr(host, ':')) != NULL )
      *p = '\0';
    int port = sfnt_sock_get_int(ss);
    NT_TRY2(read_fd, socket(PF_INET, SOCK_STREAM, 0));
    if( cfg_nodelay )
      NT_TRY(setsockopt(read_fd, SOL_TCP, TCP_NODELAY, &one, sizeof(one)));
    NT_TRY(sfnt_connect(read_fd, host, port));
    write_fd = read_fd;
    break;
  }
  case FDT_UDP:
    NT_TRY2(read_fd, socket(PF_INET, SOCK_DGRAM, 0));
    bind_udp_sock(read_fd, ss);
    exchange_addrs(read_fd, ss);
    write_fd = read_fd;
    break;
  case FDT_PIPE:
    read_fd = the_fds[0];
    write_fd = the_fds[3];
    if( cfg_spin ) {
      sfnt_fd_set_nonblocking(read_fd);
      sfnt_fd_set_nonblocking(write_fd);
    }
    break;
  case FDT_UNIX_S:
  case FDT_UNIX_D:
    read_fd = write_fd = the_fds[0];
    break;
  }
  if( fd_type & FDTF_SOCKET )
    set_sock_timeouts(read_fd);
  add_fds(read_fd);

  results = malloc(cfg_maxiter * sizeof(*results));
  NT_TEST(results != NULL);
  sfnt_dump_sys_info(&tsc);
  printf("# options: %s%s%s\n",
         cfg_connect ? "connect ":"",
         cfg_spin ? "spin ":"",
         cfg_rtt ? "rtt ":"");
  printf("# muxer=%s serv-muxer=%s\n",
         cfg_muxer, cfg_smuxer ? cfg_smuxer : cfg_muxer);
  printf("# affinity=%s\n", cfg_affinity);
  printf("# iter=%d-%d ms=%d-%d\n",
         cfg_miniter, cfg_maxiter, cfg_minms, cfg_maxms);
  printf("# multicast=%s loop=%d\n",
         cfg_mcast ? cfg_mcast : "NO", cfg_mcast_loop);
  printf("# percentile=%g\n", (double) cfg_percentile);
  printf("# server_onload=%d\n", server_onload);
  sfnt_onload_info_dump(stdout, "# ");
  printf("#\n");
  printf("#\tsize\tmean\tmin\tmedian\tmax\t%%ile\tstddev\titer\n");

  if( fd_type & FDTF_STREAM ) {
    if( cfg_minmsg == 0 )
      cfg_minmsg = 1;
    if( cfg_maxmsg == 0 )
      cfg_maxmsg = 64 * 1024;
  }
  else {
    if( cfg_maxmsg == 0 )
      cfg_maxmsg = 32 * 1024;
  }

  if( cfg_size > 0 )
    do_test(ss, read_fd, write_fd, cfg_size, results);
  else {
    for( msg_size = cfg_minmsg; msg_size <= cfg_maxmsg;
         msg_size = next_msg_size(msg_size) )
      do_test(ss, read_fd, write_fd, msg_size, results);
  }

  /* Tell server side to exit. */
  sfnt_sock_put_int(ss, 0);

  return 0;
}


int main(int argc, char* argv[])
{
  pid_t pid = 0;
  int rc = 0;

  sfnt_app_getopt("[<tcp|udp|pipe|unix_stream|unix_datagram> [<host[:port]>]]",
                &argc, argv, cfg_opts, N_CFG_OPTS);
  --argc; ++argv;

  if( cfg_miniter > cfg_maxiter )
    cfg_maxiter = cfg_miniter;
  if( cfg_minms > cfg_maxms )
    cfg_maxms = cfg_minms;
  NT_ASSERT(cfg_maxiter >= cfg_miniter);
  timeout_ms = cfg_timeout ? cfg_timeout * 1000 : -1;

#ifdef __unix__
  if( cfg_forkboth ) {
    NT_TRY2(pid, fork());
    if( pid == 0 )
      /* parent is the client. Give server a chance to start */
      sleep(1);
    else
      argc = 0;
  }
#endif

  if( argc == 0 )
    rc = -do_server();
  else
    rc = -do_client(argc, argv);

#ifdef __unix__
  if( pid ) {
    int status;
    kill(pid, SIGINT);
    waitpid(pid, &status ,0);
  }
#endif

  return rc;
}

/*! \cidoxg_end */
