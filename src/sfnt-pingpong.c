/**************************************************************************\
*    Filename: sfnt-pingpong.c
*      Author: David Riddoch <driddoch@solarflare.com>
* Description: Application to measure ping-pong latency.
*  Start date: 2005/03/06
*   Copyright: (C) 2005-2012 Solarflare Communications Inc.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License version 2 as published
* by the Free Software Foundation, incorporated herein by reference.
\**************************************************************************/

#include "sfnettest.h"


static int         cfg_port = 2048;
static int         cfg_connect[2];
static const char* cfg_sizes;
static int         cfg_spin[2];
static const char* cfg_muxer[2];
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
static const char* cfg_mcast_intf[2];
static int         cfg_mcast_loop[2];
static int         cfg_ttl[2] = { 1, 1 };
static const char* cfg_bind[2];
static const char* cfg_bindtodev[2];
static unsigned    cfg_n_pipe[2];
static unsigned    cfg_n_unixd[2];
static unsigned    cfg_n_unixs[2];
static unsigned    cfg_n_udp[2];
static unsigned    cfg_n_tcpc[2];
static unsigned    cfg_n_tcpl[2];
static const char* cfg_tcpc_serv;
static unsigned    cfg_mcast_sleep = 2;
static unsigned    cfg_timeout;
static const char* cfg_affinity[2];
static int         cfg_n_pings = 1;
static int         cfg_n_pongs = 1;
static int         cfg_nodelay[2];

#define CL1(a, b, c, d)  SFNT_CLA(a, b, &(c), d)
#define CL2(a, b, c, d)  SFNT_CLA2(a, b, &(c), d)
#define CL1F(a, c, d)    CL1(a, FLAG, c, d)
#define CL2F(a, c, d)    CL2(a, FLAG, c, d)
#define CL1I(a, c, d)    CL1(a, INT, c, d)
#define CL2I(a, c, d)    CL2(a, INT, c, d)
#define CL1U(a, c, d)    CL1(a, UINT, c, d)
#define CL2U(a, c, d)    CL2(a, UINT, c, d)
#define CL1S(a, c, d)    CL1(a, STR, c, d)
#define CL2S(a, c, d)    CL2(a, STR, c, d)
#define CL1D(a, c, d)    CL1(a, FLOAT, c, d)
#define CL2D(a, c, d)    CL2(a, FLOAT, c, d)

static struct sfnt_cmd_line_opt cfg_opts[] = {
  CL1U("port",        cfg_port,        "server port#"                        ),
  CL1S("sizes",       cfg_sizes,       "message sizes (list or range)"       ),
  CL2F("connect",     cfg_connect,     "connect() UDP socket"                ),
  CL2F("spin",        cfg_spin,        "receive side should spin"            ),
  CL2S("muxer",       cfg_muxer,       "select, poll, epoll or none"         ),
  CL1F("rtt",         cfg_rtt,         "report round-trip-time"              ),
  CL1S("raw",         cfg_raw,         "dump raw results to files"           ),
  CL1D("percentile",  cfg_percentile,  "percentile"                          ),
  CL1I("minmsg",      cfg_minmsg,      "min message size"                    ),
  CL1I("maxmsg",      cfg_maxmsg,      "max message size"                    ),
  CL1I("minms",       cfg_minms,       "min time per msg size (ms)"          ),
  CL1I("maxms",       cfg_maxms,       "max time per msg size (ms)"          ),
  CL1I("miniter",     cfg_miniter,     "min iterations for result"           ),
  CL1I("maxiter",     cfg_maxiter,     "max iterations for result"           ),
  CL1S("mcast",       cfg_mcast,       "set multicast address"               ),
  CL2S("mcastintf",   cfg_mcast_intf,  "set multicast interface"             ),
  CL2F("mcastloop",   cfg_mcast_loop,  "IP_MULTICAST_LOOP"                   ),
  CL2F("ttl",         cfg_ttl,         "IP_TTL and IP_MULTICAST_TTL"         ),
  CL2S("bind",        cfg_bind,        "bind() socket"                       ),
  CL2S("bindtodev",   cfg_bindtodev,   "SO_BINDTODEVICE"                     ),
  CL1F("forkboth",    cfg_forkboth,    "fork client and server"              ),
  CL2U("n-pipe",      cfg_n_pipe,      "include pipes in fd set"             ),
  CL2U("n-unix-d",    cfg_n_unixd,     "include unix datagrams in fd set"    ),
  CL2U("n-unix-s",    cfg_n_unixs,     "include unix streams in fd set"      ),
  CL2U("n-udp",       cfg_n_udp,       "include UDP socks in fd set"         ),
  CL2U("n-tcpc",      cfg_n_tcpc,      "include TCP socks in fd set"         ),
  CL2U("n-tcpl",      cfg_n_tcpl,      "include TCP listeners in fds"        ),
  CL1S("tcpc-serv",   cfg_tcpc_serv,   "host:port for tcp conns"             ),
  CL1U("timeout",     cfg_timeout,     "socket SND?RECV timeout"             ),
  CL2S("affinity",    cfg_affinity,    "<client-core>;<server-core>"         ),
  CL1U("n-pings",     cfg_n_pings,     "number of ping messages"             ),
  CL1U("n-pongs",     cfg_n_pongs,     "number of pong messages"             ),
  CL2F("nodelay",     cfg_nodelay,     "enable TCP_NODELAY"                  ),
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

static fd_set         select_fdset;
static int            select_fds[MAX_FDS];
static int            select_n_fds;
static int            select_max_fd;

static struct sockaddr_in  my_sa;
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
    if( (rc = read(fd, (char*) buf + got, len - got)) > 0 )
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
  int i, rc, got = 0, all = flags & MSG_WAITALL;
  flags = (flags & ~MSG_WAITALL) | MSG_DONTWAIT;
  do {
    for( i = 0; i < select_n_fds; ++i )
      FD_SET(select_fds[i], &select_fdset);
    rc = sfnt_select(select_max_fd + 1, &select_fdset, NULL, NULL, &tsc,
		     timeout_ms, flags);
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
    rc = sfnt_poll(pfds, pfds_n, timeout_ms, &tsc,
		   cfg_spin[0] ? NT_MUX_SPIN : 0);
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
    rc = sfnt_epoll_wait(epoll_fd, &e, 1, timeout_ms, &tsc, cfg_spin[0]);
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
    rc = sfnt_epoll_wait(epoll_fd, &e, 1, timeout_ms, &tsc, cfg_spin[0]);
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
    rc = sfnt_epoll_wait(epoll_fd, &e, 1, timeout_ms, &tsc, cfg_spin[0]);
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

static void set_ttl(int sock, int ttl)
{
  if( ttl >= 0 ) {
    unsigned char ttl8 = ttl;
    NT_TRY(setsockopt(sock, SOL_IP, IP_MULTICAST_TTL, &ttl8, sizeof(ttl8)));
    ttl8 = ttl8 ? ttl8 : 1;
    NT_TRY(setsockopt(sock, SOL_IP, IP_TTL, &ttl8, sizeof(ttl8)));
  }
}


static void do_init(void)
{
  const char* muxer = cfg_muxer[0];
  unsigned core_i;

  /* Set affinity first to ensure optimal locality. */
  if( strcasecmp(cfg_affinity[0], "any") )
    if( sscanf(cfg_affinity[0], "%u", &core_i) == 1 )
      if( sfnt_cpu_affinity_set(core_i) != 0 ) {
        sfnt_err("ERROR: Failed to set CPU affinity to core %d (%d %s)\n",
                 core_i, errno, strerror(errno));
        sfnt_fail_setup();
      }

  NT_TRY(sfnt_tsc_get_params(&tsc));

  if( fd_type == FDT_UDP && ! cfg_connect[0] ) {
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

  if( muxer == NULL || ! strcmp(muxer, "") || ! strcasecmp(muxer, "none") ) {
    mux_recv = cfg_spin[0] ? spin_recv : do_recv;
    mux_add = noop_add;
  }
  else if( ! strcasecmp(muxer, "select") ) {
    mux_recv = select_recv;
    mux_add = select_add;
    select_init();
  }
#if NT_HAVE_POLL
  else if( ! strcasecmp(muxer, "poll") ) {
    mux_recv = poll_recv;
    mux_add = poll_add;
  }
#endif
#if NT_HAVE_EPOLL
  else if( ! strcasecmp(muxer, "epoll") ) {
    mux_recv = epoll_recv;
    mux_add = epoll_add;
    epoll_init();
  }
  else if( ! strcasecmp(muxer, "epoll_mod") ) {
    mux_recv = epoll_mod_recv;
    mux_add = epoll_add;
    epoll_init();
  }
  else if( ! strcasecmp(muxer, "epoll_adddel") ) {
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
    /* NB. Solaris doesn't block in UDP recv with 0 length buffer. */
    rc = mux_recv(read_fd, ppbuf, sz ? sz : 1, MSG_WAITALL);
    NT_TESTi3(rc, ==, sz);
  }
}


static void do_pong(int read_fd, int write_fd, int sz)
{
  int i, rc;
  for( i = 0; i < cfg_n_pings; ++i ) {
    /* NB. Solaris doesn't block in UDP recv with 0 length buffer. */
    rc = mux_recv(read_fd, ppbuf, sz ? sz : 1, MSG_WAITALL);
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
  for( i = 0; i < cfg_n_pipe[0]; ++i ) {
    int pfd[2];
    NT_TEST(pipe(pfd) == 0);
    mux_add(pfd[0]);
    if( ++i < cfg_n_pipe[0] )
      /* Slightly dodgy that we're selecting on the "write" fd for read.
       * The write fd is never readable, so it does at least work, but I
       * suppose the performance might not be quite the same.  Advantage of
       * doing it this way is we don't waste file descriptors.
       */
      mux_add(pfd[1]);
  }
  for( i = 0; i < cfg_n_unixd[0]; ++i ) {
    int fds[2];
    NT_TEST(socketpair(PF_UNIX, SOCK_DGRAM, 0, fds) == 0);
    mux_add(fds[0]);
    if( ++i < cfg_n_unixd[0] )
      mux_add(fds[1]);
  }
  for( i = 0; i < cfg_n_unixs[0]; ++i ) {
    int fds[2];
    NT_TEST(socketpair(PF_UNIX, SOCK_STREAM, 0, fds) == 0);
    mux_add(fds[0]);
    if( ++i < cfg_n_unixs[0] )
      mux_add(fds[1]);
  }
#endif
  for( i = 0; i < cfg_n_udp[0]; ++i ) {
    NT_TRY2(sock, socket(PF_INET, SOCK_DGRAM, 0));
    mux_add(sock);
  }
  for( i = 0; i < cfg_n_tcpc[0]; ++i ) {
    NT_TRY2(sock, socket(PF_INET, SOCK_STREAM, 0));
    NT_TRY(sfnt_connect(sock, cfg_tcpc_serv, NULL, -1));
    mux_add(sock);
  }
  for( i = 0; i < cfg_n_tcpl[0]; ++i ) {
    NT_TRY2(sock, socket(PF_INET, SOCK_STREAM, 0));
    NT_TRY(listen(sock, 1));
    mux_add(sock);
  }
}


static void client_check_ver(int ss)
{
  char* serv_ver = sfnt_sock_get_str(ss);
  char* serv_csum = sfnt_sock_get_str(ss);
  if( strcmp(serv_ver, SFNT_VERSION) ) {
    sfnt_err("ERROR: Version mismatch: client=%s server=%s\n",
             SFNT_VERSION, serv_ver);
    sfnt_fail_setup();
  }
  if( strcmp(serv_csum, SFNT_SRC_CSUM) ) {
    sfnt_err("ERROR: Source Checksum mismatch:\n");
    sfnt_err("ERROR:     me=%s\n", SFNT_SRC_CSUM);
    sfnt_err("ERROR: server=%s\n", serv_csum);
    sfnt_fail_setup();
  }
}


static void server_check_ver(int ss)
{
  sfnt_sock_put_str(ss, SFNT_VERSION);
  sfnt_sock_put_str(ss, SFNT_SRC_CSUM);
}


static void client_send_opts(int ss)
{
  sfnt_sock_put_int(ss, fd_type);
  sfnt_sock_put_int(ss, cfg_connect[1]);
  sfnt_sock_put_int(ss, cfg_spin[1]);
  sfnt_sock_put_str(ss, cfg_muxer[1]);
  sfnt_sock_put_str(ss, cfg_mcast);
  sfnt_sock_put_str(ss, cfg_mcast_intf[1]);
  sfnt_sock_put_int(ss, cfg_mcast_loop[1]);
  sfnt_sock_put_int(ss, cfg_ttl[1]);
  sfnt_sock_put_str(ss, cfg_bindtodev[1]);
  sfnt_sock_put_str(ss, cfg_bind[1]);
  sfnt_sock_put_int(ss, cfg_n_pipe[1]);
  sfnt_sock_put_int(ss, cfg_n_unixs[1]);
  sfnt_sock_put_int(ss, cfg_n_unixd[1]);
  sfnt_sock_put_int(ss, cfg_n_udp[1]);
  sfnt_sock_put_int(ss, cfg_n_tcpc[1]);
  sfnt_sock_put_int(ss, cfg_n_tcpl[1]);
  sfnt_sock_put_str(ss, cfg_affinity[1]);
  sfnt_sock_put_int(ss, cfg_n_pings);
  sfnt_sock_put_int(ss, cfg_n_pongs);
  sfnt_sock_put_int(ss, cfg_nodelay[1]);
}


static void server_recv_opts(int ss)
{
  fd_type = sfnt_sock_get_int(ss);
  cfg_connect[0] = sfnt_sock_get_int(ss);
  cfg_spin[0] = sfnt_sock_get_int(ss);
  cfg_muxer[0] = sfnt_sock_get_str(ss);
  cfg_mcast = sfnt_sock_get_str(ss);
  cfg_mcast_intf[0] = sfnt_sock_get_str(ss);
  cfg_mcast_loop[0] = sfnt_sock_get_int(ss);
  cfg_ttl[0] = sfnt_sock_get_int(ss);
  cfg_bindtodev[0] = sfnt_sock_get_str(ss);
  cfg_bind[0] = sfnt_sock_get_str(ss);
  cfg_n_pipe[0] = sfnt_sock_get_int(ss);
  cfg_n_unixs[0] = sfnt_sock_get_int(ss);
  cfg_n_unixd[0] = sfnt_sock_get_int(ss);
  cfg_n_udp[0] = sfnt_sock_get_int(ss);
  cfg_n_tcpc[0] = sfnt_sock_get_int(ss);
  cfg_n_tcpl[0] = sfnt_sock_get_int(ss);
  cfg_affinity[0] = sfnt_sock_get_str(ss);
  cfg_n_pings = sfnt_sock_get_int(ss);
  cfg_n_pongs = sfnt_sock_get_int(ss);
  cfg_nodelay[0] = sfnt_sock_get_int(ss);
}


static void udp_bind_sock(int us, int ss)
{
  struct sockaddr_in ss_sa;
  struct sockaddr_in sa;
  unsigned char uc;
  socklen_t sa_len;
  int rc, one = 1;

  set_ttl(us, cfg_ttl[0]);

  sa_len = sizeof(sa);
  NT_TRY(getsockname(ss, (struct sockaddr*) &ss_sa, &sa_len));

  if( cfg_bindtodev[0] )
    NT_TRY(sfnt_so_bindtodevice(us, cfg_bindtodev[0]));

  if( cfg_bind[0] ) {
    NT_TRY(setsockopt(us, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)));
    if( (rc = sfnt_bind(us, cfg_bind[0], NULL, -1)) != 0 ) {
      sfnt_err("ERROR: Could not bind to '%s'\n", cfg_bind[0]);
      sfnt_err("ERROR: rc=%d errno=(%d %s) gai_strerror=(%s)\n",
               rc, errno, strerror(errno), gai_strerror(rc));
      sfnt_fail_setup();
    }
  }
  else if( cfg_mcast ) {
    sa.sin_family = AF_INET;
    sa.sin_port = 0;
    sa.sin_addr.s_addr = inet_addr(cfg_mcast);
    NT_TRY(bind(us, (struct sockaddr*) &sa, sizeof(sa)));
  }
  else {
    /* Bind to same local interface as the setup socket. */
    sa = ss_sa;
    sa.sin_port = 0;
    NT_TRY(bind(us, (struct sockaddr*) &sa, sizeof(sa)));
  }

  sa_len = sizeof(my_sa);
  NT_TRY(getsockname(us, (struct sockaddr*) &my_sa, &sa_len));
  if( my_sa.sin_addr.s_addr == 0 )
    my_sa.sin_addr = ss_sa.sin_addr;

  if( cfg_mcast ) {
    if( cfg_mcast_intf[0] )
      NT_TRY(sfnt_ip_multicast_if(us, cfg_mcast_intf[0]));
    rc = sfnt_ip_add_membership(us, inet_addr(cfg_mcast), cfg_mcast_intf[0]);
    if( rc != 0 ) {
      sfnt_err("ERROR: failed to join '%s' on interface '%s'\n",
               cfg_mcast, cfg_mcast_intf[0]);
      sfnt_err("ERROR: rc=%d errno=(%d %s) gai_strerror=(%s)\n",
               rc, errno, strerror(errno), gai_strerror(rc));
      sfnt_fail_setup();
    }
    /* Solaris requires this to be an unsigned char */
    uc = cfg_mcast_loop[0];
    NT_TRY(setsockopt(us, SOL_IP, IP_MULTICAST_LOOP, &uc, sizeof(uc)));
    my_sa.sin_addr.s_addr = inet_addr(cfg_mcast);
    sleep(cfg_mcast_sleep);
  }
}


static void udp_exchange_addrs(int us, int ss)
{
  /* Tell client our address, and get their's. */

  NT_TEST(send(ss, &my_sa, sizeof(my_sa), 0) == sizeof(my_sa));
  NT_TEST(recv(ss, &peer_sa, sizeof(peer_sa), MSG_WAITALL) == sizeof(peer_sa));

  if( cfg_connect[0] ) {
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
  int one = 1;

  server_check_ver(ss);
  server_recv_opts(ss);
  sfnt_sock_put_str(ss, getenv("LD_PRELOAD"));

  /* Init after we've received config opts from client. */
  do_init();

  /* Create and bind/connect test socket. */
  switch( fd_type ) {
  case FDT_TCP: {
    struct sockaddr_in sa;
    socklen_t sa_len = sizeof(sa);
    NT_TRY2(sl, socket(PF_INET, SOCK_STREAM, 0));
    if( cfg_bindtodev[0] )
      NT_TRY(sfnt_so_bindtodevice(sl, cfg_bindtodev[0]));
    NT_TRY(listen(sl, 1));
    NT_TRY(getsockname(sl, (struct sockaddr*) &sa, &sa_len));
    sfnt_sock_put_int(ss, ntohs(sa.sin_port));
    NT_TRY2(read_fd, accept(sl, NULL, NULL));
    if( cfg_nodelay[0] )
      NT_TRY(setsockopt(read_fd, SOL_TCP, TCP_NODELAY, &one, sizeof(one)));
    write_fd = read_fd;
    close(sl);
    sl = -1;
    break;
  }
  case FDT_UDP:
    NT_TRY2(read_fd, socket(PF_INET, SOCK_DGRAM, 0));
    udp_bind_sock(read_fd, ss);
    udp_exchange_addrs(read_fd, ss);
    write_fd = read_fd;
    break;
  case FDT_PIPE:
    read_fd = the_fds[2];
    write_fd = the_fds[1];
    if( cfg_spin[0] ) {
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

  sfnt_sock_put_int(ss, iter + 1); /* +1 as initial ping  below */
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


static int try_connect(const char* hostport, int default_port)
{
  int max_attempts = 100;
  int ss, rc, n_attempts = 0;
  int one = 1;

  if( strchr(hostport, ':') != NULL )
    default_port = -1;

  while( 1 ) {
    NT_TRY2(ss, socket(PF_INET, SOCK_STREAM, 0));
    NT_TRY(setsockopt(ss, SOL_TCP, TCP_NODELAY, &one, sizeof(one)));
    rc = sfnt_connect(ss, hostport, NULL, default_port);
    if( rc == 0 || ++n_attempts == max_attempts || errno != ECONNREFUSED )
      return rc ? rc : ss;
    /* Something goes bad on Solaris if we try to reconnect with the same
     * socket, so create a new one each time.
     */
    close(ss);
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
    sfnt_fail_usage("wrong number of arguments");
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
    sfnt_fail_usage("unknown fd_type '%s'", fd_type_s);

  if( fd_type & FDTF_LOCAL ) {
    int ss[2];
    if( argc != 1 )
      sfnt_fail_usage("wrong number of arguments for local socket");
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
    int ss, local;
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
    NT_TRY2(ss, try_connect(hostport, cfg_port));
    return do_client2(ss, hostport, local);
  }
}


static int do_client2(int ss, const char* hostport, int local)
{
  struct sfnt_ilist msg_sizes;
  int read_fd, write_fd;
  char* server_ld_preload;
  int msg_size;
  int* results;
  int i, one = 1;

  client_check_ver(ss);

  if( cfg_affinity[0] == NULL ) {
    /* Set affinity by default.  Avoid core 0, which often has various OS
     * junk running on it that causes high jitter.  We'll get an error on
     * singe core boxes -- user will just have to set affinity explicitly.
     */
    cfg_affinity[0] = "1";
    cfg_affinity[1] = "1";
    if( local && cfg_spin[0] )
      /* It is a very bad idea to pin two spinners onto the same core, as
       * they'll just fight each other for timeslices.
       */
      cfg_affinity[1] = "2";
  }
  if( cfg_mcast_intf[0] != NULL && cfg_mcast == NULL )
    cfg_mcast = "224.1.2.48";

  do_init();

  client_send_opts(ss);
  server_ld_preload = sfnt_sock_get_str(ss);

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
    if( cfg_nodelay[0] )
      NT_TRY(setsockopt(read_fd, SOL_TCP, TCP_NODELAY, &one, sizeof(one)));
    NT_TRY(sfnt_connect(read_fd, host, NULL, port));
    write_fd = read_fd;
    break;
  }
  case FDT_UDP:
    NT_TRY2(read_fd, socket(PF_INET, SOCK_DGRAM, 0));
    udp_bind_sock(read_fd, ss);
    udp_exchange_addrs(read_fd, ss);
    write_fd = read_fd;
    break;
  case FDT_PIPE:
    read_fd = the_fds[0];
    write_fd = the_fds[3];
    if( cfg_spin[0] ) {
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
  if( server_ld_preload != NULL )
    printf("# server LD_PRELOAD=%s\n", server_ld_preload);
  printf("# percentile=%g\n", (double) cfg_percentile);
  printf("#\n");
  printf("#\tsize\tmean\tmin\tmedian\tmax\t%%ile\tstddev\titer\n");
  fflush(stdout);

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

  if( cfg_sizes != NULL ) {
    if( sfnt_ilist_parse(&msg_sizes, cfg_sizes) != 0 )
      sfnt_fail_usage("ERROR: Malformed argument to option --sizes");
  }
  else {
    sfnt_ilist_init(&msg_sizes);
    for( msg_size = cfg_minmsg; msg_size <= cfg_maxmsg;
         msg_size = next_msg_size(msg_size) )
      sfnt_ilist_append(&msg_sizes, msg_size);
  }

  for( i = 0; i < msg_sizes.len; ++i )
    do_test(ss, read_fd, write_fd, msg_sizes.list[i], results);

  /* Tell server side to exit. */
  sfnt_sock_put_int(ss, 0);

  return 0;
}


int main(int argc, char* argv[])
{
  pid_t pid = 0;
  int rc = 0;

  sfnt_app_getopt("[tcp|udp|pipe|unix_stream|unix_datagram [host[:port]]]",
                &argc, argv, cfg_opts, N_CFG_OPTS);
  --argc; ++argv;

  if( cfg_miniter > cfg_maxiter )
    cfg_maxiter = cfg_miniter;
  if( cfg_minms > cfg_maxms )
    cfg_maxms = cfg_minms;
  NT_ASSERT(cfg_maxiter >= cfg_miniter);
  timeout_ms = cfg_timeout ? cfg_timeout * 1000 : -1;

#if defined(__unix__) ||  defined(__APPLE__)
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

#if defined(__unix__) ||  defined(__APPLE__)
  if( pid ) {
    int status;
    kill(pid, SIGINT);
    waitpid(pid, &status ,0);
  }
#endif

  return rc;
}

/*! \cidoxg_end */
