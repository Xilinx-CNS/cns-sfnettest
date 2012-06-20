/**************************************************************************\
*    Filename: sfnt-stream.c
*      Author: David Riddoch <driddoch@solarflare.com>
* Description: Application to measure latency while streaming.
*  Start date: 2011/06/17
*   Copyright: (C) 2011-2012 Solarflare Communications Inc.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License version 2 as published
* by the Free Software Foundation, incorporated herein by reference.
\**************************************************************************/

#include "sfnettest.h"

/* TODO:
 *  other fd types
 *  measure how long send call takes
 */

#define DEFAULT_MSG_SIZE  24

static int         cfg_msg_size = DEFAULT_MSG_SIZE;
static const char* cfg_rates = "50000-100000000+50000";
static int         cfg_millisec = 2000;
static int         cfg_samples;
static int         cfg_stop = 90;
static int         cfg_max_burst = 100;
static int         cfg_port = 2049;
static int         cfg_connect[2];
static int         cfg_spin[2];
static const char* cfg_muxer[2];
static int         cfg_rtt;
static const char* cfg_raw;
static float       cfg_percentile = 99;
static const char* cfg_mcast;
static const char* cfg_mcast_intf[2];
static int         cfg_mcast_loop;
static int         cfg_ttl[2] = { 1, 1 };
static const char* cfg_bindtodev[2];
static unsigned    cfg_n_pipe[2];
static unsigned    cfg_n_unixd[2];
static unsigned    cfg_n_unixs[2];
static unsigned    cfg_n_udp[2];
static unsigned    cfg_n_tcpc[2];
static unsigned    cfg_n_tcpl[2];
static const char* cfg_tcpc_serv;
static const char* cfg_affinity[2];
static int         cfg_nodelay;
static unsigned    cfg_rtt_iter = 10000;

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
  CL1U("msgsize",     cfg_msg_size,    "message size (bytes)"                ),
  CL1S("rates",       cfg_rates,       "set msg rates <min>-<max>+<step>"    ),
  CL1U("millisec",    cfg_millisec,    "time per test (millisec)"            ),
  CL1U("samples",     cfg_samples,     "samples per test"                    ),
  CL1U("stop",        cfg_stop,        "stop when TX rate achieved is below"
                                       " given percentage of target"         ),
  CL1U("maxburst",    cfg_max_burst,   "max burst length"                    ),
  CL1U("port",        cfg_port,        "server port#"                        ),
  CL2F("connect",     cfg_connect,     "connect() UDP socket"                ),
  CL2F("spin",        cfg_spin,        "spin on non-blocking recv()"         ),
  CL2S("muxer",       cfg_muxer,       "select, poll, epoll or none"         ),
  CL1F("rtt",         cfg_rtt,         "report round-trip-time"              ),
  CL1S("raw",         cfg_raw,         "dump raw results to files"           ),
  CL1D("percentile",  cfg_percentile,  "percentile"                          ),
  CL1S("mcast",       cfg_mcast,       "set multicast address"               ),
  CL2S("mcastintf",   cfg_mcast_intf,  "set multicast interface"             ),
  CL1F("mcastloop",   cfg_mcast_loop,  "IP_MULTICAST_LOOP"                   ),
  CL2F("ttl",         cfg_ttl,         "IP_TTL and IP_MULTICAST_TTL"         ),
  CL2S("bindtodev",   cfg_bindtodev,   "SO_BINDTODEVICE"                     ),
  CL2U("n-pipe",      cfg_n_pipe,      "include pipes in fd set"             ),
  CL2U("n-unix-d",    cfg_n_unixd,     "include unix dgram in fd set"        ),
  CL2U("n-unix-s",    cfg_n_unixs,     "include unix strm in fd set"         ),
  CL2U("n-udp",       cfg_n_udp,       "include UDP socks in fd set"         ),
  CL2U("n-tcpc",      cfg_n_tcpc,      "include TCP socks in fd set"         ),
  CL2U("n-tcpl",      cfg_n_tcpl,      "include TCP listeners in fds"        ),
  CL1S("tcpc-serv",   cfg_tcpc_serv,   "host:port for tcp conns"             ),
  CL2S("affinity",    cfg_affinity,    "<client-tx>,<client-rx>;<server>"    ),
  CL1F("nodelay",     cfg_nodelay,     "enable TCP_NODELAY"                  ),
  CL1U("rtt-iter",    cfg_rtt_iter,    "iterations for RTT measurement"      ),
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


struct gap_stats {
  uint64_t  n_msgs_dropped;
  uint32_t  n_gaps;
  uint32_t  n_ooo;
};


enum msg_flags {
  MF_TIMESTAMP = 0x01,      /* server should add timestamp */
  MF_RESET     = 0x02,      /* server should reset seq and stats */
  MF_SAVE      = 0x04,      /* client rx thread should save result */
  MF_SYNC      = 0x08,      /* client rx thread should ding cond var */
  MF_STOP      = 0x10,      /* client rx thread should stop */
};


struct msg {
  uint64_t  timestamp;
  uint32_t  seq;
  uint32_t  send_lateness;
  uint8_t   flags;
  uint8_t   reply_seq;
};


struct msg_reply {
  /* Fields reflected from [struct msg]. */
  uint64_t  c_timestamp;
  uint32_t  seq;
  uint32_t  send_lateness;
  uint8_t   flags;
  uint8_t   reply_seq;
  /* Fields unique to reply. */
  uint16_t  unused1;
  uint64_t  s_timestamp;
  struct gap_stats gap_stats;
};


enum client_rx_cmd {
  CRXC_NEW,
  CRXC_WAIT,
  CRXC_GO,
  CRXC_EXIT
};


struct client_rx_rec {
  uint64_t  ts_send;
  uint64_t  ts_recv;
  uint32_t  seq;
  uint32_t  send_lateness;
};


struct client_rx {
  pthread_mutex_t       lock;
  pthread_cond_t        cond;
  enum client_rx_cmd    cmd;
  enum client_rx_cmd    state;
  struct msg_reply*     reply;
  int                   reply_buf_len;
  int                   sock;
  int                   port;
  volatile int          n_rx;
  struct client_rx_rec* recs;
  int                   recs_max;
  int                   recs_n;
  uint32_t              sync_seq;
};


struct client_tx {
  int                   ss;
  struct client_rx*     crx;
  struct sfnt_ilist     rates;
  struct msg*           msg;
  int                   msg_len;
  uint32_t              next_seq;
  int                   write_fd;
  int                   read_fd;
  int                   msg_per_sec_target;
  int                   msg_per_sec_tx;
  int                   msg_per_sec_rx;
  int                   reply_every;
  uint64_t              ts_start;
  uint32_t              start_seq;
  uint32_t              end_seq;
  struct stats          ret_lat_stats;
  int                   n_fall_behinds;
  char*                 server_ld_preload;
};


struct server_per_client {
  struct addrinfo* addrinfo;
  uint32_t  seq_expected;
  uint8_t   reply_seq;
  struct gap_stats gap_stats;
};


struct server {
  int       ss;
  int       read_fd;
  int       write_fd;
  int       n_clients;
  struct server_per_client clients[1];
  int       recv_size;
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


/* Test that pthread call succeeded. */
#define PT_CHK(cmd)  NT_TESTi3(cmd, ==, 0)


#define MAX_FDS            1024

static struct sfnt_tsc_params tsc;
static char           ppbuf[64 * 1024];

static int            client_rx_core_i;

static enum fd_type   fd_type;
static int            the_fds[4];  /* used for pipes and unix sockets */

static fd_set         select_fdset;
static int            select_fds[MAX_FDS];
static int            select_n_fds;
static int            select_max_fd;

static struct sockaddr*    to_sa;
static socklen_t           to_sa_len;

static int                 timeout_ms = 100;

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
  NT_ASSERT(cfg_spin[0] == 0);  /* spin not yet supported with select */
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
    if( rc == 1 ) {
      NT_TEST(pfds[0].revents & POLLIN);
      if( (rc = do_recv(fd, (char*) buf + got, len - got, flags)) > 0 )
        got += rc;
    }
    else {
      if( rc == 0 && got == 0 ) {
        errno = EAGAIN;
        rc = -1;
      }
      break;
    }
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
    if( rc == 1 ) {
      NT_TEST(e.events & EPOLLIN);
      if( (rc = do_recv(fd, (char*) buf + got, len - got, flags)) > 0 )
        got += rc;
    }
    else {
      if( rc == 0 && got == 0 ) {
        errno = EAGAIN;
        rc = -1;
      }
      break;
    }
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
    if( rc == 1 ) {
      NT_TEST(e.events & EPOLLIN);
      if( (rc = do_recv(fd, (char*) buf + got, len - got, flags)) > 0 )
        got += rc;
    }
    else {
      if( rc == 0 && got == 0 ) {
        errno = EAGAIN;
        rc = -1;
      }
      break;
    }
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
    if( rc == 1 ) {
      NT_TEST(e.events & EPOLLIN);
      if( (rc = do_recv(fd, (char*) buf + got, len - got, flags)) > 0 )
        got += rc;
    }
    else {
      if( rc == 0 && got == 0 ) {
        errno = EAGAIN;
        rc = -1;
      }
      break;
    }
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
  uint64_t tsc_now, tsc_timeout;

  flags = (flags & ~MSG_WAITALL) | MSG_DONTWAIT;

  sfnt_tsc(&tsc_timeout);
  tsc_timeout += sfnt_msec_tsc(&tsc, timeout_ms);

  do {
    while( (rc = do_recv(fd, (char*) buf + got, len - got, flags)) < 0 )
      if( errno != EAGAIN ) {
        goto out;
      }
      else {
	sfnt_tsc(&tsc_now);
	if( timeout_ms && tsc_now >= tsc_timeout ){
	  errno = EAGAIN;
	  rc = -1;
	  break;
	}
      }
    got += rc;
  } while( all && got < len && rc > 0 );
 out:
  return got ? got : rc;
}

/**********************************************************************/

static void cpu_affinity_set(int core_i)
{
  if( sfnt_cpu_affinity_set(core_i) != 0 ) {
    sfnt_err("ERROR: Failed to set CPU affinity to core %d (%d %s)\n",
             core_i, errno, strerror(errno));
    sfnt_fail_test();
  }
}


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
    sfnt_fail_test();
  }
  if( strcmp(serv_csum, SFNT_SRC_CSUM) ) {
    sfnt_err("ERROR: Source Checksum mismatch:\n");
    sfnt_err("ERROR:     me=%s\n", SFNT_SRC_CSUM);
    sfnt_err("ERROR: server=%s\n", serv_csum);
    sfnt_fail_test();
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
  sfnt_sock_put_int(ss, cfg_ttl[1]);
  sfnt_sock_put_str(ss, cfg_bindtodev[1]);
  sfnt_sock_put_int(ss, cfg_n_pipe[1]);
  sfnt_sock_put_int(ss, cfg_n_unixs[1]);
  sfnt_sock_put_int(ss, cfg_n_unixd[1]);
  sfnt_sock_put_int(ss, cfg_n_udp[1]);
  sfnt_sock_put_int(ss, cfg_n_tcpc[1]);
  sfnt_sock_put_int(ss, cfg_n_tcpl[1]);
  sfnt_sock_put_str(ss, cfg_affinity[1]);
  sfnt_sock_put_int(ss, cfg_nodelay);
}


static void server_recv_opts(int ss)
{
  fd_type = sfnt_sock_get_int(ss);
  cfg_connect[0] = sfnt_sock_get_int(ss);
  cfg_spin[0] = sfnt_sock_get_int(ss);
  cfg_muxer[0] = sfnt_sock_get_str(ss);
  cfg_mcast = sfnt_sock_get_str(ss);
  cfg_mcast_intf[0] = sfnt_sock_get_str(ss);
  cfg_ttl[0] = sfnt_sock_get_int(ss);
  cfg_bindtodev[0] = sfnt_sock_get_str(ss);
  cfg_n_pipe[0] = sfnt_sock_get_int(ss);
  cfg_n_unixs[0] = sfnt_sock_get_int(ss);
  cfg_n_unixd[0] = sfnt_sock_get_int(ss);
  cfg_n_udp[0] = sfnt_sock_get_int(ss);
  cfg_n_tcpc[0] = sfnt_sock_get_int(ss);
  cfg_n_tcpl[0] = sfnt_sock_get_int(ss);
  cfg_affinity[0] = sfnt_sock_get_str(ss);
  cfg_nodelay = sfnt_sock_get_int(ss);
}


static int do_server2(int ss);
static int do_server3(struct server* server);


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
  struct server_per_client* client;
  struct server server;
  int rc, i, sock;

  server_check_ver(ss);
  server_recv_opts(ss);
  sfnt_sock_put_str(ss, getenv("LD_PRELOAD"));

  if( strcasecmp(cfg_affinity[0], "any") ) {
    int core_i;
    if( sscanf(cfg_affinity[0], "%u", &core_i) != 1 )
      sfnt_fail_usage("ERROR: bad argument for --affinity");
    cpu_affinity_set(core_i);
  }

  /* No support for other fd_types yet. */
  NT_TESTi3(fd_type, ==, FDT_UDP);
  /* Init after we've received config opts from client. */
  do_init();

  NT_TRY2(sock, socket(PF_INET, SOCK_DGRAM, 0));
  set_ttl(sock, cfg_ttl[0]);
  if( cfg_bindtodev[0] )
    NT_TRY(sfnt_so_bindtodevice(sock, cfg_bindtodev[0]));
  if( cfg_mcast ) {
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    if( 1 )  /* allows us to support mcast or unicast receive */
      sin.sin_addr.s_addr = htonl(INADDR_ANY);
    else
      sin.sin_addr.s_addr = inet_addr(cfg_mcast);
    NT_TRY(bind(sock, (const struct sockaddr*) &sin, sizeof(sin)));
    rc = sfnt_ip_add_membership(sock, inet_addr(cfg_mcast), cfg_mcast_intf[0]);
    if( rc != 0 ) {
      sfnt_err("ERROR: failed to join '%s' on interface '%s'\n",
               cfg_mcast, cfg_mcast_intf[0]);
      sfnt_err("ERROR: rc=%d errno=(%d %s) gai_strerror=(%s)\n",
               rc, errno, strerror(errno), gai_strerror(rc));
      sfnt_fail_setup();
    }
  }
  else {
    NT_TRY(sfnt_bind_port(sock, 0));
  }
  add_fds(sock);
  NT_TRY(sfnt_sock_set_timeout(sock, SO_RCVTIMEO, timeout_ms));
  sfnt_sock_put_int(ss, sfnt_get_port(sock));

  server.ss = ss;
  server.read_fd = sock;
  server.write_fd = sock;
  server.n_clients = 1;
  server.recv_size = sizeof(ppbuf);
  /* TODO: for streaming fd_types we need to set recv_size to the size of
     the message */

  for( i = 0; i < server.n_clients; ++i ) {
    char* hostport;
    client = &server.clients[i];
    memset(client, 0, sizeof(*client));
    hostport = sfnt_sock_get_str(ss);
    if( ! sfnt_quiet )
      sfnt_err("sfnt-stream: server: client %d at %s\n", i, hostport);
    NT_TEST(sfnt_getaddrinfo(hostport, NULL, -1, &client->addrinfo) == 0);
    free(hostport);
  }

  return do_server3(&server);
}

/* return 0 if server->recv_size was set */
static int get_recv_size(struct server* server)
{
  int32_t v32;
  int rc;

  rc = recv(server->ss, &v32, sizeof(v32), MSG_DONTWAIT);
  if( rc == -1 && errno == EAGAIN ) {
    /* Nothing here -- keep going. */
  }
  else if( rc == sizeof(v32) ) {
    server->recv_size = NT_LE32(v32);
    sfnt_sock_put_int(server->ss, 0);
  }
  else if( rc == 0 ) {
    return 1;
  }
  else {
    sfnt_err("sfnt-stream: server: error on control socket "
	     "(rc=%d errno=%d %s)\n", rc, errno, strerror(errno));
    exit(1);
  }
  return 0;
}


static int do_server3(struct server* server)
{
  struct msg* msg = (struct msg*) ppbuf;
  struct msg_reply* reply = (struct msg_reply*) ppbuf;
  struct server_per_client* client;
  int flags = 0;
  int rc;

  if( fd_type & FDTF_STREAM )
    flags |= MSG_WAITALL;

  (void) get_recv_size(server);

  while( 1 ) {
    rc = mux_recv(server->read_fd, msg, server->recv_size, flags);

    if( rc > 0 ) {
      client = &server->clients[0];
      if( ! (msg->flags & MF_RESET) ) {
        if( msg->seq == client->seq_expected ) {
          ++client->seq_expected;
        }
        else if( sfnt_int32_lt(msg->seq, client->seq_expected) ) {
          ++client->gap_stats.n_ooo;
        }
        else {
          client->gap_stats.n_msgs_dropped += msg->seq - client->seq_expected;
          client->seq_expected = msg->seq + 1;
          ++client->gap_stats.n_gaps;
        }
      }
      else {
        client->seq_expected = msg->seq + 1;
        memset(&client->gap_stats, 0, sizeof(client->gap_stats));
      }
      if( msg->reply_seq != client->reply_seq ) {
        client->reply_seq = msg->reply_seq;
        if( msg->flags & MF_TIMESTAMP )
          sfnt_tsc(&reply->s_timestamp);
        reply->gap_stats = client->gap_stats;
        rc = sendto(server->write_fd, reply, sizeof(*reply), 0,
                    client->addrinfo->ai_addr, client->addrinfo->ai_addrlen);
        NT_TESTi3(rc, ==, sizeof(*reply));
      }
    }
    else if( rc == -1 && errno == EAGAIN ) {
      if (get_recv_size(server))
	break;
    }
  }

  return 0;
}


static void client_rx_cmd_set(struct client_rx* crx,
                              enum client_rx_cmd cmd)
{
  PT_CHK(pthread_mutex_lock(&crx->lock));
  crx->cmd = cmd;
  PT_CHK(pthread_mutex_unlock(&crx->lock));
  PT_CHK(pthread_cond_signal(&crx->cond));
}


static void client_rx_state_wait_change(struct client_rx* crx,
                                        enum client_rx_cmd cmd)
{
  /* Wait until state changes from [cmd]. */
  PT_CHK(pthread_mutex_lock(&crx->lock));
  while( crx->state == cmd )
    PT_CHK(pthread_cond_wait(&crx->cond, &crx->lock));
  PT_CHK(pthread_mutex_unlock(&crx->lock));
}


static int client_rx_wait_sync(struct client_rx* crx, uint32_t seq,
                               int timeout_millisec)
{
  /* Wait [timeout_millisec] for message with given [seq] to be received.
   * Returns 0 on success, or ETIMEDOUT on timeout.
   */
  struct timespec ts;
  int rc = 0;

#ifdef __APPLE__
  clock_serv_t cs;
  mach_timespec_t mts;
  kern_return_t kr;
  NT_TRY3(kr, KERN_SUCCESS,
	  host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cs));
  NT_TRY3(kr, KERN_SUCCESS, clock_get_time(cs, &mts));
  NT_TRY3(kr, KERN_SUCCESS, mach_port_deallocate(mach_task_self(), cs));
  ts.tv_sec = mts.tv_sec;
  ts.tv_nsec = mts.tv_nsec;
#else
  NT_TRY(clock_gettime(CLOCK_REALTIME, &ts));
#endif
  ts.tv_nsec += timeout_millisec * 1000000;
  if( ts.tv_nsec > 1000000000 ) {
    ts.tv_nsec -= 1000000000;
    ts.tv_sec += 1;
  }
  PT_CHK(pthread_mutex_lock(&crx->lock));
  while( crx->sync_seq != seq ) {
    rc = pthread_cond_timedwait(&crx->cond, &crx->lock, &ts);
    if( rc == ETIMEDOUT )
      break;
    PT_CHK(rc);
  }
  PT_CHK(pthread_mutex_unlock(&crx->lock));
  return rc;
}


static void client_rx_go(struct client_rx* crx)
{
  struct client_rx_rec* rec;
  uint64_t now;
  int flags = 0;
  int rc;

  if( fd_type & FDTF_STREAM )
    flags |= MSG_WAITALL;

  memset(crx->recs, 0, crx->recs_max * sizeof(crx->recs[0]));
  crx->recs_n = 0;

  while( 1 ) {
    rc = mux_recv(crx->sock, crx->reply, crx->reply_buf_len, flags);
    sfnt_tsc(&now);
    if( rc >= sizeof(struct msg_reply) ) {
      if( crx->reply->flags & MF_SAVE ) {
        NT_TESTi3(crx->recs_n, <, crx->recs_max);
        rec = &crx->recs[crx->recs_n];
        rec->ts_send = crx->reply->c_timestamp;
        rec->ts_recv = now;
        rec->seq = crx->reply->seq;
        rec->send_lateness = crx->reply->send_lateness;
        ++crx->recs_n;
      }
      if( crx->reply->flags & MF_SYNC ) {
        PT_CHK(pthread_mutex_lock(&crx->lock));
        crx->sync_seq = NT_LE32(crx->reply->seq);
        PT_CHK(pthread_mutex_unlock(&crx->lock));
        PT_CHK(pthread_cond_signal(&crx->cond));
      }
      if( crx->reply->flags & MF_STOP )
        break;
    }
    else {
      sfnt_err("ERROR: short read or error receiving\n");
      sfnt_err("ERROR: rc=%d errno=(%d %s)\n", rc, errno, strerror(errno));
      sfnt_fail_test();
    }
  }
}


static void* client_rx_thread(void* arg)
{
  struct client_rx* crx = arg;
  struct sockaddr_in sin;

  /* Set affinity first to ensure optimal locality. */
  if( strcasecmp(cfg_affinity[0], "any") )
    cpu_affinity_set(client_rx_core_i);
  crx->reply_buf_len = 64 * 1024;
  crx->reply = malloc(crx->reply_buf_len);
  switch( fd_type ) {
  case FDT_UDP:
    NT_TRY2(crx->sock, socket(PF_INET, SOCK_DGRAM, 0));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = 0;
    NT_TRY(bind(crx->sock, (const struct sockaddr*) &sin, sizeof(sin)));
    crx->recs = malloc(crx->recs_max * sizeof(crx->recs[0]));
    memset(crx->recs, 0, crx->recs_max * sizeof(crx->recs[0]));
    crx->recs_n = 0;
    crx->port = sfnt_get_port(crx->sock);
    add_fds(crx->sock);
    break;
  default:
    NT_ASSERT(0); /* ?? todo */
    break;
  }

  PT_CHK(pthread_mutex_lock(&crx->lock));
  while( crx->state != CRXC_EXIT ) {
    if( crx->state != crx->cmd ) {
      crx->state = crx->cmd;
      PT_CHK(pthread_cond_signal(&crx->cond));
    }
    switch( crx->state ) {
    case CRXC_WAIT:
      PT_CHK(pthread_cond_wait(&crx->cond, &crx->lock));
      break;
    case CRXC_GO:
      PT_CHK(pthread_mutex_unlock(&crx->lock));
      client_rx_go(crx);
      PT_CHK(pthread_mutex_lock(&crx->lock));
      crx->state = CRXC_WAIT;
      PT_CHK(pthread_cond_signal(&crx->cond));
      break;
    case CRXC_EXIT:
      break;
    default:
      NT_ASSERT(0);
      break;
    }
  }
  PT_CHK(pthread_mutex_unlock(&crx->lock));
  return NULL;
}


static struct client_rx* client_rx_thread_start(void)
{
  struct client_rx* crx;
  pthread_t tid;

  crx = malloc(sizeof(*crx));
  PT_CHK(pthread_mutex_init(&crx->lock, NULL));
  PT_CHK(pthread_cond_init(&crx->cond, NULL));
  crx->recs_max = cfg_samples * 3;
  if( crx->recs_max < cfg_rtt_iter )
    crx->recs_max = cfg_rtt_iter;
  crx->state = CRXC_NEW;
  crx->cmd = CRXC_WAIT;
  PT_CHK(pthread_create(&tid, NULL, client_rx_thread, crx));
  client_rx_state_wait_change(crx, CRXC_NEW);
  NT_TESTi3(crx->state, ==, CRXC_WAIT);
  return crx;
}


static void client_send_sync(struct client_tx* ctx, enum msg_flags flags)
{
  struct msg* msg = ctx->msg;
  uint32_t seq;
  int rc;

  msg->flags = MF_SYNC | flags;
  ++msg->reply_seq;
  seq = ctx->next_seq++;
  msg->seq = NT_LE32(seq);
  rc = send(ctx->write_fd, msg, ctx->msg_len, 0);
  NT_TESTi3(rc, ==, ctx->msg_len);
}


static int client_sync(struct client_tx* ctx, enum msg_flags flags,
                       int timeout_millisec)
{
  /* Send message and wait for reflected reply.  Return 0 on success or
   * ETIMEDOUT.
   */
  struct client_rx* crx = ctx->crx;
  uint32_t seq = ctx->next_seq;

  crx->sync_seq = seq - 1;
  client_send_sync(ctx, flags);
  return client_rx_wait_sync(crx, seq, timeout_millisec);
}


static void client_warmup(struct client_tx* ctx, int n_warmups)
{
  int i;
  for( i = 0; i < n_warmups; ++i )
    if( client_sync(ctx, MF_RESET, 1000) != 0 ) {
      sfnt_err("ERROR: Timeout waiting for synchronisation message\n");
      sfnt_fail_test();
    }
}


static void client_start(struct client_tx* ctx, int warmup_n, int msg_len)
{
  NT_TESTi3(ctx->crx->cmd, ==, CRXC_WAIT);
  client_rx_cmd_set(ctx->crx, CRXC_GO);
  ctx->msg_len = msg_len;
  ctx->next_seq = 0;
  client_warmup(ctx, warmup_n);
}


static void client_stop(struct client_tx* ctx)
{
  /* We're done.  We need to wait for everything to finish and tell client
   * rx thread to stop so we can gather results.
   */
  int i;
  client_rx_cmd_set(ctx->crx, CRXC_WAIT);
  for( i = 0; i < 10; ++i )
    if( client_sync(ctx, MF_STOP, 100) == 0 )
      break;
  if( i == 10 ) {
    sfnt_err("ERROR: Sync messages at end of test lost\n");
    sfnt_fail_test();
  }
  client_rx_state_wait_change(ctx->crx, CRXC_GO);
  NT_TESTi3(ctx->crx->state, ==, CRXC_WAIT);
}


int64_t rec_latency_ns(struct client_tx* ctx, struct client_rx_rec* r)
{
  int64_t latency = sfnt_tsc_nsec(&tsc, r->ts_recv - r->ts_send);
  if( ! cfg_rtt )
    latency -= ctx->ret_lat_stats.mean;
  return latency;
}


uint64_t rec_target_send_ts(struct client_tx* ctx, struct client_rx_rec* r)
{
  return r->ts_send - r->send_lateness;
}


static double ts_to_dbl(struct client_tx* ctx, uint64_t ts)
{
  return 1e-9 * sfnt_tsc_nsec(&tsc, ts - ctx->ts_start);
}


static void write_raw_results(struct client_tx* ctx)
{
  char fname[strlen(cfg_raw) + 60];
  FILE* f;
  int i;

  sprintf(fname, "%s-%d-%d.dat",
          cfg_raw, ctx->msg_len, ctx->msg_per_sec_target);
  if( (f = fopen(fname, "w")) == NULL ) {
    sfnt_err("ERROR: Could not open output file '%s'\n", fname);
    sfnt_fail_test();
  }
  fprintf(f, "#send-target(ns)\tsend-actual(ns)\tlatency(ns)\n");
  for( i = 0; i < ctx->crx->recs_n; ++i ) {
    struct client_rx_rec* r = &ctx->crx->recs[i];
    fprintf(f, "%.9f\t%.9f\t%.9f\n",
            ts_to_dbl(ctx, rec_target_send_ts(ctx, r)),
            ts_to_dbl(ctx, r->ts_send),
            1e-9 * rec_latency_ns(ctx, r));
  }
  fclose(f);
}


static void get_stats(struct stats* s, int* results, int results_n)
{
  int* results_end = results + results_n;
  int64_t variance;

  qsort(results, results_n, sizeof(int), &sfnt_qsort_compare_int);
  sfnt_iarray_mean_and_limits(results, results_end, &s->mean, &s->min,
                              &s->max);

  s->median = results[results_n >> 1u];
  s->percentile = results[(int) (results_n * cfg_percentile / 100)];
  sfnt_iarray_variance(results, results_end, s->mean, &variance);
  s->stddev = (int) sqrt((double) variance);
}


static void stats_divide(struct stats* s, int divisor)
{
  s->mean /= divisor;
  s->min /= divisor;
  s->median /= divisor;
  s->max /= divisor;
  s->percentile /= divisor;
}


static void write_result_line(struct client_tx* ctx)
{
  struct client_rx* crx = ctx->crx;
  int send_jit[ctx->crx->recs_n];
  int lat[ctx->crx->recs_n];
  struct stats l, j;
  int i;

  for( i = 0; i < crx->recs_n; ++i ) {
    struct client_rx_rec* r = &crx->recs[i];
    lat[i] = rec_latency_ns(ctx, r);
    send_jit[i] = sfnt_tsc_nsec(&tsc, r->send_lateness);
  }
  get_stats(&l, lat, crx->recs_n);
  get_stats(&j, send_jit, crx->recs_n);
  printf(/*mps*/"%d\t%d\t%d\t"
         /*latency*/"%d\t%d\t%d\t%d\t%d\t%d\t%d\t"
         /*sendjit*/"%d\t%d\t%d\t%d\t"
         /*gaps*/"%d\t%"PRIu64"\t%d\n",
         ctx->msg_per_sec_target, ctx->msg_per_sec_tx, ctx->msg_per_sec_rx,
         l.mean, l.min, l.median, l.max, l.percentile, l.stddev, crx->recs_n,
         j.mean, j.min, j.max, ctx->n_fall_behinds,
         crx->reply->gap_stats.n_gaps, crx->reply->gap_stats.n_msgs_dropped,
           crx->reply->gap_stats.n_ooo);
  fflush(stdout);
}


static void client_do_test(struct client_tx* ctx)
{
  struct msg* msg = ctx->msg;
  int msgs_since_reply = 0;
  uint64_t ts_start, ts_end, ts_next_send;
  uint64_t ticks_per_msg, ts_last_send;
  uint64_t max_fall_behind;
  uint32_t seq;
  int rc;

  /* Start-up the client RX thread and warmup. */
  client_start(ctx, 100/*??*/, cfg_msg_size);

  /* Get ready. */
  ctx->reply_every = (int) ((uint64_t) ctx->msg_per_sec_target * cfg_millisec
                            / 1000 / cfg_samples);
  if( ctx->reply_every < 1 )
    ctx->reply_every = 1;
  ticks_per_msg = tsc.hz / ctx->msg_per_sec_target;
  ctx->start_seq = ctx->next_seq;
  /* If this thread loses the CPU for a while, it will get behind, and then
   * race to catch-up.  This could overwhelm the receiver, causing drops.
   * That isn't really an accurate reflection of the receiver's
   * performance, so we seek to prevent this from happening...
   */
  max_fall_behind = cfg_max_burst * ticks_per_msg;
  ctx->n_fall_behinds = 0;

  /* Do the experiment. */
  sfnt_tsc(&ts_start);
  ts_last_send = ts_start;
  ts_next_send = ts_last_send + ticks_per_msg;
  ctx->ts_start = ts_next_send;
  ts_end = ts_start + tsc.hz / 1000 * cfg_millisec;
  msg->timestamp = ts_start;
  msg->flags = MF_SAVE;
  while( msg->timestamp < ts_end ) {
    seq = ctx->next_seq++;
    msg->seq = NT_LE32(seq);
    if( ++msgs_since_reply == ctx->reply_every ) {
      ++msg->reply_seq;
      msgs_since_reply = 0;
    }
    while( msg->timestamp < ts_next_send )
      sfnt_tsc(&msg->timestamp);
    if( msg->timestamp > ts_next_send + max_fall_behind &&
        msg->send_lateness < max_fall_behind / 5 ) {
      /* The intent here is to only count the times that sender has hit a
       * significant delay, as opposed to gradually falling behind.
       */
      ts_next_send = msg->timestamp;
      ++ctx->n_fall_behinds;
    }
    msg->send_lateness = msg->timestamp - ts_next_send;
    rc = send(ctx->write_fd, msg, ctx->msg_len, 0);
    NT_TESTi3(rc, ==, ctx->msg_len);
    ts_last_send = msg->timestamp;
    ts_next_send += ticks_per_msg;
  }

  ctx->end_seq = ctx->next_seq;

  client_stop(ctx);

  { /* Calculate achieved TX and RX rate. */
    uint64_t n_tx_msgs = ctx->end_seq - ctx->start_seq;
    uint64_t n_rx_msgs = n_tx_msgs - ctx->crx->reply->gap_stats.n_msgs_dropped;
    ctx->msg_per_sec_tx = (int) (n_tx_msgs * 1000 / cfg_millisec);
    ctx->msg_per_sec_rx = (int) (n_rx_msgs * 1000 / cfg_millisec);
  }
}


static void client_measure_rtt(struct client_tx* ctx, struct stats* stats)
{
  /* Measure round-trip time using ping-pongs. */

  struct client_rx* crx = ctx->crx;
  struct msg* msg = ctx->msg;
  uint32_t seq;
  int msg_len;
  int i, rc;

  /* We want symmetric ping-pongs, so that RTT/2 reflects the return path
   * latency.  Therefore use the reply size for forward send too.
   */
  msg_len = sizeof(struct msg_reply);
  sfnt_sock_put_int(ctx->ss, msg_len);
  sfnt_sock_get_int(ctx->ss);

  /* Start-up the client RX thread and warmup. */
  client_start(ctx, cfg_rtt_iter, msg_len);

  crx->sync_seq = ctx->next_seq - 1;
  msg->flags = MF_SAVE | MF_RESET | MF_SYNC;
  for( i = 0; i < cfg_rtt_iter; ++i ) {
    seq = ctx->next_seq++;
    msg->seq = NT_LE32(seq);
    ++msg->reply_seq;
    sfnt_tsc(&msg->timestamp);
    rc = send(ctx->write_fd, msg, msg_len, 0);
    NT_TESTi3(rc, ==, msg_len);
    rc = client_rx_wait_sync(crx, seq, 1000);
  }

  {
    struct client_rx_rec* r;
    int rtt[crx->recs_n];
    for( i = 0; i < crx->recs_n; ++i ) {
      r = &crx->recs[i];
      rtt[i] = sfnt_tsc_nsec(&tsc, r->ts_recv - r->ts_send);
    }
    get_stats(stats, rtt, crx->recs_n);
  }

  client_stop(ctx);
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


static int tx_is_not_keeping_up(struct client_tx* ctx)
{
  return ctx->msg_per_sec_tx * 100 / ctx->msg_per_sec_target < cfg_stop;
}


static int do_client2(int ss, const char* hostport, int local);
static int do_client3(struct client_tx* ctx);


static int do_client(int argc, char* argv[])
{
  const char* hostport;
  const char* fd_type_s;
  pid_t pid;

  if( cfg_msg_size < sizeof(struct msg) )
    sfnt_fail_usage("ERROR: message size (--msgsize) too small (minimum "
                    "is %d)", (int) sizeof(struct msg));

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

  if( cfg_samples == 0 )
    /* Default to one latency sample per millisecond of test time. */
    cfg_samples = cfg_millisec;

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
    NT_TRY2(ss, try_connect(hostport, cfg_port));
    return do_client2(ss, hostport, local);
  }
}


static int do_client2(int ss, const char* hostport, int local)
{
  struct client_tx* ctx;
  unsigned char uc;
  int one = 1;

  client_check_ver(ss);

  if( cfg_affinity[0] == NULL ) {
    /* Set affinity by default.  Avoid core 0, which often has various OS
     * junk running on it that causes high jitter.  We'll get an error on
     * singe core boxes -- user will just have to set affinity explicitly.
     */
    cfg_affinity[0] = "1,2";
    cfg_affinity[1] = "1";
    if( local && cfg_spin[0] )
      /* It is a very bad idea to pin two spinners onto the same core, as
       * they'll just fight each other for timeslices.
       */
      cfg_affinity[1] = "3";
  }
  if( strcasecmp(cfg_affinity[0], "any") ) {
    int core_i;
    if( sscanf(cfg_affinity[0], "%d,%d", &core_i, &client_rx_core_i) != 2 )
      sfnt_fail_usage("ERROR: bad argument for --affinity");
    cpu_affinity_set(core_i);
  }

  if( cfg_mcast_intf[0] != NULL && cfg_mcast == NULL )
    cfg_mcast = "224.1.2.49";

  do_init();
  client_send_opts(ss);
  ctx = malloc(sizeof(*ctx));
  ctx->ss = ss;
  ctx->crx = client_rx_thread_start();

  if( sfnt_ilist_parse(&ctx->rates, cfg_rates) != 0 )
    sfnt_fail_usage("ERROR: Malformed argument to option --rates");

  ctx->server_ld_preload = sfnt_sock_get_str(ss);

  /* Create and bind/connect test socket. */
  switch( fd_type ) {
  case FDT_TCP: {
    int port = sfnt_sock_get_int(ss);
    char host[strlen(hostport) + 1];
    char* p;
    strcpy(host, hostport);
    if( (p = strchr(host, ':')) != NULL )
      *p = '\0';
    NT_TRY2(ctx->read_fd, socket(PF_INET, SOCK_STREAM, 0));
    if( cfg_nodelay )
      NT_TRY(setsockopt(ctx->read_fd, SOL_TCP, TCP_NODELAY,
                        &one, sizeof(one)));
    NT_TRY(sfnt_connect(ctx->read_fd, host, NULL, port));
    ctx->write_fd = ctx->read_fd;
    break;
  }
  case FDT_UDP: {
    struct sockaddr_in sin;
    socklen_t sin_len = sizeof(sin);
    int us, port = sfnt_sock_get_int(ss);
    char reply_hostport[80];
    NT_TRY2(us, socket(PF_INET, SOCK_DGRAM, 0));
    set_ttl(us, cfg_ttl[0]);
    if( cfg_bindtodev[0] )
      NT_TRY(sfnt_so_bindtodevice(us, cfg_bindtodev[0]));
    if( cfg_mcast_intf[0] )
      NT_TRY(sfnt_ip_multicast_if(us, cfg_mcast_intf[0]));
    uc = cfg_mcast_loop;
    NT_TRY(setsockopt(us, SOL_IP, IP_MULTICAST_LOOP, &uc, sizeof(uc)));
    if( cfg_mcast != NULL ) {
      NT_TRY(sfnt_connect(us, cfg_mcast, NULL, port));
    }
    else {
      char host[strlen(hostport) + 1];
      char* p;
      strcpy(host, hostport);
      if( (p = strchr(host, ':')) != NULL )
        *p = '\0';
      NT_TRY(sfnt_connect(us, host, NULL, port));
    }
    NT_TRY(getsockname(us, (struct sockaddr*) &sin, &sin_len));
    sprintf(reply_hostport, "%s:%d",
            inet_ntoa(sin.sin_addr), ctx->crx->port);
    sfnt_sock_put_str(ss, reply_hostport);
    ctx->write_fd = us;
    ctx->read_fd = -1;
    break;
  }
  case FDT_PIPE:
    ctx->read_fd = the_fds[0];
    ctx->write_fd = the_fds[3];
    if( cfg_spin[0] ) {
      sfnt_fd_set_nonblocking(ctx->read_fd);
      sfnt_fd_set_nonblocking(ctx->write_fd);
    }
    break;
  case FDT_UNIX_S:
  case FDT_UNIX_D:
    ctx->read_fd = ctx->write_fd = the_fds[0];
    break;
  }
  if( ctx->read_fd >= 0 )
    add_fds(ctx->read_fd);

  return do_client3(ctx);
}


static int do_client3(struct client_tx* ctx)
{
  int i;

  ctx->msg = malloc(64 * 1024);

  sfnt_dump_sys_info(&tsc);
  if( ctx->server_ld_preload != NULL )
    printf("# server LD_PRELOAD=%s\n", ctx->server_ld_preload);
  printf("# percentile=%g\n", (double) cfg_percentile);
  printf("# msgsize=%d\n", cfg_msg_size);
  fflush(stdout);

  /* Measure single-trip latency when quiescent */
  client_measure_rtt(ctx, &ctx->ret_lat_stats);
  stats_divide(&ctx->ret_lat_stats, 2);
  printf("# return_latency=%d\n", ctx->ret_lat_stats.mean);

  printf("#\n");
  printf("#mps\tmps\tmps\t"
         "latency\tlatency\tlatency\tlatency\tlatency\tlatency\tlatency\t"
         "sendjit\tsendjit\tsendjit\tsendjit\t"
         "gaps\tgaps\tgaps\n");
  printf("#target\tsend\trecv\t"
         "mean\tmin\tmedian\tmax\t%%ile\tstddev\tsamples\t"
         "mean\tmin\tmax\tbehind\t"
         "n_gaps\tn_drops\tn_ooo\n");
  fflush(stdout);

  sfnt_sock_put_int(ctx->ss, cfg_msg_size);
  sfnt_sock_get_int(ctx->ss);

  /* the test proper */
  for( i = 0; i < ctx->rates.len; ++i ) {
    ctx->msg_per_sec_target = ctx->rates.list[i];
    client_do_test(ctx);
    if( cfg_raw != NULL )
      write_raw_results(ctx);
    write_result_line(ctx);
    if( cfg_stop && tx_is_not_keeping_up(ctx) ) {
      sfnt_err("sfnt-stream: client: TX rate is %d%% of target; stopping\n",
               ctx->msg_per_sec_tx * 100 / ctx->msg_per_sec_target);
      break;
    }
  }

  return 0;
}


int main(int argc, char* argv[])
{
  int rc = 0;

  /* fixme: this could be a compile-time check */
  NT_TESTi3(DEFAULT_MSG_SIZE, >=, sizeof(struct msg));

  sfnt_app_getopt("[tcp|udp|pipe|unix_stream|unix_datagram [host[:port]]]",
                &argc, argv, cfg_opts, N_CFG_OPTS);
  --argc; ++argv;

  if( argc == 0 )
    rc = -do_server();
  else
    rc = -do_client(argc, argv);

  return rc;
}
