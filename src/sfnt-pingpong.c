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
#include <onload/extensions.h>
#include <onload/extensions_zc.h>

#ifdef USE_ZF
#include <zf/zf.h>
#endif

#ifdef USE_DPDK
#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <limits.h>
#include <sys/time.h>
#include <getopt.h>
#include <rte_net.h>
#endif

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
static unsigned    cfg_timeout[2];
static const char* cfg_affinity[2];
static int         cfg_n_pings = 1;
static int         cfg_n_pongs = 1;
static int         cfg_nodelay[2];
static unsigned    cfg_sleep_gap = 0;
static unsigned    cfg_spin_gap = 0;
static int         cfg_zc[2];
static unsigned    cfg_warm[2];
static int         cfg_tmpl_send[2] = {-1, -1};

/* CL1* implies that the cmdline args are the same for both client and
 * server.  CL2* implies that different options can be specified for
 * client and server by using ';'.
 */
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
  CL2S("muxer",       cfg_muxer,       "select, poll, epoll, zf or none"     ),
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
  CL2I("ttl",         cfg_ttl,         "IP_TTL and IP_MULTICAST_TTL"         ),
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
  CL2U("timeout",     cfg_timeout,     "socket SND?RECV timeout"             ),
  CL2S("affinity",    cfg_affinity,    "<client-core>;<server-core>"         ),
  CL1U("n-pings",     cfg_n_pings,     "number of ping messages"             ),
  CL1U("n-pongs",     cfg_n_pongs,     "number of pong messages"             ),
  CL2F("nodelay",     cfg_nodelay,     "enable TCP_NODELAY"                  ),
  CL1U("sleep-gap",   cfg_sleep_gap,   "additional gap in microseconds to sleep between iterations"),
  CL1U("spin-gap",    cfg_spin_gap,    "additional gap in microseconds to spin between iterations"),
  CL2F("zerocopy",    cfg_zc,          "Use Zero Copy API for TCP tx and UDP rx"),
  CL2U("warm",        cfg_warm,        "Use MSG_WARM in usecs gap (must be < spin-gap)"),
  CL2I("template",    cfg_tmpl_send,   "Use templated_sends and update thispercentage of bytes"),
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


struct user_info {
  int size;
  int flags;
  int zc_rc;
};

#define MAX_FDS            1024

static struct sfnt_tsc_params tsc;
static char           ppbuf[64 * 1024];
static char           msg_buf[64 * 1024];

#define NUM_ZC_BUFFERS 50
static struct onload_zc_iovec zc_iovec[NUM_ZC_BUFFERS];
static struct onload_zc_mmsg zc_mmsg;
static struct msghdr zc_msg;
static struct iovec zc_iov;
struct onload_zc_recv_args zc_args;

static enum handle_type handle_type;
static int              the_fds[4];  /* used for pipes and unix sockets */

static fd_set           select_fdset;
static int              select_fds[MAX_FDS];
static int              select_n_fds;
static int              select_max_fd;

static struct sockaddr_in  my_sa;
static struct sockaddr_in  peer_sa;
static struct sockaddr*    to_sa;
static socklen_t           to_sa_len;

/* Timeout for receives in milliseconds, or -1 if blocking forever. */
static int                 timeout_ms;

static onload_template_handle tmpl_handle;
static int                    tmpl_update_size;

#if NT_HAVE_POLL
static struct pollfd       pfds[MAX_FDS];
static int                 pfds_n;
#endif

#if NT_HAVE_EPOLL
static int                 epoll_fd;
#endif

#ifdef USE_ZF
static struct zf_muxer_set* zf_mux;
static struct zf_attr* zattr;
static struct zf_stack* ztack;
#endif

#ifdef USE_DPDK
#define RX_RING_SIZE 512
#define TX_RING_SIZE 512

#define NUM_MBUFS 1023
#define MBUF_CACHE_SIZE 250

#define IP_VERSION 0x40
#define IP_HDRLEN  0x05 /* default IP header length == five 32-bits words. */
#define IP_DEFTTL  64   /* from RFC 1340. */
#define IP_VHL_DEF (IP_VERSION | IP_HDRLEN)
#define IP_DN_FRAGMENT_FLAG 0x0040

struct rte_mempool *dpdk_mbuf_pool;

static const struct rte_eth_conf port_conf_default = {
  .rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN }
};

static uint16_t dpdk_num_tx=0;
#endif

static ssize_t (*do_recv)(union handle, void*, size_t, int);
static ssize_t (*do_send)(union handle, const void*, size_t, int);

static ssize_t (*mux_recv)(union handle, void*, size_t, int);
static void (*mux_add)(int fd);


static void noop_add(int fd)
{
}

/**********************************************************************/


#ifdef __sun__
#define rfn_recv  solaris_recv
void alarm_handler()
{
  return;
}


ssize_t solaris_recv(union handle h, void *buf, size_t len, int flags)
{
  int rc = 0;

  signal(SIGALRM, alarm_handler);
  if( cfg_timeout[0] )
    alarm(cfg_timeout[0]);

  rc = recv(h.fd, buf, len, flags);
  if(rc == -1 && errno == EINTR) {
    errno = ETIMEDOUT;
  }

  alarm(0);
  return rc;
}
#else
static inline ssize_t
rfn_recv(union handle h, void* buf, size_t len, int flags)
{
  return recv(h.fd, buf, len, flags);
}
#endif


static ssize_t sfn_sendto(union handle h, const void* buf, size_t len,
                          int flags)
{
  return sendto(h.fd, buf, len, 0, to_sa, to_sa_len);
}


static inline ssize_t
sfn_send(union handle h, const void* buf, size_t len, int flags)
{
  return send(h.fd, buf, len, flags);
}


static ssize_t rfn_read(union handle h, void* buf, size_t len, int flags)
{
  /* NB. To support non-blocking semantics caller must have set O_NONBLOCK. */
  int rc, got = 0, all = flags & MSG_WAITALL;
  do {
    if( (rc = read(h.fd, (char*) buf + got, len - got)) > 0 )
      got += rc;
  } while( all && got < len && rc > 0 );
  return got ? got : rc;
}


static ssize_t sfn_write(union handle h, const void* buf, size_t len, int flags)
{
  return write(h.fd, buf, len);
}


#ifdef USE_ZF
static ssize_t rfn_zfur_recv(union handle h, void* buf, size_t len, int flags)
{
  struct {
    struct zfur_msg zcr;
    struct iovec iov[6];
  } rd;
  rd.zcr.iovcnt = 6;

  int got = 0, all = flags & MSG_WAITALL;
  flags = 0;
  int i;

  do {
    if( !zf_mux )
      while(zf_reactor_perform(ztack) == 0);

    zfur_zc_recv(h.ur, &rd.zcr, flags);
    for(i = 0; i < rd.zcr.iovcnt; i++)
      got += rd.zcr.iov[i].iov_len;

    zfur_zc_recv_done(h.ur, &rd.zcr);
  } while( all && got < len );

  return got;
}


static ssize_t sfn_zfut_send(union handle h, const void* buf, size_t len,
                             int flags)
{
  const struct iovec siov = {
    .iov_base = (void*)buf,
    .iov_len = len
  };

  int rc = zfut_send(h.ut, &siov, 1, 0);
  return rc == 0 ? len : rc;
}


static ssize_t rfn_zft_recv(union handle h, void* buf, size_t len, int flags)
{
  struct {
    struct zft_msg zcr;
    struct iovec iov[6];
  } rd;
  int in_iovcnt = sizeof(rd.iov)/sizeof(rd.iov[0]);

  int got = 0, all = flags & MSG_WAITALL;
  flags = 0;
  int i;
 
  do {
    rd.zcr.iovcnt = in_iovcnt;

    if( !zf_mux )
      while(zf_reactor_perform(ztack) == 0);

    zft_zc_recv(h.t, &rd.zcr, flags);

    for(i = 0; i < rd.zcr.iovcnt; i++)
      got += rd.zcr.iov[i].iov_len;

    if( rd.zcr.iovcnt )
      zft_zc_recv_done(h.t, &rd.zcr);

    rd.zcr.iovcnt = in_iovcnt;

    /* zf_reactor perform is edge triggered so we need to ensure we've fully
     * drained our recv queue before spinning on it.  That means we need to
     * make 2 calls to zft_zc_recv as if we have data queued over the point at
     * which the ring wraps it will be split into batches.
     */
    zft_zc_recv(h.t, &rd.zcr, flags);

    for(i = 0; i < rd.zcr.iovcnt; i++)
      got += rd.zcr.iov[i].iov_len;

    if( rd.zcr.iovcnt )
      zft_zc_recv_done(h.t, &rd.zcr);
  } while( all && got < len );

  return got;
}


static ssize_t sfn_zft_send(union handle h, const void* buf, size_t len,
                            int flags)
{
  const struct iovec siov = {
    .iov_base = (void*)buf,
    .iov_len = len
  };

  int rc = zft_send(h.t, &siov, 1, 0);
  return rc == 0 ? len : rc;
}
#endif

#ifdef USE_DPDK
/* currently this is non blocking. Wrap with rfn_dpdk_recv to spin */
static ssize_t _rfn_dpdk_recv(union handle h, void* buf, size_t len, int flags)
{
  unsigned num_rx = 0;
  struct rte_mbuf* m;
  struct rte_net_hdr_lens hdr_lens;
  struct udp_hdr* udp;
  char* payload;
  int paylen;

  num_rx = rte_eth_rx_burst(0, 0, &m, 1);

  if( likely(num_rx == 0) )
    return -EAGAIN;

  uint32_t ptype = rte_net_get_ptype(m, &hdr_lens, RTE_PTYPE_ALL_MASK);
  switch( ptype & RTE_PTYPE_L4_MASK ) {
  case RTE_PTYPE_L4_UDP:
    udp = (struct udp_hdr*)( rte_pktmbuf_mtod(m, char*)
                             + hdr_lens.l2_len + hdr_lens.l3_len );
    payload = (char*)( udp +1 );
    /* NB network byte order. Also dgram_len includes UDP header */
    paylen = ntohs(udp->dgram_len) - hdr_lens.l4_len;
    if( (udp->src_port != peer_sa.sin_port) ||
        (udp->dst_port != my_sa.sin_port) ) {
      rte_pktmbuf_free(m);
      return -EAGAIN;
    }
    if( paylen != len ) {
      printf("Payload length %d does not match requested length %zd\n",
             paylen, len);
      exit(0);
    }
    rte_memcpy(buf, payload, paylen);
    rte_pktmbuf_free(m);
    return paylen;
    break;

  default:
    rte_pktmbuf_free(m);
    return -EAGAIN;
  }
}


static ssize_t rfn_dpdk_recv(union handle h, void* buf, size_t len, int flags)
{
  int rc, got = 0, all = flags & MSG_WAITALL;
  flags = (flags & ~MSG_WAITALL) | MSG_DONTWAIT;
  do {
    while( (rc = _rfn_dpdk_recv(h, (char*) buf + got, len - got, flags)) < 0 )
      if( rc != -EAGAIN )
        goto out;
    got += rc;
  } while( all && got < len && rc > 0 );
 out:
  return got ? got : rc;
}


/* Use a broadcast destination MAC for now*/
static const struct ether_addr ether_multicast = {
  .addr_bytes = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
};
static void
fill_udp_pkt(struct rte_mbuf *m, int paylen, uint16_t n, const char* data)
{
  int ip_len = sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr) + paylen;
  int tx_frame_len = sizeof(struct ether_hdr) + ip_len;
  struct ether_hdr* eth;
  struct ipv4_hdr* ip4;
  struct udp_hdr* udp;
  char* payload;

  eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
  ip4 = (struct ipv4_hdr*)((char*) eth +
                           sizeof(struct ether_hdr));
  udp = (struct udp_hdr*)((void*) (ip4 + 1));
  payload = (char*) (udp +1);

  /* Fill in ethernet */
  ether_addr_copy(&ether_multicast, &eth->d_addr);
  rte_eth_macaddr_get(0, &eth->s_addr);
  eth->ether_type = htons(0x0800);

  /* Fill in IP */
  ip4->version_ihl = IP_VHL_DEF;
  ip4->type_of_service = 0;
  ip4->total_length = htons(ip_len);
  ip4->packet_id = htons(n);
  ip4->fragment_offset = IP_DN_FRAGMENT_FLAG;
  ip4->time_to_live = IP_DEFTTL;
  ip4->next_proto_id = IPPROTO_UDP;
  ip4->hdr_checksum = 0;
  ip4->src_addr = my_sa.sin_addr.s_addr;
  ip4->dst_addr = peer_sa.sin_addr.s_addr;

  /* Fill in UDP */
  udp->src_port = my_sa.sin_port;
  udp->dst_port = peer_sa.sin_port;
  udp->dgram_len = htons(paylen + sizeof(struct udp_hdr));
  udp->dgram_cksum = 0;

  /* fill in payload */
  rte_memcpy(payload, data, paylen);

  /* book-keeping */
  m->data_len = tx_frame_len;
  m->pkt_len = tx_frame_len;
}


static ssize_t sfn_dpdk_send(union handle h, const void* buf, size_t len,
                            int flags)
{
  struct rte_mbuf *m;
  /* Currently doesn't support Jumbos */
  NT_ASSERT(len <= 1472);

  m = rte_pktmbuf_alloc(dpdk_mbuf_pool);
  fill_udp_pkt(m, len, dpdk_num_tx, buf);
  NT_TESTi3(rte_eth_tx_burst(0, 0, &m, 1), ==, 1);
  dpdk_num_tx++;

  return len;
}
#endif

/**********************************************************************/
static void handle_msg(void* iov_base, int len)
{
}

/**********************************************************************/

static enum onload_zc_callback_rc
zc_recv_callback(struct onload_zc_recv_args *args, int flag)
{
  struct user_info *zc_info = (struct user_info *)args->user_ptr;
  int i, zc_rc = 0;

  if(args->msg.msghdr.msg_iovlen == 1) {
    zc_rc += args->msg.iov[0].iov_len;
    handle_msg(args->msg.iov[0].iov_base, args->msg.iov[0].iov_len);
  }
  else {
    for( i = 0; i < args->msg.msghdr.msg_iovlen; ++i ) {
      zc_rc += args->msg.iov[i].iov_len;
      handle_msg(args->msg.iov[i].iov_base, args->msg.iov[i].iov_len);  
    }
  }

  if( zc_rc == 0 )
    return ONLOAD_ZC_TERMINATE;

  zc_info->zc_rc += zc_rc;

  if( (zc_info->flags & MSG_WAITALL) && 
      (zc_info->zc_rc < zc_info->size) )
    return ONLOAD_ZC_CONTINUE;
  else 
    return ONLOAD_ZC_TERMINATE;
}


/**********************************************************************/

static ssize_t do_recv_zc(union handle h, void* buf, size_t len, int flags)
{
  struct user_info info;
  int rc;

  info.size = len;
  info.flags = flags & MSG_WAITALL;
  info.zc_rc = 0;

  zc_args.user_ptr = &info;
  zc_args.flags = 0;
  if( flags & MSG_DONTWAIT )
    zc_args.flags |= ONLOAD_MSG_DONTWAIT;

  rc = onload_zc_recv(h.fd, &zc_args);
  if( rc == -ENOTEMPTY ) {
    if( ( rc = onload_recvmsg_kernel(h.fd, &zc_msg, 0) ) < 0 )
      printf("onload_recvmsg_kernel failed\n");
  } 
  else if( rc == 0 ) {
    /* zc_rc gets set by callback to indicate bytes received, so we
     * can return that to make it look like a standard recv call
     */
    rc = info.zc_rc;
  }
  return rc;
}


static ssize_t do_send_zc(union handle h, const void* buf, size_t len,
                          int flags)
{
  int bytes_done, rc, i, bufs_needed;

  /* This assumes that iovec has been initialised with zc buffers by
   * the caller.  It will replenish iovec with buffers that are
   * consumed before returning.
   */

  zc_mmsg.fd = h.fd;
  zc_mmsg.msg.iov = zc_iovec;

  bytes_done = 0;
  zc_mmsg.msg.msghdr.msg_iovlen = 0;
  while( bytes_done < len ) {
    if( zc_iovec[zc_mmsg.msg.msghdr.msg_iovlen].iov_len > (len - bytes_done) )
      zc_iovec[zc_mmsg.msg.msghdr.msg_iovlen].iov_len = (len - bytes_done);
    /* NB. In theory we should copy buf into the iovec, but as ppbuf is
     * never patterned there seems little point in doing the memcpy
     */
    bytes_done += zc_iovec[zc_mmsg.msg.msghdr.msg_iovlen].iov_len;
    ++zc_mmsg.msg.msghdr.msg_iovlen;
  }
  NT_ASSERT(zc_mmsg.msg.msghdr.msg_iovlen < NUM_ZC_BUFFERS);

  rc = onload_zc_send(&zc_mmsg, 1, 0);
  if( rc != 1 ) {
    printf("onload_zc_send failed to process msg, %d\n", rc);
    return -1;
  }
  else {
    if( zc_mmsg.rc < 0 )
      printf("onload_zc_send message error %d\n", zc_mmsg.rc);
    else {
      /* Iterate over the iovecs; any that we used that have been sent
       * we need to replenish.  Any that we used that haven't been
       * sent remain with us so we don't need to replenish, but does
       * indicate an error
       */
      i = 0;
      bytes_done = 0;
      bufs_needed = 0;
      while( i < zc_mmsg.msg.msghdr.msg_iovlen ) {
        if( bytes_done == zc_mmsg.rc ) {
          printf("onload_zc_send did not send iovec %d\n", i);
          /* In other buffer allocation schemes we would have to release
           * these buffers, but seems pointless as we guarantee at the
           * end of this function to have iovec array full, so do nothing.
           *
           *  onload_zc_release_buffers(h.fd, &zc_iovec[i].buf, 0)
           */
        }
        else {
          /* Buffer sent (at least partially) successfully, now owned by
           * Onload, so replenish iovec array
           */
          ++bufs_needed;
          
          if( zc_mmsg.rc - bytes_done < zc_iovec[i].iov_len ) {
            printf("onload_zc_send partial send (%d of %d) of zc_iovec %d\n",
                   zc_mmsg.rc - bytes_done, (int)zc_iovec[i].iov_len, i);
            bytes_done = zc_mmsg.rc;
          }
          else
            bytes_done += zc_iovec[i].iov_len;
        }
        ++i;
      }

      if( bufs_needed ) {
        rc = onload_zc_alloc_buffers(h.fd, zc_iovec, bufs_needed, 
                                     ONLOAD_ZC_BUFFER_HDR_TCP);
        NT_ASSERT(rc == 0);
      }
    }
  }

  /* Set a return code that looks similar enough to send().  NB. we're
   * not setting (and neither does onload_zc_send()) errno 
   */
  if( zc_mmsg.rc < 0 )
    return -1;
  else
    return bytes_done;
}


/**********************************************************************/

static void do_tmpl_alloc(int fd, const void* buf, size_t len, int flags)
{
  int rc;
  NT_ASSERT(tmpl_update_size >= 0 && tmpl_update_size <= len);
  NT_ASSERT(cfg_tmpl_send[0] >= 0 && cfg_tmpl_send[0] <= 100);

  struct iovec iovec = {
    .iov_base = (void*)buf,
    .iov_len = len,
  };

  /* onload_msg_template_alloc() can temporarily fail as templates
   * only become reusable when the previous ones have finished
   * sending.  As sfnt-pingpong is trying to allocate them off the
   * fast path, we can spin here.
   */
  while( 1 ) {
    rc = onload_msg_template_alloc(fd, &iovec, 1, &tmpl_handle, 0);
    if( rc == 0 )
      return;

    /* This error implies that templated sends for these lengths is
     * not supported so we just exit normally.
    */
    if( rc == -E2BIG ) {
      fprintf(stderr, "onload_msg_template_alloc for %ld failed with E2BIG\n",
              len);
      exit(0);
    }

    /* Ignore temporary errors */
    if( rc != -ENOMEM && rc != -EBUSY ) {
      fprintf(stderr, "onload_msg_template_alloc for %ld failed with %d %s\n",
              len, rc, strerror(-rc));
      exit(1);
    }
  }
}


static void do_tmpl_abort(int sock_fd)
{
#ifndef NDEBUG
  int rc;
  NT_ASSERT(cfg_tmpl_send[0] >= 0 && cfg_tmpl_send[0] <= 100);
  rc =
#endif
    onload_msg_template_abort(sock_fd, tmpl_handle);
  NT_ASSERT(rc == 0);
}


static ssize_t do_send_tmpl(union handle h, const void* buf, size_t len,
                            int flags)
{
  int rc;
  NT_ASSERT(tmpl_update_size >= 0 && tmpl_update_size <= len);
  NT_ASSERT(cfg_tmpl_send[0] >= 0 && cfg_tmpl_send[0] <= 100);
  NT_ASSERT(flags == 0);

  /* Finish the current send and then allocate a template for the next
   * msg off the fast path.
   */

  if( tmpl_update_size == 0 ) {
    /* Send with no updates */
    rc = onload_msg_template_update(h.fd, tmpl_handle, NULL, 0,
                                    ONLOAD_TEMPLATE_FLAGS_SEND_NOW);
  }
  else {
    /* Send with updates.  Construct the update iovec with the
     * requested amount of bytes to update.  This will just update
     * starting from offset 0 and for tmpl_update_size bytes.
     */
    struct onload_template_msg_update_iovec otmu = {
      .otmu_base   = ppbuf,
      .otmu_len    = tmpl_update_size,
      .otmu_offset = 0,
      .otmu_flags  = 0,
    };
    rc = onload_msg_template_update(h.fd, tmpl_handle, &otmu, 1,
                                    ONLOAD_TEMPLATE_FLAGS_SEND_NOW);
  }
  NT_ASSERT(rc == 0);
  do_tmpl_alloc(h.fd, buf, len, flags);
  return len;
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


static ssize_t select_recv(union handle h, void* buf, size_t len, int flags)
{
  enum sfnt_mux_flags mux_flags = NT_MUX_CONTINUE_ON_EINTR;
  int i, rc, got = 0, all = flags & MSG_WAITALL;
  flags = (flags & ~MSG_WAITALL) | MSG_DONTWAIT;
  if( cfg_spin[0] )
    mux_flags |= NT_MUX_SPIN;
  do {
    for( i = 0; i < select_n_fds; ++i )
      FD_SET(select_fds[i], &select_fdset);
    rc = sfnt_select(select_max_fd + 1, &select_fdset, NULL, NULL, &tsc,
                     timeout_ms, mux_flags);
    if( rc == 1 ) {
      NT_TEST(FD_ISSET(h.fd, &select_fdset));
      if( (rc = do_recv(h, (char*) buf + got, len - got, flags)) > 0 )
        got += rc;
    }
    else {
      NT_TESTi3(rc, <=, 0);
      if( rc == 0 && got == 0 ) {
        errno = EAGAIN;
        rc = -1;
      }
      break;
    }
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


static ssize_t poll_recv(union handle h, void* buf, size_t len, int flags)
{
  enum sfnt_mux_flags mux_flags = NT_MUX_CONTINUE_ON_EINTR;
  int rc, got = 0, all = flags & MSG_WAITALL;
  flags = (flags & ~MSG_WAITALL) | MSG_DONTWAIT;
  if( cfg_spin[0] )
    mux_flags |= NT_MUX_SPIN;
  do {
    rc = sfnt_poll(pfds, pfds_n, timeout_ms, &tsc, mux_flags);
    if( rc == 1 ) {
      NT_TEST(pfds[0].revents & POLLIN);
      if( (rc = do_recv(h, (char*) buf + got, len - got, flags)) > 0 )
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


static ssize_t epolltype_recv(union handle h, void* buf, size_t len, int flags)
{
  enum sfnt_mux_flags mux_flags = NT_MUX_CONTINUE_ON_EINTR;
  struct epoll_event e;
  int rc, got = 0, all = flags & MSG_WAITALL;
  flags = (flags & ~MSG_WAITALL) | MSG_DONTWAIT;
  union handle mh;
  enum handle_type mh_type;
  if( handle_type & HTF_ZF ) {
#ifdef USE_ZF
    mh.zf_mux = zf_mux;
    mh_type = HT_ZF_MUX;
#endif
  }
  else {
    mh.fd = epoll_fd;
    mh_type = HT_EPOLL;
  }

  if( cfg_spin[0] )
    mux_flags |= NT_MUX_SPIN;
  do {
    rc = sfnt_epolltype_wait(mh, mh_type, &e, 1, timeout_ms, &tsc, mux_flags);
    if( rc == 1 ) {
      NT_TEST(e.events & EPOLLIN);
      if( (rc = do_recv(h, (char*) buf + got, len - got, flags)) > 0 )
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


static ssize_t epoll_mod_recv(union handle h, void* buf, size_t len, int flags)
{
  enum sfnt_mux_flags mux_flags = NT_MUX_CONTINUE_ON_EINTR;
  struct epoll_event e;
  int rc, got = 0, all = flags & MSG_WAITALL;
  flags = (flags & ~MSG_WAITALL) | MSG_DONTWAIT;
  union handle mh = { .fd = epoll_fd };

  if( cfg_spin[0] )
    mux_flags |= NT_MUX_SPIN;
  e.events = EPOLLIN;
  NT_TRY(epoll_ctl(epoll_fd, EPOLL_CTL_MOD, h.fd, &e));
  do {
    rc = sfnt_epolltype_wait(mh, HT_EPOLL, &e, 1, timeout_ms, &tsc, mux_flags);
    if( rc == 1 ) {
      NT_TEST(e.events & EPOLLIN);
      if( (rc = do_recv(h, (char*) buf + got, len - got, flags)) > 0 )
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
  NT_TRY(epoll_ctl(epoll_fd, EPOLL_CTL_MOD, h.fd, &e));
  return got ? got : rc;
}


static ssize_t epoll_adddel_recv(union handle h, void* buf, size_t len,
                                 int flags)
{
  enum sfnt_mux_flags mux_flags = NT_MUX_CONTINUE_ON_EINTR;
  struct epoll_event e;
  int rc, got = 0, all = flags & MSG_WAITALL;
  flags = (flags & ~MSG_WAITALL) | MSG_DONTWAIT;
  union handle mh = { .fd = epoll_fd };

  if( cfg_spin[0] )
    mux_flags |= NT_MUX_SPIN;
  e.events = EPOLLIN;
  NT_TRY(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, h.fd, &e));
  do {
    rc = sfnt_epolltype_wait(mh, HT_EPOLL, &e, 1, timeout_ms, &tsc,
                             mux_flags);
    if( rc == 1 ) {
      NT_TEST(e.events & EPOLLIN);
      if( (rc = do_recv(h, (char*) buf + got, len - got, flags)) > 0 )
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
  NT_TRY(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, h.fd, &e));
  return got ? got : rc;
}

#endif

/**********************************************************************/

#ifdef USE_ZF
static void zf_mux_init(void)
{
  NT_TRY(zf_muxer_alloc(ztack, &zf_mux));
}
#endif

/**********************************************************************/

static ssize_t spin_recv(union handle h, void* buf, size_t len, int flags)
{
  int rc, got = 0, all = flags & MSG_WAITALL;
  flags = (flags & ~MSG_WAITALL) | MSG_DONTWAIT;
  do {
    while( (rc = do_recv(h, (char*) buf + got, len - got, flags)) < 0 )
      if( errno != EAGAIN )
        goto out;
    got += rc;
  } while( all && got < len && rc > 0 );
 out:
  return got ? got : rc;
}


static ssize_t warm_recv(union handle h, void* buf, size_t len, int flags)
{
  int rc, got = 0, all = flags & MSG_WAITALL;
  flags = (flags & ~MSG_WAITALL) | MSG_DONTWAIT;
  do {
    rc = do_recv(h, (char*) buf + got, len - got, flags);
    if( rc < 0 ) {
      if( errno != EAGAIN )
        goto out;
      NT_TRY(send(h.fd, buf, 1, ONLOAD_MSG_WARM));
      /* Set rc to pass the while condition. */
      rc = 1;
    }
    else {
      got += rc;
    }
  } while( all && got < len && rc > 0 );
 out:
  return got ? got : rc;
}

/**********************************************************************/

static void set_ttl(int sock, int ttl)
{
  if( ttl >= 0 ) {
    unsigned char ttl8 = ttl;
    int ttl_result;
    NT_TRY(setsockopt(sock, SOL_IP, IP_MULTICAST_TTL, &ttl8, sizeof(ttl8)));
    ttl = ttl ? ttl : 1;
    /* Sol10 and Sol11 disagree on the valid size of this argument.
     * so try both. */
    ttl8 = ttl8 ? ttl8 : 1;
    ttl_result = setsockopt(sock, SOL_IP, IP_TTL, &ttl8, sizeof(ttl8));
    if( ttl_result<0 )
      ttl_result = setsockopt(sock, SOL_IP, IP_TTL, &ttl, sizeof(ttl));
    NT_TRY(ttl_result);
  }
}

static void do_zc_init(int write_fd)
{
  if( cfg_zc[0] ) {
    if( (handle_type != HT_UDP) && (handle_type != HT_TCP) )
      sfnt_fail_usage("ERROR: zerocopy support only available for UDP and TCP");

    if( handle_type == HT_UDP ) {
      memset(&zc_args, 0, sizeof(zc_args));
      zc_args.cb = &zc_recv_callback;
    }
    if( handle_type == HT_TCP )
      NT_TRY(onload_zc_alloc_buffers(write_fd, &zc_iovec[0], NUM_ZC_BUFFERS,
                                     ONLOAD_ZC_BUFFER_HDR_TCP));
  }
}


#ifdef USE_ZF
static void do_zf_init(void)
{
  NT_TRY(zf_init());
  NT_TRY(zf_attr_alloc(&zattr));
  NT_TRY(zf_stack_alloc(zattr, &ztack));
}
#endif


#ifdef USE_DPDK
static inline int
dpdk_port_init(struct rte_mempool *mbuf_pool)
{
  uint8_t port = 0;
  struct rte_eth_dev_info dev_info;
  struct rte_eth_conf port_conf = port_conf_default;
  const uint16_t rx_rings = 1;
  const uint16_t tx_rings = 1;
  uint16_t q;
  uint16_t nb_rxd = RX_RING_SIZE;
  uint16_t nb_txd = TX_RING_SIZE;

  if (port >= rte_eth_dev_count())
    return -1;

  /* Configure the Ethernet device. */
  NT_TESTi3(rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf), ==, 0);

  NT_TESTi3(rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd), ==, 0);

  /* Allocate and set up 1 RX queue per Ethernet port. */
  for (q = 0; q < rx_rings; q++) {
    NT_TESTi3(rte_eth_rx_queue_setup(port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool), ==, 0);
  }

  /* Allocate and set up 1 TX queue per Ethernet port. */
  for (q = 0; q < tx_rings; q++) {
    /* Setup txq_flags */
    struct rte_eth_txconf *txconf;

    rte_eth_dev_info_get(q, &dev_info);
    txconf = &dev_info.default_txconf;

    NT_TRY(rte_eth_tx_queue_setup(port, q, nb_txd, rte_eth_dev_socket_id(port), txconf));
  }

  /* Start the Ethernet port. */
  NT_TRY(rte_eth_dev_start(port));

  /* Enable RX in promiscuous mode for the Ethernet device. */
  rte_eth_promiscuous_enable(port);

  return 0;
}


static void do_dpdk_init(int core)
{
  char* argv[10] = { "dummy", "--proc-type=auto", "-l1", NULL };
  int argc = 3;
  char set_core[30];

  sprintf(set_core, "-l%d", core);
  argv[2] = set_core;

  fprintf(stderr, "Initialising EAL\n");
  int rc = rte_eal_init(argc, argv);
  if (rc < 0) {
    rte_exit(EXIT_FAILURE, "Failed to initialise EAL (%s)\n", rte_strerror(-rc));
  }
  fprintf(stderr, "Initialised EAL\n");

  int num_ports = rte_eth_dev_count();
  if( num_ports < 1 )
    rte_exit(EXIT_FAILURE, "Requires at least one interface bound to DPDK\n");
  if( num_ports > 1 )
    fprintf(stderr,
            "Multiple interfaces bound to DPDK - only using first one\n");

  dpdk_mbuf_pool = rte_pktmbuf_pool_create("POOL",
                                           NUM_MBUFS,
                                           MBUF_CACHE_SIZE,
                                           0,
                                           RTE_MBUF_DEFAULT_BUF_SIZE,
                                           rte_socket_id());

  if( dpdk_mbuf_pool == NULL )
    rte_exit(EXIT_FAILURE, "Unable to create mbuf pool - %s\n",
             rte_strerror(rte_errno));

  NT_TESTi3(dpdk_port_init(dpdk_mbuf_pool), ==, 0);
}
#endif


static void do_init(void)
{
  const char* muxer = cfg_muxer[0];
  unsigned core_i = 1;

  if( cfg_tmpl_send[0] != -1 && cfg_tmpl_send[0] > 100 ) {
    sfnt_err("ERROR: Amount of templated send to update(%d) more than 100%%\n",
             cfg_tmpl_send[0]);
    sfnt_fail_setup();
  }

  /* Set affinity first to ensure optimal locality. */

  if( strcasecmp(cfg_affinity[0], "any") )
    if( sscanf(cfg_affinity[0], "%u", &core_i) == 1 )
      if( ! (handle_type & HTF_DPDK) )
        if( sfnt_cpu_affinity_set(core_i) != 0 ) {
          sfnt_err("ERROR: Failed to set CPU affinity to core %d (%d %s)\n",
                   core_i, errno, strerror(errno));
          sfnt_fail_setup();
        }


  NT_TRY(sfnt_tsc_get_params(&tsc));

  if( handle_type == HT_UDP && ! cfg_connect[0] ) {
    if( cfg_tmpl_send[0] != -1 ) {
      sfnt_err("ERROR: templated sends not supported for UDP\n");
      sfnt_fail_setup();
    }
    if( cfg_zc[0] )
      do_recv = do_recv_zc;
    else
      do_recv = rfn_recv;
    do_send = sfn_sendto;
  }
  else if( handle_type & HTF_SOCKET ) {
    if( cfg_zc[0] && (handle_type == HT_TCP) )
      do_send = do_send_zc;
    else
      do_send = sfn_send;
    if( cfg_zc[0] && (handle_type == HT_UDP) )
      do_recv = do_recv_zc;
    else
      do_recv = rfn_recv;
    if( cfg_tmpl_send[0] != -1 ) {
      if( handle_type == HT_UDP ) {
        sfnt_err("ERROR: templated sends not supported for UDP\n");
        sfnt_fail_setup();
      }
      do_send = do_send_tmpl;
    }
  }
#ifdef USE_ZF
  else if( handle_type & HTF_ZF ) {
    if( cfg_tmpl_send[0] != -1 ) {
      sfnt_err("ERROR: templated sends not supported for zockets\n");
      sfnt_fail_setup();
    }
    if( cfg_warm[0] != 0 ) {
      sfnt_err("ERROR: MSG_WARM not supported for zockets\n");
      sfnt_fail_setup();
    }
    if( cfg_zc[0] ) {
      sfnt_err("ERROR: Onload zero copy not supported for zockets\n");
      sfnt_fail_setup();
    }

    if( handle_type == HT_ZF_UDP ) {
      do_recv = rfn_zfur_recv;
      do_send = sfn_zfut_send;
    }
    else {
      NT_ASSERT(handle_type == HT_ZF_TCP);
      do_recv = rfn_zft_recv;
      do_send = sfn_zft_send;
    }

    do_zf_init();
  }
#endif

#ifdef USE_DPDK
  else if (handle_type & HTF_DPDK ) {
    if( cfg_tmpl_send[0] != -1 ) {
      sfnt_err("ERROR: templated sends not supported for DPDK\n");
      sfnt_fail_setup();
    }
    if( cfg_warm[0] != 0 ) {
      sfnt_err("ERROR: MSG_WARM not supported for DPDK\n");
      sfnt_fail_setup();
    }
    if( cfg_zc[0] ) {
      sfnt_err("ERROR: Onload zero copy not supported for DPDK\n");
      sfnt_fail_setup();
    }

    NT_ASSERT(handle_type == HT_DPDK_UDP);
    do_recv = rfn_dpdk_recv;
    do_send = sfn_dpdk_send;
    do_dpdk_init(core_i);
  }
#endif

  else {
    do_recv = rfn_read;
    do_send = sfn_write;
  }

  /* If we're using the direct zockets API we must use an appropriate muxer
   * type, so check mux separately in that case.
   */
  if( handle_type & HTF_ZF ) {
#ifdef USE_ZF
    if( muxer == NULL || ! strcmp(muxer, "") || ! strcasecmp(muxer, "none") ) {
      mux_recv = cfg_spin[0] ? spin_recv : do_recv;
      mux_add = noop_add;
    }
    else if( ! strcasecmp(muxer, "zf") ) {
      mux_recv = epolltype_recv;
      /* mux_add is used for adding additional fds to a mux set - adding to
       * a mux set for zockets is handled explicitly
       */
      mux_add = noop_add;
      zf_mux_init();
    }
    else {
      sfnt_fail_usage("ERROR: muxer '%s' unknown, or invalid with zockets",
                      muxer);
    }
#else
    /* Shouldn't be using a zocket if we're not built with zf */
    NT_ASSERT(0);
#endif
  }
#ifdef USE_DPDK
  else if( handle_type & HTF_DPDK ) {
    if( muxer == NULL || ! strcmp(muxer, "") || ! strcasecmp(muxer, "none") ) {
      mux_recv = cfg_spin[0] ? spin_recv : do_recv;
      mux_add = noop_add;
    }
    else {
      sfnt_err("ERROR: Muxer not supported for DPDK\n");
      sfnt_fail_setup();
    }
  }
#endif
  else {
    if( muxer == NULL || ! strcmp(muxer, "") || ! strcasecmp(muxer, "none") ) {
      if( cfg_warm[0] ) 
        mux_recv = warm_recv;
      else
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
      mux_recv = epolltype_recv;
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
}


static void do_ping(union handle read_h, union handle write_h, int sz)
{
  int i, rc;

  zc_msg.msg_name = NULL;
  zc_msg.msg_namelen = 0;
  zc_msg.msg_iov = &zc_iov;
  zc_msg.msg_iovlen = 1;
  zc_msg.msg_control = 0;
  zc_msg.msg_controllen = 0;
  zc_msg.msg_iov->iov_base = msg_buf;
  zc_msg.msg_iov->iov_len = sz;

  for( i = 0; i < cfg_n_pings; ++i ) {
    rc = do_send(write_h, ppbuf, sz, 0);
    NT_TESTi3(rc, ==, sz);
  }
  for( i = 0; i < cfg_n_pongs; ++i ) {
    rc = mux_recv(read_h, ppbuf, sz, MSG_WAITALL);
    NT_TESTi3(rc, ==, sz);
  }
}


static void do_pong(union handle read_h, union handle write_h, int sz)
{
  int i, rc;

  zc_msg.msg_name = NULL;
  zc_msg.msg_namelen = 0;
  zc_msg.msg_iov = &zc_iov;
  zc_msg.msg_iovlen = 1;
  zc_msg.msg_control = 0;
  zc_msg.msg_controllen = 0;
  zc_msg.msg_iov->iov_base = msg_buf;
  zc_msg.msg_iov->iov_len = sz;

  for( i = 0; i < cfg_n_pings; ++i ) {
#ifdef __sun__
    /* NB. Solaris doesn't block in UDP recv with 0 length buffer. */
    rc = mux_recv(read_h, ppbuf, sz ? sz : 1, MSG_WAITALL);
#else
    rc = mux_recv(read_h, ppbuf, sz, MSG_WAITALL);
#endif
    NT_TESTi3(rc, ==, sz);
  }
  for( i = 0; i < cfg_n_pongs; ++i ) {
    rc = do_send(write_h, ppbuf, sz, 0);
    NT_TESTi3(rc, ==, sz);
  }
}


#ifdef USE_ZF
static void add_zocket(union handle h)
{
  /* In future we could add the options to put additional zocket types in
   * the mux set, but for now we only add the test zocket.
   */
  if( (cfg_n_pipe[0] > 0) || (cfg_n_unixd[0] > 0) || (cfg_n_udp[0] > 0) ||
      (cfg_n_tcpc[0] > 0) || (cfg_n_tcpl[0] > 0) ) {
    sfnt_err("ERROR: Cannot mix normal fds with zockets for muxing\n");
    sfnt_fail_setup();
  }

  if( zf_mux ) {
    struct epoll_event e;
    e.events = EPOLLIN;

    struct zf_waitable* w = NULL;  /* Initialise to placate compiler. */
    if( handle_type == HT_ZF_UDP ) {
      w = zfur_to_waitable(h.ur);
    }
    else if( handle_type == HT_ZF_TCP ) {
      w = zft_to_waitable(h.t);
    }
    else {
      sfnt_err("ERROR: Only UDP zockets supported for zf muxing currently\n");
      sfnt_fail_setup();
    }

    NT_TRY(zf_muxer_add(zf_mux, w, &e));
  }
}
#endif


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
  sfnt_sock_put_int(ss, handle_type);
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
  sfnt_sock_put_int(ss, cfg_timeout[1]);
  sfnt_sock_put_str(ss, cfg_affinity[1]);
  sfnt_sock_put_int(ss, cfg_n_pings);
  sfnt_sock_put_int(ss, cfg_n_pongs);
  sfnt_sock_put_int(ss, cfg_nodelay[1]);
  sfnt_sock_put_int(ss, cfg_zc[1]);
  sfnt_sock_put_int(ss, cfg_warm[1]);
  sfnt_sock_put_int(ss, cfg_tmpl_send[1]);
}


static void server_recv_opts(int ss)
{
  handle_type = sfnt_sock_get_int(ss);
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
  cfg_timeout[0] = sfnt_sock_get_int(ss);
  cfg_affinity[0] = sfnt_sock_get_str(ss);
  cfg_n_pings = sfnt_sock_get_int(ss);
  cfg_n_pongs = sfnt_sock_get_int(ss);
  cfg_nodelay[0] = sfnt_sock_get_int(ss);
  cfg_zc[0] = sfnt_sock_get_int(ss);
  cfg_warm[0] = sfnt_sock_get_int(ss);
  cfg_tmpl_send[0] = sfnt_sock_get_int(ss);
}


#ifdef USE_ZF
/* FIXME This is a temporary hack until we have cplane and port selection */
static void zf_udp_setup_addrs(int ss)
{
  socklen_t my_sa_len;
  my_sa_len = sizeof(my_sa);

  /* Use the same local interface as the setup socket */
  NT_TRY(getsockname(ss, (struct sockaddr*) &my_sa, &my_sa_len));
  my_sa.sin_port = 11111;

  /* Tell client our address, and get their's. */
  sfnt_sock_put_sockaddr_in(ss, &my_sa);
  sfnt_sock_get_sockaddr_in(ss, &peer_sa);

  to_sa = (struct sockaddr*) &peer_sa;
  to_sa_len = sizeof(peer_sa);
}


static void zf_tcp_accept(int ss, struct zft** zft_out)
{
  /* Use the same local interface as the setup socket */
  struct sockaddr_in sa;
  socklen_t sa_len = sizeof(sa);

  NT_TRY(getsockname(ss, (struct sockaddr*) &sa, &sa_len));
  sa.sin_port = 11111;

  struct zftl* listener;
  NT_TRY(zftl_listen(ztack, (struct sockaddr*) &sa, sa_len, zattr, &listener));

  sfnt_sock_put_int(ss, ntohs(sa.sin_port));

  while( zftl_accept(listener, zft_out) == -EAGAIN )
    while(zf_reactor_perform(ztack) == 0);

  NT_TRY(zftl_free(listener));
}


static int zf_tcp_connect(int ss, struct zft_handle* th,
                          const char* host_or_hostport, int port_i_or_neg,
                          struct zft** t_out)
{
  struct addrinfo* ai;
  int rc;

  if( (rc = sfnt_getaddrinfo(host_or_hostport, NULL, port_i_or_neg, &ai)) != 0 )
    return rc;

  /* Use the same local interface as the setup socket */
  struct sockaddr_in sa;
  socklen_t sa_len = sizeof(sa);
  NT_TRY(getsockname(ss, (struct sockaddr*) &sa, &sa_len));
  sa.sin_port = 11111;

  NT_TRY(zft_addr_bind(th, (struct sockaddr*) &sa, sa_len, 0));
  NT_TRY(zft_connect(th, ai->ai_addr, sa_len, t_out));

  /* Now wait for the connect to complete */
  struct epoll_event event = { .events = EPOLLOUT };
  struct zf_muxer_set* muxer;
  NT_TRY(zf_muxer_alloc(ztack, &muxer));
  NT_TRY(zf_muxer_add(muxer, zft_to_waitable(*t_out), &event));
  do {
    int events = zf_muxer_wait(muxer, &event, 1, -1);
    NT_TEST(events > 0);
  } while( ! (event.events & EPOLLOUT) );
  zf_muxer_del(zft_to_waitable(*t_out));
  zf_muxer_free(muxer);

  freeaddrinfo(ai);
  return rc;
}
#endif


#ifdef USE_DPDK
static void dpdk_udp_setup_addrs(int ss)
{
  struct addrinfo* ai;
  struct sockaddr_in* sa;
  int rc;
  NT_TEST( cfg_bind[0] );
  if( (rc = sfnt_getaddrinfo(cfg_bind[0], NULL, -1, &ai)) != 0 ) {
    sfnt_err("ERROR: Could not bind to '%s'\n", cfg_bind[0]);
    sfnt_err("ERROR: rc=%d errno=(%d %s) gai_strerror=(%s)\n",
             rc, errno, strerror(errno), gai_strerror(rc));
    sfnt_fail_setup();
  }

  NT_TEST( ai->ai_family == AF_INET );
  sa = ((struct sockaddr_in*)ai->ai_addr);
  my_sa.sin_family = AF_INET;
  my_sa.sin_addr.s_addr = sa->sin_addr.s_addr;
  my_sa.sin_port = sa->sin_port ? sa->sin_port : htons(11111);

  /* Tell client our address, and get their's. */
  sfnt_sock_put_sockaddr_in(ss, &my_sa);
  sfnt_sock_get_sockaddr_in(ss, &peer_sa);

  to_sa = (struct sockaddr*) &peer_sa;
  to_sa_len = sizeof(peer_sa);
}
#endif


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
  sfnt_sock_put_sockaddr_in(ss, &my_sa);
  sfnt_sock_get_sockaddr_in(ss, &peer_sa);

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


#if defined(__sun__)
static void set_sock_timeouts(int sock)
{
  /* we use SIGALRM on Solaris. See solaris_recv() */

  if( cfg_warm[0] ) {
    fprintf(stderr, "MSG_WARM not supported on Solaris\n");
    exit(1);
  }
  return;
}
#else
static void set_sock_timeouts(int sock)
{
  struct timeval tv = {0,0};
  if( cfg_timeout[0] ) {
    tv.tv_sec = cfg_timeout[0];
    tv.tv_usec = 0;
  }
  if( cfg_warm[0] ) {
    if( cfg_timeout[0] ) {
      fprintf(stderr, "MSG_WARM not supported with timeout\n");
      exit(1);
    }
    tv.tv_sec = cfg_warm[0] / 1000000;
    tv.tv_usec = cfg_warm[0] % 1000000;
  }
  if( tv.tv_sec || tv.tv_usec ) {
    NT_TRY(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)));
    NT_TRY(setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)));
  }
}
#endif


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
  union handle read_handle, write_handle;

  server_check_ver(ss);
  server_recv_opts(ss);
  sfnt_sock_put_str(ss, getenv("LD_PRELOAD"));

  /* Init after we've received config opts from client. */
  do_init();

  /* Create and bind/connect test socket. */
  switch( handle_type ) {
  case HT_TCP: {
    struct sockaddr_in sa;
    socklen_t sa_len = sizeof(sa);
    int one = 1;
    NT_TRY2(sl, socket(PF_INET, SOCK_STREAM, 0));
    if( cfg_bindtodev[0] )
      NT_TRY(sfnt_so_bindtodevice(sl, cfg_bindtodev[0]));
    NT_TRY(listen(sl, 1));
    NT_TRY(getsockname(sl, (struct sockaddr*) &sa, &sa_len));
    sfnt_sock_put_int(ss, ntohs(sa.sin_port));
    NT_TRY2(read_handle.fd, accept(sl, NULL, NULL));
    write_handle.fd = read_handle.fd;
    if( cfg_nodelay[0] )
      NT_TRY(setsockopt(write_handle.fd, SOL_TCP, TCP_NODELAY, &one,
                        sizeof(one)));
    close(sl);
    sl = -1;
    break;
  }
  case HT_UDP:
    NT_TRY2(read_handle.fd, socket(PF_INET, SOCK_DGRAM, 0));
    udp_bind_sock(read_handle.fd, ss);
    udp_exchange_addrs(read_handle.fd, ss);
    write_handle.fd = read_handle.fd;
    break;
  case HT_PIPE:
    read_handle.fd = the_fds[2];
    write_handle.fd = the_fds[1];
    if( cfg_spin[0] ) {
      sfnt_fd_set_nonblocking(read_handle.fd);
      sfnt_fd_set_nonblocking(write_handle.fd);
    }
    break;
  case HT_UNIX_S:
  case HT_UNIX_D:
    read_handle.fd = write_handle.fd = the_fds[1];
    break;
#ifdef USE_ZF
  case HT_ZF_UDP:
    zf_udp_setup_addrs(ss);
    NT_TRY(zfur_alloc(&read_handle.ur, ztack, zattr));
    NT_TRY(zfur_addr_bind(read_handle.ur,
                          (struct sockaddr*) &my_sa, sizeof(my_sa),
                          (struct sockaddr*) &peer_sa, sizeof(peer_sa), 0));
    NT_TRY(zfut_alloc(&write_handle.ut, ztack,
                      (struct sockaddr*) &my_sa, sizeof(my_sa),
                      (struct sockaddr*) &peer_sa, sizeof(peer_sa), 0, zattr));
    break;
  case HT_ZF_TCP:
    if( cfg_bindtodev[0] || cfg_nodelay[0] ) {
      sfnt_err("ERROR: %s not supported with zockets",
               cfg_bindtodev[0] ? "--bindtodev" : "--nodelay");
      sfnt_fail_setup();
    }

    zf_tcp_accept(ss, &read_handle.t);
    write_handle.t = read_handle.t;
    break;
#endif
#ifdef USE_DPDK
  case HT_DPDK_UDP:
    dpdk_udp_setup_addrs(ss);
    break;
#endif
  default:
    NT_ASSERT(0);
  }
  if( handle_type & HTF_SOCKET )
    set_sock_timeouts(read_handle.fd);

#ifdef USE_ZF
  if( handle_type & HTF_ZF )
    add_zocket(read_handle);
  else
#endif
    add_fds(read_handle.fd);

  do_zc_init(write_handle.fd);


  printf("Server ready to start - informing client\n");
  sfnt_sock_put_int(ss,42);

  while( 1 ) {
    iter = sfnt_sock_get_int(ss);
    if( iter == 0 )
      break;
    msg_size = sfnt_sock_get_int(ss);

    if( cfg_tmpl_send[0] != -1 ) {
      tmpl_update_size = msg_size * cfg_tmpl_send[0] / 100;
      do_tmpl_alloc(read_handle.fd, ppbuf, msg_size, 0);
    }
    while( iter-- )
      do_pong(read_handle, write_handle, msg_size);
    if( cfg_tmpl_send[0] != -1 )
      do_tmpl_abort(write_handle.fd);
  }

  NT_TESTi3(recv(ss, ppbuf, 1, 0), ==, 0);

  return 0;
}


static void do_pings(int ss, union handle read_h, union handle write_h,
                     int msg_size, int iter, int* results)
{
  uint64_t start, stop;
  unsigned time_cnt = 0;
  int i;
  char buf[1];

  sfnt_sock_put_int(ss, iter + 1); /* +1 as initial ping  below */
  sfnt_sock_put_int(ss, msg_size);
  if( cfg_tmpl_send[0] != -1 ) {
    do_tmpl_alloc(read_h.fd, ppbuf, msg_size, 0);
    tmpl_update_size = msg_size * cfg_tmpl_send[0] / 100;
  }

  /* Touch to ensure resident. */
  memset(results, 0, iter * sizeof(results[0]));

  /* Ensure server is ready. */
  do_ping(read_h, write_h, msg_size);

  for( i = 0; i < iter; ++i ) {
    sfnt_tsc(&start);
    do_ping(read_h, write_h, msg_size);
    sfnt_tsc(&stop);
    results[i] = (int) sfnt_tsc_nsec(&tsc, stop - start - tsc.tsc_cost);
    if( ! cfg_rtt )
      results[i] /= 2;
    if( cfg_sleep_gap )
      usleep(cfg_sleep_gap);
    if( cfg_spin_gap ) {
      if( cfg_warm[0] ) {
        time_cnt = 0;
        for(time_cnt = 0; time_cnt < cfg_spin_gap; time_cnt += cfg_warm[0] ) {
          sfnt_tsc_usleep(&tsc, cfg_warm[0]);
          NT_TRY(send(write_h.fd, buf, 1, ONLOAD_MSG_WARM));
        }
      }
      else {
        sfnt_tsc_usleep(&tsc, cfg_spin_gap);
      }
    }
  }
  if( cfg_tmpl_send[0] != -1 )
    do_tmpl_abort(write_h.fd);
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


static void do_test(int ss, union handle read_handle, union handle write_handle,
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

    /* n_this_time can be 0 if minms not yet met */
    do_pings(ss, read_handle, write_handle, msg_size,
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
  if( handle_type & HTF_STREAM )
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
  const char* handle_type_s;
  pid_t pid;

  if( argc < 1 || argc > 2 )
    sfnt_fail_usage("wrong number of arguments");
  handle_type_s = argv[0];
  if( ! strcasecmp(handle_type_s, "tcp") )
    handle_type = HT_TCP;
  else if( ! strcasecmp(handle_type_s, "udp") )
    handle_type = HT_UDP;
  else if( ! strcasecmp(handle_type_s, "pipe") )
    handle_type = HT_PIPE;
  else if( ! strcasecmp(handle_type_s, "unix_stream") )
    handle_type = HT_UNIX_S;
  else if( ! strcasecmp(handle_type_s, "unix_datagram") )
    handle_type = HT_UNIX_D;
  else if( ! strcasecmp(handle_type_s, "zf_udp") )
    handle_type = HT_ZF_UDP;
  else if( ! strcasecmp(handle_type_s, "zf_tcp") )
    handle_type = HT_ZF_TCP;
  else if( ! strcasecmp(handle_type_s, "dpdk_udp") )
    handle_type = HT_DPDK_UDP;
  else
    sfnt_fail_usage("unknown handle_type '%s'", handle_type_s);

  if( handle_type & HTF_LOCAL ) {
    int ss[2];
    if( argc != 1 )
      sfnt_fail_usage("wrong number of arguments for local socket");
    switch( handle_type ) {
    case HT_PIPE:
      NT_TRY(pipe(the_fds));
      NT_TRY(pipe(the_fds + 2));
      break;
    case HT_UNIX_S:
      NT_TRY(socketpair(PF_UNIX, SOCK_STREAM, 0, the_fds));
      break;
    case HT_UNIX_D:
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
  union handle read_h, write_h;
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

  if( cfg_warm[0] != 0 && cfg_spin_gap == 0 )
    sfnt_fail_usage("ERROR: --warm must be used with --spin-gap option");

  if( cfg_warm[0] != 0 && cfg_warm[0] >= cfg_spin_gap )
    sfnt_fail_usage("ERROR: it doesn't make sense for --warm to be larger "
                    "than or equal to --spin-gap option");

  client_send_opts(ss);
  server_ld_preload = sfnt_sock_get_str(ss);

  /* Create and bind/connect test socket. */
  switch( handle_type ) {
  case HT_TCP: {
    char host[strlen(hostport) + 1];
    char* p;
    strcpy(host, hostport);
    if( (p = strchr(host, ':')) != NULL )
      *p = '\0';
    int port = sfnt_sock_get_int(ss);
    NT_TRY2(read_h.fd, socket(PF_INET, SOCK_STREAM, 0));
    if( cfg_nodelay[0] )
      NT_TRY(setsockopt(read_h.fd, SOL_TCP, TCP_NODELAY, &one, sizeof(one)));
    NT_TRY(sfnt_connect(read_h.fd, host, NULL, port));
    write_h.fd = read_h.fd;
    break;
  }
  case HT_UDP:
    NT_TRY2(read_h.fd, socket(PF_INET, SOCK_DGRAM, 0));
    udp_bind_sock(read_h.fd, ss);
    udp_exchange_addrs(read_h.fd, ss);
    write_h.fd = read_h.fd;
    break;
  case HT_PIPE:
    read_h.fd = the_fds[0];
    write_h.fd = the_fds[3];
    if( cfg_spin[0] ) {
      sfnt_fd_set_nonblocking(read_h.fd);
      sfnt_fd_set_nonblocking(write_h.fd);
    }
    break;
  case HT_UNIX_S:
  case HT_UNIX_D:
    read_h.fd = write_h.fd = the_fds[0];
    break;
#ifdef USE_ZF
  case HT_ZF_UDP:
    zf_udp_setup_addrs(ss);
    NT_TRY(zfur_alloc(&read_h.ur, ztack, zattr));
    NT_TRY(zfur_addr_bind(read_h.ur, (struct sockaddr*) &my_sa, sizeof(my_sa),
                          (struct sockaddr*) &peer_sa, sizeof(peer_sa), 0));
    NT_TRY(zfut_alloc(&write_h.ut, ztack,
                      (struct sockaddr*) &my_sa, sizeof(my_sa),
                      (struct sockaddr*) &peer_sa, sizeof(peer_sa), 0, zattr));
    break;
  case HT_ZF_TCP: {
    if( cfg_bindtodev[0] || cfg_nodelay[0] ) {
      sfnt_err("ERROR: %s not supported with zockets",
               cfg_bindtodev[0] ? "--bindtodev" : "--nodelay");
      sfnt_fail_setup();
    }

    char host[strlen(hostport) + 1];
    char* p;
    strcpy(host, hostport);
    if( (p = strchr(host, ':')) != NULL )
      *p = '\0';
    int port = sfnt_sock_get_int(ss);

    struct zft_handle* th;
    NT_TRY(zft_alloc(ztack, zattr, &th));
    NT_TRY(zf_tcp_connect(ss, th, host, port, &read_h.t));
    write_h.t = read_h.t;
    break;
  }
#endif
#ifdef USE_DPDK
  case HT_DPDK_UDP: {
    dpdk_udp_setup_addrs(ss);
    break;
  }
#endif
  default:
    NT_ASSERT(0);
  }
  if( handle_type & HTF_SOCKET )
    set_sock_timeouts(read_h.fd);

#ifdef USE_ZF
  /* For zf we can't mux between normal fds and zockets */
  if( handle_type & HTF_ZF )
    add_zocket(read_h);
  else
#endif
    add_fds(read_h.fd);

  results = malloc(cfg_maxiter * sizeof(*results));
  NT_TEST(results != NULL);
  sfnt_dump_sys_info(&tsc);
  if( server_ld_preload != NULL )
    printf("# server LD_PRELOAD=%s\n", server_ld_preload);
  printf("# percentile=%g\n", (double) cfg_percentile);
  printf("#\n");
  printf("#\tsize\tmean\tmin\tmedian\tmax\t%%ile\tstddev\titer\n");
  fflush(stdout);

  do_zc_init(write_h.fd);

  if( handle_type & HTF_STREAM ) {
    if( cfg_minmsg == 0 )
      cfg_minmsg = 1;
    if( cfg_maxmsg == 0 )
      cfg_maxmsg = 64 * 1024;
  }
  else if( handle_type & HTF_DPDK ) {
    if( cfg_maxmsg == 0 )
      cfg_maxmsg = 1472;
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

  /* Client side ready - will start after signal from server */
  i = sfnt_sock_get_int(ss);

  for( i = 0; i < msg_sizes.len; ++i )
    do_test(ss, read_h, write_h, msg_sizes.list[i], results);

  /* Tell server side to exit. */
  sfnt_sock_put_int(ss, 0);

  return 0;
}


int main(int argc, char* argv[])
{
  pid_t pid = 0;
  int rc = 0;

  sfnt_app_getopt("[tcp|udp|pipe|unix_stream|unix_datagram|zf_udp|zf_tcp|"
                  "dpdk_udp [host[:port]]]",
                &argc, argv, cfg_opts, N_CFG_OPTS);
  --argc; ++argv;

  if( cfg_miniter > cfg_maxiter )
    cfg_maxiter = cfg_miniter;
  if( cfg_minms > cfg_maxms )
    cfg_maxms = cfg_minms;
  NT_ASSERT(cfg_maxiter >= cfg_miniter);
  timeout_ms = cfg_timeout[0] ? cfg_timeout[0] * 1000 : -1;

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
