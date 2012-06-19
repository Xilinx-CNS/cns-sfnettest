/**************************************************************************\
*    Filename: sfnt_socket.c
*      Author: David Riddoch <driddoch@solarflare.com>
* Description: Socket convenience routines.
*   Copyright: (C) 2005-2012 Solarflare Communications Inc.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License version 2 as published
* by the Free Software Foundation, incorporated herein by reference.
\**************************************************************************/

#include "sfnettest.h"
#ifdef __unix__
# include <net/if.h>
#endif


int sfnt_getaddrinfo(const char* host, const char* port, int port_i,
                     struct addrinfo** ai_out)
{
  struct addrinfo hints;
  char str[256];

  if( port == NULL ) {
    if( port_i >= 0 ) {
      sprintf(str, "%d", port_i);
      port = str;
    }
    else if( (port = strrchr(host, ':')) != NULL ) {
      NT_ASSERT(sizeof(str) > (port - host));
      strcpy(str, host);
      str[port - host] = '\0';
      host = str;
      ++port;
      if( host[0] == '\0' )
        host = NULL;
    }
    else {
      sprintf(str, "0");
      port = str;
    }
  }

  hints.ai_flags = AI_PASSIVE; 
  hints.ai_family = AF_INET; /* not AF_INET6 */
  hints.ai_socktype = 0;
  hints.ai_protocol = IPPROTO_TCP;  /* Solaris compatability */
  hints.ai_addrlen = 0;
  hints.ai_addr = NULL;
  hints.ai_canonname = NULL;
  hints.ai_next = NULL;
  return getaddrinfo(host, port, &hints, ai_out);
}


int sfnt_get_port(int sock)
{
  struct sockaddr_storage sas;
  struct sockaddr* sa = (void*) &sas;
  socklen_t sa_len = sizeof(sas);
  int rc;
  if( (rc = getsockname(sock, sa, &sa_len)) < 0 )
    return rc;
  switch( sa->sa_family ) {
  case AF_INET:
    return ntohs(((struct sockaddr_in*) sa)->sin_port);
  case AF_INET6:
    return ntohs(((struct sockaddr_in6*) sa)->sin6_port);
  default:
    errno = ENOPROTOOPT;
    return -1;
  }
}


int sfnt_bind_port(int sock, int port)
{
  struct sockaddr_in sa;
  sa.sin_family = AF_INET;
  sa.sin_port = htons((uint16_t) port);
  sa.sin_addr.s_addr = htonl(INADDR_ANY);
  return bind(sock, (struct sockaddr*) &sa, sizeof(sa));
}


int sfnt_bind(int sock, const char* host_or_hostport,
              const char* port_or_null, int port_i_or_neg)
{
  struct addrinfo* ai;
  int rc;

  if( (rc = sfnt_getaddrinfo(host_or_hostport, port_or_null,
                             port_i_or_neg, &ai)) != 0 )
    return rc;
  rc = bind(sock, ai->ai_addr, ai->ai_addrlen);
  freeaddrinfo(ai);
  return rc;
}


int sfnt_connect(int sock, const char* host_or_hostport,
                 const char* port_or_null, int port_i_or_neg)
{
  struct addrinfo* ai;
  int rc;

  if( (rc = sfnt_getaddrinfo(host_or_hostport, port_or_null,
                             port_i_or_neg, &ai)) != 0 )
    return rc;
  rc = connect(sock, ai->ai_addr, ai->ai_addrlen);
  freeaddrinfo(ai);
  return rc;
}


#if NT_HAVE_SO_BINDTODEVICE
int sfnt_so_bindtodevice(int sock, const char* dev_name)
{
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev_name);
  return setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr));
}
#else
int sfnt_so_bindtodevice(int sock, const char* dev_name)
{
  sfnt_err("ERROR: SO_BINDTODEVICE requested but not supported on this "
	   "platform\n");
  sfnt_fail_test();
  /* never reached */
  return -1;
}
#endif


int sfnt_ip_multicast_if(int sock, const char* intf)
{
  struct addrinfo* ai;
  struct in_addr sin;
#if NT_HAVE_IP_MREQN
  struct ip_mreqn r;
#else
  struct ip_mreq r;
#endif
  int rc;

  memset(&r, 0, sizeof(r));
  memset(&sin, 0, sizeof(sin));

#if NT_HAVE_IP_MREQN
  if( (rc = if_nametoindex(intf)) != 0 ) {
    r.imr_ifindex = rc;
  } else
  /* note hanging else */
#endif
  if( (rc = sfnt_getaddrinfo(intf, NULL, 0, &ai)) == 0 ) {
    sin = ((struct sockaddr_in*) ai->ai_addr)->sin_addr;
    freeaddrinfo(ai);
  }
  else
    return rc;

#if NT_HAVE_IP_MREQN
  r.imr_address = sin;
  return setsockopt(sock, SOL_IP, IP_MULTICAST_IF, &r, sizeof(r));
#else
  return setsockopt(sock, SOL_IP, IP_MULTICAST_IF, &sin, sizeof(sin));  
#endif
}


int sfnt_ip_add_membership(int sock, in_addr_t mcast_addr, const char* intf)
{
  struct addrinfo* ai;
  struct in_addr sin;
#if NT_HAVE_IP_MREQN
  struct ip_mreqn r;
#else
  struct ip_mreq r;
#endif
  int rc;

  memset(&r, 0, sizeof(r));
  memset(&sin, 0, sizeof(sin));
  
  if( intf != NULL ) {
#if NT_HAVE_IP_MREQN
    if( (rc = if_nametoindex(intf)) != 0 ) {
      r.imr_ifindex = rc;
    } else
    /* note hanging else */
#endif
    if( (rc = sfnt_getaddrinfo(intf, NULL, 0, &ai)) == 0 ) {
      sin = ((struct sockaddr_in*) ai->ai_addr)->sin_addr;
      freeaddrinfo(ai);
    }
    else
      return rc;
  }

  r.imr_multiaddr.s_addr = mcast_addr;
#if NT_HAVE_IP_MREQN
  r.imr_address = sin;
#else
  r.imr_interface = sin;
#endif
  return setsockopt(sock, SOL_IP, IP_ADD_MEMBERSHIP, &r, sizeof(r));
}


int sfnt_sock_set_timeout(int sock, int send_or_recv, int millisec)
{
  struct timeval tv;
  tv.tv_sec = millisec / 1000;
  tv.tv_usec = (millisec % 1000) * 1000;
  return setsockopt(sock, SOL_SOCKET, send_or_recv, &tv, sizeof(tv));
}


void sfnt_sock_put_int(int fd, int v)
{
  int32_t v32 = NT_LE32(v);
  NT_TESTi3(send(fd, &v32, sizeof(v32), 0), ==, sizeof(v32));
}


int sfnt_sock_get_int(int fd)
{
  int32_t v32;
  NT_TESTi3(recv(fd, &v32, sizeof(v32), MSG_WAITALL), ==, sizeof(v32));
  return NT_LE32(v32);
}


void  sfnt_sock_put_str(int fd, const char* str)
{
  if( str != NULL ) {
    int len = strlen(str) + 1;
    sfnt_sock_put_int(fd, len);
    NT_TESTi3(send(fd, str, len, 0), ==, len);
  }
  else {
    sfnt_sock_put_int(fd, 0);
  }
}


char* sfnt_sock_get_str(int fd)
{
  char* str;
  int len = sfnt_sock_get_int(fd);
  if( len == 0 )
    return NULL;
  NT_TEST(len > 0);
  str = malloc(len);
  NT_TESTi3(recv(fd, str, len, MSG_WAITALL), ==, len);
  NT_TESTi3(str[len - 1], == ,'\0');
  return str;
}
