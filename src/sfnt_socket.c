/**************************************************************************\
*    Filename: sfnt_socket.c
*      Author: David Riddoch <driddoch@solarflare.com>
* Description: Socket convenience routines.
*   Copyright: (C) 2005-2011 Solarflare Communications Inc.
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
      strncpy(str, host, sizeof(str));
      host = str;
      strrchr(host, ':')[0] = '\0';
      ++port;
    }
    else {
      sprintf(str, "0");
      port = str;
    }
  }

  hints.ai_flags = AI_NUMERICSERV;
  hints.ai_family = AF_INET;
  hints.ai_socktype = 0;
  hints.ai_protocol = 0;
  hints.ai_addrlen = 0;
  hints.ai_addr = NULL;
  hints.ai_canonname = NULL;
  hints.ai_next = NULL;
  return getaddrinfo(host, port, &hints, ai_out);
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
                             port_i_or_neg, &ai)) < 0 )
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
                             port_i_or_neg, &ai)) < 0 )
    return rc;
  rc = connect(sock, ai->ai_addr, ai->ai_addrlen);
  freeaddrinfo(ai);
  return rc;
}


int sfnt_so_bindtodevice(int sock, const char* dev_name)
{
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev_name);
  return setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr));
}


int sfnt_ip_multicast_if(int sock, const char* intf)
{
  struct addrinfo* ai;
  struct ip_mreqn r;
  int rc;

  memset(&r, 0, sizeof(r));

  if( (rc = if_nametoindex(intf)) != 0 ) {
    r.imr_ifindex = rc;
  }
  else if( (rc = sfnt_getaddrinfo(intf, NULL, 0, &ai)) == 0 ) {
    r.imr_address = ((struct sockaddr_in*) ai->ai_addr)->sin_addr;
    freeaddrinfo(ai);
  }
  else
    return rc;

  return setsockopt(sock, SOL_IP, IP_MULTICAST_IF, &r, sizeof(r));
}


int sfnt_ip_add_membership(int sock, in_addr_t mcast_addr, const char* intf)
{
  struct addrinfo* ai;
  struct ip_mreqn r;
  int rc;

  memset(&r, 0, sizeof(r));
  r.imr_multiaddr.s_addr = mcast_addr;

  if( intf != NULL ) {
    if( (rc = if_nametoindex(intf)) != 0 ) {
      r.imr_ifindex = rc;
    }
    else if( (rc = sfnt_getaddrinfo(intf, NULL, 0, &ai)) == 0 ) {
      r.imr_address = ((struct sockaddr_in*) ai->ai_addr)->sin_addr;
      freeaddrinfo(ai);
    }
    else
      return rc;
  }

  return setsockopt(sock, SOL_IP, IP_ADD_MEMBERSHIP, &r, sizeof(r));
}


void sfnt_sock_put_int(int fd, int v)
{
  int32_t v32 = NT_LE32(v);
  NT_TEST(send(fd, &v32, sizeof(v32), 0) == sizeof(v32));
}


int sfnt_sock_get_int(int fd)
{
  int32_t v32;
  NT_TEST(recv(fd, &v32, sizeof(v32), MSG_WAITALL) == sizeof(v32));
  return NT_LE32(v32);
}


void  sfnt_sock_put_str(int fd, const char* str)
{
  if( str != NULL ) {
    int len = strlen(str) + 1;
    sfnt_sock_put_int(fd, len);
    NT_TEST(send(fd, str, len, 0) == len);
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
  NT_TEST(recv(fd, str, len, MSG_WAITALL) == len);
  NT_TEST(str[len - 1] == '\0');
  return str;
}
