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


#ifndef MSG_MORE
#define MSG_MORE
#endif


static void error_unknown_address_family(int family)
{
  /* Higher-level code should already have ensured that this can't happen. */
  sfnt_err("INTERNAL ERROR: unsupported address family %d\n", family);
  sfnt_abort();
}


/* Decode browser-style host and port specifiers.
 * On return populates supplied pointers with bare host and port strings
 * or NULL where not specified in input. Uses the supplied buffer if
 * necessary, which must survive use of the returned strings.
 */
static int decode_hostport(char *str, size_t str_sz,
                           const char *host,
                           const char **host_found, const char **port_found)
{
  const char* port = NULL;
  const char* firstcolon = NULL;
  const char* lastcolon = NULL;
  const char* percent = NULL;
  const char* closesquare = NULL;

  if( host ) {
    firstcolon = strchr(host, ':');
    lastcolon = strrchr(host, ':');
    percent = strchr(host, '%');
    closesquare = strchr(host, ']');
  }

  /* strings we want to parse:
   * 1.2.3.4
   * 1.2.3.4:1234
   * ffff::ffff
   * ffff::ffff%eth0
   * ffff::ffff%eth0:1234
   * [ffff::ffff]:1234
   * dellr630a
   * dellr630a:1234
   */

  /* Handle a specified port */
  if( lastcolon &&
      (firstcolon == lastcolon ||
       (percent && lastcolon > percent) ||
       (closesquare && closesquare < lastcolon)) ) {
    int hostlen = lastcolon - host;
    if( hostlen >= str_sz )
      return EAI_OVERFLOW;
    strncpy(str, host, hostlen);
    str[hostlen] = '\0';
    host = str;
    port = lastcolon + 1;
  }

  /* Strip square brackets */
  if( host && host[0] == '[' && host[strlen(host) - 1] == ']' ) {
    if( host != str ) {
      if( strlen(host) >= str_sz )
	return EAI_OVERFLOW;
      strcpy(str, host);
    }
    str[strlen(str) - 1] = '\0';
    host = str + 1;
  }

  *port_found = port;
  *host_found = host;
  return 0;
}


int sfnt_getaddrinfo(int hint_af, const char* host, const char* port,
                     int port_i, struct addrinfo** ai_out)
{
  const char *default_port = port;
  struct addrinfo hints;
  char strport[11];
  char str[256];
  int rc;

  rc = decode_hostport(str, sizeof(str), host, &host, &port);
  if (rc != 0)
    return rc;

  if( default_port == NULL ) {
    if( port_i >= 0 ) {
      sprintf(strport, "%d", port_i);
      port = strport;
    }
  } else
    port = default_port;

  hints.ai_flags = AI_PASSIVE; 
  hints.ai_family = hint_af;
  hints.ai_socktype = 0;
  hints.ai_protocol = IPPROTO_TCP;  /* Solaris compatability */
  hints.ai_addrlen = 0;
  hints.ai_addr = NULL;
  hints.ai_canonname = NULL;
  hints.ai_next = NULL;
  return getaddrinfo(host, port, &hints, ai_out);
}


int sfnt_getendpointinfo(int hint_af, const char* host, int default_port,
                         struct addrinfo** ai_out)
{
  struct addrinfo hints;
  const char* port;
  char strport[11];
  char str[256];
  int rc;

  rc = decode_hostport(str, sizeof(str), host, &host, &port);
  if (rc != 0)
    return rc;

  if( port == NULL ) {
    port = strport;
    sprintf(strport, "%d", default_port);
  }

  hints.ai_flags = AI_PASSIVE;
  hints.ai_family = hint_af;
  hints.ai_socktype = 0;
  hints.ai_protocol = IPPROTO_TCP;  /* Solaris compatability */
  hints.ai_addrlen = 0;
  hints.ai_addr = NULL;
  hints.ai_canonname = NULL;
  hints.ai_next = NULL;
  return getaddrinfo(host, port, &hints, ai_out);
}


socklen_t sfnt_getendpoint(int hint_af, const char* host, int default_port,
                           struct sockaddr *addr, socklen_t addrlen)
{
  struct addrinfo *ai;

  NT_TRY_GAI(sfnt_getendpointinfo(hint_af, host, default_port, &ai));
  NT_ASSERT(ai->ai_addrlen <= addrlen);
  addrlen = ai->ai_addrlen;
  memcpy(addr, ai->ai_addr, addrlen);
  freeaddrinfo(ai);

  return addrlen;
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


int sfnt_bind_port(int sock, int af, int port)
{
  if( af == AF_INET6 ) {
    struct sockaddr_in6 sa;
    struct in6_addr any = IN6ADDR_ANY_INIT;
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons((uint16_t) port);
    sa.sin6_addr = any;
    return bind(sock, (struct sockaddr*) &sa, sizeof(sa));
  }
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

  if( (rc = sfnt_getaddrinfo(AF_UNSPEC, host_or_hostport, port_or_null,
                             port_i_or_neg, &ai)) != 0 )
    return rc;
  rc = bind(sock, ai->ai_addr, ai->ai_addrlen);
  freeaddrinfo(ai);

  /* Present any error in getaddrinfo style; EAI_SYSTEM => look at errno */
  return rc < 0 ? EAI_SYSTEM : rc;
}


int sfnt_connect(int sock, const char* host_or_hostport,
                 const char* port_or_null, int port_i_or_neg)
{
  struct addrinfo* ai;
  int rc;

  if( (rc = sfnt_getaddrinfo(AF_INET, host_or_hostport, port_or_null,
                             port_i_or_neg, &ai)) != 0 )
    return rc;
  rc = connect(sock, ai->ai_addr, ai->ai_addrlen);
  freeaddrinfo(ai);

  /* Present any error in getaddrinfo style; EAI_SYSTEM => look at errno */
  return rc < 0 ? EAI_SYSTEM : rc;
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


int sfnt_ip_multicast_if(int sock, int af, const char* intf)
{
  int rc;

  /* Any errors are presented in getaddrinfo style where a return code
     of EAI_SYSTEM means look at the errno. */

  if( af == AF_INET6 ) {
    int ifindex;

    ifindex = if_nametoindex(intf);
    if( ifindex == 0 )
      rc = -1;
    else
      rc = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex,
                      sizeof(ifindex));
    return rc < 0 ? EAI_SYSTEM : rc;
  }
  else {
    struct addrinfo* ai;
    struct in_addr sin;
#if NT_HAVE_IP_MREQN
    struct ip_mreqn r;
#endif

    memset(&sin, 0, sizeof(sin));

#if NT_HAVE_IP_MREQN
    memset(&r, 0, sizeof(r));

    if( (rc = if_nametoindex(intf)) != 0 ) {
      r.imr_ifindex = rc;
    } else
    /* note hanging else */
#endif
    {
      rc = sfnt_getaddrinfo(AF_INET, intf, NULL, 0, &ai);
      if (rc == 0) {
        sin = ((struct sockaddr_in*) ai->ai_addr)->sin_addr;
        freeaddrinfo(ai);
      } else
        return rc;
    }

#if NT_HAVE_IP_MREQN
    r.imr_address = sin;
    rc = setsockopt(sock, SOL_IP, IP_MULTICAST_IF, &r, sizeof(r));
#else
    rc = setsockopt(sock, SOL_IP, IP_MULTICAST_IF, &sin, sizeof(sin));
#endif
    return rc < 0 ? EAI_SYSTEM : rc;
  }
}


int sfnt_ip_add_membership(int sock, int af, const char* mcast_addr,
                           const char* intf)
{
  int rc;

  /* Any errors are presented in getaddrinfo style where a return code
     of EAI_SYSTEM means look at the errno. */

  if( af == AF_INET6 ) {
    struct ipv6_mreq r;
    if( intf != NULL ) {
      r.ipv6mr_interface = if_nametoindex(intf);
      if( r.ipv6mr_interface == 0 )
        return EAI_SYSTEM;
    }

    inet_pton(af, mcast_addr, &r.ipv6mr_multiaddr);
    rc = setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &r, sizeof(r));
    return rc < 0 ? EAI_SYSTEM : rc;
  }
  else {
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
      {
        rc = sfnt_getaddrinfo(AF_INET, intf, NULL, 0, &ai);
        if (rc == 0) {
          sin = ((struct sockaddr_in*) ai->ai_addr)->sin_addr;
          freeaddrinfo(ai);
        } else
          return rc;
      }
    }

    r.imr_multiaddr.s_addr = inet_addr(mcast_addr);
#if NT_HAVE_IP_MREQN
    r.imr_address = sin;
#else
    r.imr_interface = sin;
#endif
    rc = setsockopt(sock, SOL_IP, IP_ADD_MEMBERSHIP, &r, sizeof(r));
    return rc < 0 ? EAI_SYSTEM : rc;
  }
}


int sfnt_sock_set_timeout(int sock, int send_or_recv, int millisec)
{
#ifdef _WIN32
  DWORD optval = (DWORD)millisec;
  return setsockopt(sock, SOL_SOCKET, send_or_recv, (void*)&optval,
                    sizeof(optval));
#else
  struct timeval tv;
  tv.tv_sec = millisec / 1000;
  tv.tv_usec = (millisec % 1000) * 1000;
  return setsockopt(sock, SOL_SOCKET, send_or_recv, &tv, sizeof(tv));
#endif
}


extern int sfnt_sock_cork(int fd)
{
#ifdef TCP_CORK
  int one = 1;
  return setsockopt(fd, IPPROTO_TCP, TCP_CORK, &one, sizeof(one));
#else
  /* Corking isn't used for testing purposes: only for Nagle-avoidance during
   * setup */
  return -1;
#endif
}


extern int sfnt_sock_uncork(int fd)
{
#ifdef TCP_CORK
  int zero = 0;
  return setsockopt(fd, IPPROTO_TCP, TCP_CORK, &zero, sizeof(zero));
#else
  return -1;
#endif
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
    int32_t v32 = NT_LE32(len);
    NT_TESTi3(send(fd, &v32, sizeof(v32), MSG_MORE), ==, sizeof(v32));
    NT_TESTi3(send(fd, str, len, 0), ==, len);
  }
  else {
    sfnt_sock_put_int(fd, 0);
  }
}


char* sfnt_sock_get_str(int fd)
{
  char* str;
  int len;
  len = sfnt_sock_get_int(fd);
  if( len == 0 )
    return NULL;
  NT_TEST(len > 0);
  str = malloc(len);
  NT_TESTi3(recv(fd, str, len, MSG_WAITALL), ==, len);
  NT_TESTi3(str[len - 1], == ,'\0');
  return str;
}


void sfnt_sock_put_sockaddr(int fd, const struct sockaddr_storage* ss)
{
  /* sin_family is in host byte order so send in little endian,
     sin_port and sin_addr are already in network order so send as
     is */
  int family = NT_LE32(ss->ss_family);
  NT_TEST(send(fd, &family, sizeof(family), MSG_MORE) == sizeof(family));
  switch( family ) {
  case PF_INET: {
    const struct sockaddr_in* sa = (const struct sockaddr_in*)ss;
    NT_TEST(send(fd, &sa->sin_port, sizeof(sa->sin_port), MSG_MORE) ==
            sizeof(sa->sin_port));
    NT_TEST(send(fd, &sa->sin_addr, sizeof(sa->sin_addr), 0) ==
            sizeof(sa->sin_addr));
    break;
  }
  case PF_INET6: {
    const struct sockaddr_in6* sa = (const struct sockaddr_in6*)ss;
    NT_TEST(send(fd, &sa->sin6_port, sizeof(sa->sin6_port), MSG_MORE) ==
            sizeof(sa->sin6_port));
    NT_TEST(send(fd, &sa->sin6_addr, sizeof(sa->sin6_addr), 0) ==
            sizeof(sa->sin6_addr));
    break;
  }
  default:
    error_unknown_address_family(family);
    break;
  }
}


void sfnt_sock_get_sockaddr(int fd, struct sockaddr_storage* ss)
{
  /* Look at comments in sfnt_sock_put_sockaddr */
  int family;
  NT_TEST(recv(fd, &family, sizeof(family), MSG_WAITALL) == sizeof(family));
  ss->ss_family = NT_LE32(family);
  switch( family ) {
  case PF_INET: {
    struct sockaddr_in* sa = (struct sockaddr_in*)ss;
    NT_TEST(recv(fd, &sa->sin_port, sizeof(sa->sin_port), MSG_WAITALL) ==
            sizeof(sa->sin_port));
    NT_TEST(recv(fd, &sa->sin_addr, sizeof(sa->sin_addr), MSG_WAITALL) ==
            sizeof(sa->sin_addr));
    break;
  }
  case PF_INET6: {
    struct sockaddr_in6* sa = (struct sockaddr_in6*)ss;
    NT_TEST(recv(fd, &sa->sin6_port, sizeof(sa->sin6_port), MSG_WAITALL) ==
            sizeof(sa->sin6_port));
    NT_TEST(recv(fd, &sa->sin6_addr, sizeof(sa->sin6_addr), MSG_WAITALL) ==
            sizeof(sa->sin6_addr));
    break;
  }
  default:
    error_unknown_address_family(family);
    break;
  }
}
