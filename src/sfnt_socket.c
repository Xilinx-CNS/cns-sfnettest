#include "sfnettest.h"
#ifdef __unix__
# include <net/if.h>
#endif


int sfnt_getaddrinfo(const char* host, const char* port, struct addrinfo**ai_out)
{
  struct addrinfo hints;
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


int sfnt_connect(int sock, const char* hostport, int default_port)
{
  struct addrinfo* ai;
  char host[256];
  char* port;
  int rc;

  NT_ASSERT(strlen(hostport) < sizeof(host) - 20);
  strcpy(host, hostport);
  if( (port = strchr(host, ':')) == NULL )
    sprintf((port = host + strlen(host)), ":%d", default_port);
  *port = '\0';
  ++port;

  if( (rc = sfnt_getaddrinfo(host, port, &ai)) < 0 )
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
  else if( (rc = sfnt_getaddrinfo(intf, NULL, &ai)) == 0 ) {
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
    else if( (rc = sfnt_getaddrinfo(intf, NULL, &ai)) == 0 ) {
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
  int len = strlen(str) + 1;
  sfnt_sock_put_int(fd, len);
  NT_TEST(send(fd, str, len, 0) == len);
}


char* sfnt_sock_get_str(int fd)
{
  int len = sfnt_sock_get_int(fd);
  char* str = malloc(len);
  NT_TEST(recv(fd, str, len, MSG_WAITALL) == len);
  NT_TEST(str[len - 1] == '\0');
  return str;
}
