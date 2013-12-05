/* socket.cpp
 *
 * BSD socket interface code...
 */

/* Copyright (c) 2002-2006 Nominum, Inc.   All rights reserved.
 *
 * Copyright (c) 1995-2002 Internet Software Consortium.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Nominum, Internet Software Consortium nor the
 *    names of its contributors may be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY NOMINUM, THE INTERNET SOFTWARE
 * CONSORTIUM AND CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL NOMINUM, THE INTERNET SOFTWARE CONSORTIUM OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef lint
static char copyright[] __attribute__((unused)) =
  "$Id: socket.cpp,v 1.13 2012/04/01 21:26:34 mellon Exp $ Copyright (c) 2005-2006 Nominum, Inc.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"
#include "dhc++/v4listener.h"
#include "dhc++/v6listener.h"

static isc_result_t receive_packet_worker(int sock);
static int sockfd;
static int sock4fd;

static int
if_readsocket (void *v)
{
  return sockfd;
}

static int
if_read4socket(void *v)
{
  return sock4fd;
}

static isc_result_t
receive_ipv4_packet(void *v)
{
  return receive_packet_worker(sock4fd);
}

/* Registration routine for V4-only socket, if needed. */

void
dhcpv4_socket_setup(void)
{
  struct sockaddr_in name;
  int flag;

  /* Set up the address we're going to bind to. */
  memset(&name, 0, sizeof name);
#if defined(HAVE_SA_LEN)
  name.sin_len = sizeof name;
#endif
  name.sin_family = AF_INET;
  name.sin_port = listen_port;

  if ((sock4fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
    {
      log_fatal("Cannot create DHCPv4 socket: %m");
    }

  flag = 1;
  if (setsockopt(sock4fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof flag) < 0)
    {
      log_fatal("Unable to set SO_REUSEADDR sockopt: %m");
    }
  if (bind(sock4fd, (struct sockaddr *)&name, sizeof name) < 0)
    {
      log_fatal("Cannot bind to DHCPv4 address %s/%d: %m",
		inet_ntoa(name.sin_addr), ntohs(name.sin_port));
    }

  flag = 1;
  if (setsockopt(sock4fd, SOL_SOCKET, SO_BROADCAST, &flag, sizeof flag) < 0)
    {
      log_fatal("Unable to set SO_BROADCAST sockopt: %m");
    }

  /* XXX I don't think this works without IP_PKTINFO.   Probably need
   * XXX to implement IP_PKTINFO for NetBSD.   OTOH, really the right
   * XXX thing is just to get v4 compatibility working correctly.
   */
#ifdef IP_PKTINFO
  /* Request the ip_pktinfo socket data. */
  flag = 1;
  if (setsockopt(sock4fd, IPPROTO_IP, IP_PKTINFO, &flag, sizeof flag) < 0)
    {
      log_fatal("Unable to set IP_PKTINFO sockopt: %m");
    }
#else
  /* Request the ip_recvif socket data. */
  flag = 1;
  if (setsockopt(sock4fd, IPPROTO_IP, IP_RECVIF, &flag, sizeof flag) < 0)
    {
      log_fatal("Unable to set IP_RECVIF sockopt: %m");
    }

  /* Request the ip_recvif socket data. */
  flag = 1;
  if (setsockopt(sock4fd, IPPROTO_IP, IP_RECVDSTADDR, &flag, sizeof flag) < 0)
    {
      log_fatal("Unable to set IP_RECVIF sockopt: %m");
    }
#endif

  register_io_object(NULL, if_read4socket, 0, receive_ipv4_packet, 0, 0);
  return;
}

static isc_result_t
receive_packet(void *v)
{
  return receive_packet_worker(sockfd);
}

/* Generic interface registration routine... */
void
dhcpv6_socket_setup(void)
{
  struct sockaddr_in6 name;
  int flag = 1;
  char addrbuf[128];

  /* Set up the address we're going to bind to. */
  memset(&name, 0, sizeof name);
#if defined(HAVE_SA_LEN)
  name.sin6_len = sizeof name;
#endif
  name.sin6_family = AF_INET6;
  name.sin6_port = listen_port_dhcpv6;

  if ((sockfd = socket(PF_INET6, SOCK_DGRAM, 0)) < 0)
    {
      log_fatal("Cannot create DHCPv6 socket: %m");
    }

  /* The RFC requires v6only to be disabled by default, but
   * it's generally enabled by default.   So just to be sure,
   * we need to explicitly enable it.
   */
  flag = 1;

  if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY,
		 &flag, sizeof flag) < 0)
    {
      log_debug("Unable to reset IPV6_V6ONLY sockopt: %m");
    }

  flag = 1;
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof flag) < 0)
    {
      log_debug("Unable to reset IPV6_V6ONLY sockopt: %m");
    }

  if (bind(sockfd, (struct sockaddr *)&name, sizeof name) < 0)
    {
      log_fatal("Cannot bind to DHCPv6 port: %m");
    }

  inet_ntop(AF_INET6, &name.sin6_addr, addrbuf, sizeof addrbuf);
  log_info("bound to %s/%d", addrbuf, ntohs(local_port_dhcpv6));

  /* Enable broadcasts. */
  flag = 1;
  if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &flag, sizeof flag) < 0)
    {
      log_fatal("Unable to set IPV6_PKTINFO sockopt: %m");
    }

  /* Request the in6_pktinfo socket data. */
  flag = 1;
  if (setsockopt(sockfd,
		 IPPROTO_IPV6, IPV6_RECVPKTINFO, &flag, sizeof flag) < 0)
    {
      log_fatal("Unable to set IPV6_PKTINFO sockopt: %m");
    }

  register_io_object(0, if_readsocket, 0, receive_packet, 0, 0);
}

void
dhcpv6_multicast_relay_join(struct interface_info *info)
{
  struct ipv6_mreq mreq;
  char addrbuf[128];

  /* Join the All_DHCP_Relay_Agents_and_Servers multicast group.
   * This is link-scoped, so it shouldn't fail.
   */
  memset(&mreq, 0, sizeof mreq);
  inet_pton(AF_INET6, "FF02::1:2", &mreq.ipv6mr_multiaddr);
  mreq.ipv6mr_interface = info->index;

  if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_JOIN_GROUP,
		 (char *)&mreq, sizeof mreq) < 0)
    {
      log_fatal("Unable to join All_DHCP_Relay_Agents_and_"
		"Servers multicast group on %s: %m", info->name);
    }
  else
    {
      inet_ntop(AF_INET6, (char *)&mreq.ipv6mr_multiaddr,
		addrbuf, sizeof addrbuf);
      log_info("Joined %s on interface %s (index %d)",
	       addrbuf, info->name, info->index);
    }
}

void
dhcpv6_multicast_server_join(struct interface_info *info)
{
  struct ipv6_mreq mreq;

  /* Join the All_DHCP_Servers multicast group.  This is site-scoped, so
   * it can fail, and (I think!) it's not an error when it does.
   */
  memset(&mreq, 0, sizeof mreq);
  inet_pton(AF_INET6, "FF05::1:3", &mreq.ipv6mr_multiaddr);
  mreq.ipv6mr_interface = info->index;

  if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_JOIN_GROUP,
		 (char *)&mreq, sizeof mreq) < 0)
    {
      log_error("Unable to join All_DHCP_Servers multicast "
		"group on %s: %m", info->name);
    }
}

void
if_statusprint(struct interface_info *info, const char *status)
{
  log_info("%s %s: %s", status, info->name,
	   print_hex_1(info->lladdr.hlen, info->lladdr.hbuf, 40));
}

ssize_t send_packet(struct interface_info *interface,
		    void *packet, size_t len, struct sockaddr *to)
{
  int sent;
  char buf[128];
  struct iovec iov;
  struct msghdr mh;
  struct cmsghdr *cmh;
  unsigned char cmsg_buf[1024];
  int retry = 0;
  struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)to;
  int sock = sockfd;
  int need_sendif = 0;

  /* Set up msgbuf. */
  memset(&iov, 0, sizeof iov);
  memset(&mh, 0, sizeof mh);
	
#if defined(DEBUG_PACKET)
  dump_raw((unsigned char *)packet, len);
#endif

  /* Set up mh.msg_name: the equivalent of the to address in sendto(). */

  /* If we're using separate sockets for v4 and v6, the sockaddr we
   * were passed will do the trick as is.
   */
  mh.msg_name = (caddr_t)to;
  if (to->sa_family == AF_INET)
    {
      mh.msg_namelen = sizeof (struct sockaddr_in);
      sock = sock4fd;
    }
  else
    mh.msg_namelen = sizeof (struct sockaddr_in6);
	
  /* This is equivalent to the buf argument in recvfrom. */
  mh.msg_iov = &iov;
  mh.msg_iovlen = 1;
  iov.iov_base = (caddr_t)packet;
  iov.iov_len = len;

  /* If we are sending to an IPv6 link-local address, we need to specify
   * the interface on which to send.
   */
  if (interface &&
      to->sa_family == AF_INET6 && (IN6_IS_ADDR_LINKLOCAL(&in6->sin6_addr) ||
				    IN6_IS_ADDR_MULTICAST(&in6->sin6_addr)))
    need_sendif = 1;

  /* Likewise, if we are sending to the all-ones broadcast address in
   * IPv4-land, we need to specify the interface.
   */
  else if (interface && to->sa_family == AF_INET &&
	   ((struct sockaddr_in *)to)->sin_addr.s_addr == 0xFFFFFFFF)
    need_sendif = 1;

  if (need_sendif && to->sa_family == AF_INET)
    {
#ifdef IP_PKTINFO
      struct in_pktinfo *pktin;

      cmh = (struct cmsghdr *)cmsg_buf;
      cmh->cmsg_len = CMSG_LEN(sizeof *pktin);
      cmh->cmsg_level = IPPROTO_IP;
      cmh->cmsg_type = IP_PKTINFO;

      pktin = (struct in_pktinfo *)CMSG_DATA(cmh);

      /* We set the index, but not the source address - let the
       * kernel pick the source address.
       */
      memset(pktin, 0, sizeof *pktin);
      pktin->ipi_ifindex = interface->index;

      /* Assemble everything into a single buffer. */
      mh.msg_control = cmsg_buf;
      mh.msg_controllen = CMSG_SPACE(sizeof *pktin);
#else
# if defined(NEED_BPF)
      bpf_send_packet(interface, packet, len, (struct sockaddr_in *)to);
# else
      log_info("need to set send interface, but can't.");
# endif
#endif
    }
  else if (need_sendif)
    {
      struct in6_pktinfo *pktin6;

      cmh = (struct cmsghdr *)cmsg_buf;
      cmh->cmsg_len = CMSG_LEN(sizeof *pktin6);
      cmh->cmsg_level = IPPROTO_IPV6;
      cmh->cmsg_type = IPV6_PKTINFO;

      pktin6 = (struct in6_pktinfo *)CMSG_DATA(cmh);
      memset(pktin6, 0, sizeof *pktin6);
      pktin6->ipi6_ifindex = interface->index;

      /* Always use the link-local address as the source address. */
      if (interface->ipv6_addr_count > 0)
	pktin6->ipi6_addr = interface->ipv6s[interface->ipv6_ll_index];
      else
	{
	  log_info("send_packet: unable to transmit IPv6 packet on non-"
		   "IPv6 network on interface %s", interface->name);
#if defined(EADDRNOTAVAIL)
	  errno = EADDRNOTAVAIL;
#endif
	  return -1;
	}

      /* Assemble everything into a single buffer. */
      mh.msg_control = cmsg_buf;
      mh.msg_controllen = CMSG_SPACE(sizeof *pktin6);
      log_info("Specifying outgoing interface: %d",
	       interface->index);
    }

  log_info("Sending to %s/%d%s%s",
	   inet_ntop(to->sa_family,
		     (to->sa_family == AF_INET
		      ? (char *)&((struct sockaddr_in *)to)->sin_addr
		      : (char *)&((struct sockaddr_in6 *)to)->sin6_addr),
		     buf, sizeof buf),
	   ntohs(((struct sockaddr_in6 *)to)->sin6_port),
	   need_sendif ? " on " : "",
	   need_sendif ? interface->name : "");

  do {
    sent = sendmsg(sock, &mh, 0);
  } while (sent < 0 &&
	   (errno == EHOSTUNREACH ||
	    errno == ENETUNREACH ||
	    errno == ECONNREFUSED) &&
	   retry++ < 10);

  if (sent < 0)
    {
      log_error ("send_packet: %m");
      if (errno == ENETUNREACH && to->sa_family == AF_INET)
	log_error ("send_packet: please consult README file%s",
		   " regarding broadcast address.");
    }
  return sent;
}

static isc_result_t
receive_packet_worker(int sock)
{
  int kount;
  int result;
  struct iovec iov;
  struct msghdr mh;
  char cmsg_buf[1024];
  struct cmsghdr *cmh;
  int got_ifindex = 0;
  struct interface_info *iface;
  int ifindex = 0;
  union {
    unsigned char packbuf[4096];
    u_int64_t aligneything;
  } u;
  union {
    struct sockaddr_in in;
    struct sockaddr_in6 in6;
    struct sockaddr sa;
  } from;
  char buf[100];


  /* To work around incompatibilities with Linux' recvmsg, we may
   * have to try receiving the packet more than once.
   */
  kount = 0;
 again:
  if (++kount > 10)
    {
      return ISC_R_SUCCESS;
    }

  /* Set up msgbuf. */
  memset(&iov, 0, sizeof iov);
  memset(&mh, 0, sizeof mh);
	
  /* This is equivalent to the from argument in recvfrom. */
  mh.msg_name = (caddr_t)&from;
  mh.msg_namelen = sizeof from;
	
  /* This is equivalent to the buf argument in recvfrom. */
  mh.msg_iov = &iov;
  mh.msg_iovlen = 1;
  iov.iov_base = (caddr_t)&u;
  iov.iov_len = sizeof u;

  /* This is where additional headers get stuffed. */
  mh.msg_control = cmsg_buf;
  mh.msg_controllen = sizeof cmsg_buf;

  result = recvmsg(sock, &mh, 0);
  if (result < 0)
    {
      if (errno == EHOSTUNREACH || errno == ECONNREFUSED)
	goto again;
      else
	/* XXX may have to do more here to avoid a spin if
	 * XXX there is an unrecoverable error.
	 */
	return ISC_R_NOMORE;
      goto again;
    }

  /* Loop through the control message headers looking for
   * the IPV6_PKTINFO or IP_PKTINFO data.
   */
  for (cmh = CMSG_FIRSTHDR(&mh); cmh; cmh = CMSG_NXTHDR(&mh, cmh))
    {
      if (cmh->cmsg_level == IPPROTO_IPV6 &&
	  cmh->cmsg_type == IPV6_PKTINFO)
	{
	  struct in6_pktinfo pktinfo;

	  /* The sockaddr should be right after the cmsg_hdr. */
	  memcpy(&pktinfo, CMSG_DATA(cmh), sizeof pktinfo);
	  ifindex = pktinfo.ipi6_ifindex;
	  got_ifindex = 1;
#ifdef IP_PKTINFO
	}
      else if (cmh->cmsg_level == IPPROTO_IP &&
	       cmh->cmsg_type == IP_PKTINFO)
	{
	  struct in_pktinfo pktinfo;

	  /* The sockaddr should be right after the cmsg_hdr. */
	  memcpy(&pktinfo, CMSG_DATA(cmh), sizeof pktinfo);
	  ifindex = pktinfo.ipi_ifindex;
	  got_ifindex = 1;
#endif
#ifdef IP_RECVIF
	}
      else if (cmh->cmsg_level == IPPROTO_IP &&
	       cmh->cmsg_type == IP_RECVIF)
	{
	  struct sockaddr_dl *sdl = (struct sockaddr_dl *)CMSG_DATA(cmh);
	  /* The sockaddr should be right after the cmsg_hdr. */
	  ifindex = sdl->sdl_index;
	  got_ifindex = 1;
#endif
	}
    }

  /* If we didn't get an interface index, something's wrong. */
  if (!got_ifindex)
    {
      log_error("receive_packet: no interface index");
      return ISC_R_SUCCESS;
    }

  /* Using the interface index, look up the interface structure. */
  for (iface = interfaces; iface; iface = iface->next)
    {
      if (iface->index == ifindex)
	{
	  goto out;
	}
    }
  log_error("receive_packet(): unknown ifindex %d", ifindex);
  return ISC_R_SUCCESS;

 out:
  if (from.sa.sa_family == AF_INET6)
    {
      if (iface->num_v6listeners > 0)
	{
	  struct dhcpv6_response *rsp = decode_dhcpv6_packet(u.packbuf, result, 0);
	  DHCPv6Listener *listener;
	  if (rsp)
	    {
	      int i;
	      for (i = 0; i < iface->num_v6listeners; i++)
		{
		  listener = iface->v6listeners[i];
		  if (listener->mine(rsp))
		    {
		      isc_result_t rv = listener->got_packet(rsp, &from.in6, u.packbuf, result);
		      return rv;
		    }
		}
	    }
	}
      inet_ntop(from.sa.sa_family, &from.in6.sin6_addr, buf, sizeof buf);
      log_error("Dropping packet from %s on %s - no matching listener object",
		buf, iface->name);
    }
  else if (from.sa.sa_family == AF_INET)
    {
      if (iface->v4listener)
	return iface->v4listener->got_packet(iface, &from.in,
					     u.packbuf, result);
      else
	{
	  inet_ntop(from.sa.sa_family, &from.in.sin_addr, buf, sizeof buf);
	  log_error("Dropping packet from %s on %s - no listener object",
		    buf, iface->name);
	}
    }
  else
    {
      log_error("Dropping packet with sa_family == %d", from.sa.sa_family);
    }
  return ISC_R_SUCCESS;
}

/* Local Variables:  */
/* mode:C++ */
/* c-file-style:"gnu" */
/* end: */
