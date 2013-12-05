/* discover.cpp
 *
 * Discover available network interfaces.
 */

/* Copyright (c) 2002-2006 Nominum, Inc.   All rights reserved.
 *
 * Copyright (c) 1996-2001 Internet Software Consortium.
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
  "$Id: discover.cpp,v 1.6 2012/04/01 21:26:34 mellon Exp $ Copyright (c) 2005-2006 Nominum, Inc.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

#if defined(NEED_GETIFADDRS)
#include "ifaddrs_compat.h"
#else
#include <ifaddrs.h>
#endif

struct interface_info *interfaces, *dummy_interfaces, *fallback_interface;
int interfaces_invalidated;
int quiet_interface_discovery;
u_int16_t local_port;
u_int16_t remote_port;
u_int16_t listen_port;
int (*dhcp_interface_setup_hook) (struct interface_info *, struct iaddr *);
int (*dhcp_interface_discovery_hook) (struct interface_info *);
isc_result_t (*dhcp_interface_startup_hook) (struct interface_info *);
int (*dhcp_interface_shutdown_hook) (struct interface_info *);

struct in_addr limited_broadcast;
struct in_addr local_address;

void (*bootp_packet_handler) PROTO ((struct interface_info *,
				     struct dhcp_packet *, unsigned,
				     unsigned int,
				     struct iaddr));

/* Use the SIOCGIFCONF ioctl to get a list of all the attached interfaces.
   For each interface that's of type INET and not the loopback interface,
   register that interface with the network I/O software, figure out what
   subnet it's on, and add it to the list of interfaces. */

void discover_interfaces()
{
  struct interface_info *tmp;
  struct sockaddr_in foo;
#ifdef ALIAS_NAMES_PERMUTED
  char *s;
#endif
  struct ifaddrs *ifaddrs, *ifp;

  getifaddrs(&ifaddrs);

  /* Cycle through the list of interfaces looking for IP addresses. */
  for (ifp = ifaddrs; ifp; ifp = ifp->ifa_next)
    {
#ifdef ALIAS_NAMES_PERMUTED
      if ((s = strrchr (ifp->ifa_name, ':')))
	{
	  *s = 0;
	}
#endif

#ifdef SKIP_DUMMY_INTERFACES
      if (!strncmp (ifp->ifa_name, "dummy", 5))
	continue;
#endif

      /* See if we've seen an interface that matches this one. */
      for (tmp = interfaces; tmp; tmp = tmp->next)
	if (!strcmp (tmp->name, ifp->ifa_name))
	  break;

      /* If there isn't already an interface by this name,
	 allocate one. */
      if (!tmp)
	{
	  tmp = (struct interface_info *)safemalloc(sizeof *tmp);
	  memset(tmp, 0, sizeof *tmp);
	  strcpy(tmp->name, ifp->ifa_name);
	  interface_snorf(tmp);
	  tmp->index = if_nametoindex(ifp->ifa_name);
	  log_info("interface %s index is %d", tmp->name, tmp->index);
	}

      if (dhcp_interface_discovery_hook)
	(*dhcp_interface_discovery_hook)(tmp);

      /* If we have the capability, extract link information
	 and record it in a linked list. */
#ifdef HAVE_AF_LINK
      if (ifp->ifa_addr->sa_family == AF_LINK)
	{
	  struct sockaddr_dl *foo = (struct sockaddr_dl *)(ifp->ifa_addr);
#if defined (HAVE_SA_LEN)
	  tmp->lladdr.hlen = foo->sdl_alen;
#else
	  tmp->lladdr.hlen = 6; /* XXX!!! */
#endif
	  tmp->lladdr.hbuf[0] = HTYPE_ETHER; /* XXX */
	  memcpy(&tmp->lladdr.hbuf [1], LLADDR(foo), tmp->lladdr.hlen);
	  tmp->lladdr.hlen++;	/* for type. */
	}
      else
#endif /* AF_LINK */
#ifdef HAVE_AF_PACKET
	/* AF_PACKET is a Linux thing; linux reports hardware
	 * addresses for interfaces that have none.   The exclusions
	 * below are intended to filter out such interfaces.
	 */
	if (ifp->ifa_addr->sa_family == AF_PACKET &&
	    !(ifp->ifa_flags & IFF_LOOPBACK) &&
	    !(ifp->ifa_flags & IFF_POINTOPOINT) &&
	    !(ifp->ifa_flags & IFF_NOARP))
	  {
	    struct sockaddr_ll *foo =
	      (struct sockaddr_ll *)ifp->ifa_addr;
	    tmp->lladdr.hlen = foo->sll_halen;
	    tmp->lladdr.hbuf[0] = foo->sll_hatype;
	    memcpy(&tmp->lladdr.hbuf [1],
		   foo->sll_addr, tmp->lladdr.hlen);
	    tmp->lladdr.hlen++;	/* for type. */
	  }
	else
#endif /* AF_PACKET */
	  if (ifp->ifa_addr->sa_family == AF_INET)
	    {
	      struct iaddr addr;

	      /* Get a pointer to the address... */
	      memcpy(&foo, ifp->ifa_addr, sizeof foo);
		  
	      /* If the only address we have is 0.0.0.0, we
		 shouldn't consider the interface configured. */
	      if (foo.sin_addr.s_addr != htonl(INADDR_ANY))
		tmp->v4configured = 1;
		  
	      if (!tmp->ipv4s)
		{
		  tmp->ipv4s =
		    (struct in_addr *)safemalloc(10 * sizeof (struct in_addr));
		  tmp->ipv4_addr_count = 0;
		  tmp->ipv4_addr_max = 10;
		}
	      else if (tmp->ipv4_addr_count >= tmp->ipv4_addr_max)
		{
		  struct in_addr *ta;
		  int newmax = tmp->ipv4_addr_max * 2;
		  ta = (struct in_addr *)safemalloc(tmp->ipv4_addr_max *
						    sizeof (struct in_addr));
		  memcpy (ta, tmp->ipv4s,
			  tmp->ipv4_addr_max * sizeof (struct in_addr));
		  tmp->ipv4s = ta;
		  tmp->ipv4_addr_max = newmax;
		}
	      tmp->ipv4s [tmp->ipv4_addr_count++] = foo.sin_addr;
		  
	      /* Grab the address... */
	      addr.len = 4;
	      memcpy (addr.iabuf, &foo.sin_addr.s_addr, addr.len);
	      if (dhcp_interface_setup_hook)
		(*dhcp_interface_setup_hook) (tmp, &addr);
	    }
	  else if (ifp->ifa_addr->sa_family == AF_INET6)
	    {
	      struct iaddr addr;
	      struct sockaddr_in6 in6;
	      char addrbuf[128];
		  
	      /* Get a pointer to the address... */
	      memcpy(&in6, ifp->ifa_addr, sizeof in6);
		  
	      /* If the only address we have is 0.0.0.0, we
		 shouldn't consider the interface configured. */
	      if (!IN6_IS_ADDR_UNSPECIFIED(&in6.sin6_addr) &&
		  !IN6_IS_ADDR_LINKLOCAL(&in6.sin6_addr))
		tmp->v6configured = 1;
	      inet_ntop(AF_INET6, (char *)&in6.sin6_addr,
			addrbuf, sizeof addrbuf);
	      log_info("%s/%s: %s", tmp->name, addrbuf, (tmp->v6configured
							 ? "configured"
							 : "not configured"));
		  
	      if (!tmp->ipv6s)
		{
		  tmp->ipv6s = ((struct in6_addr *)
				safemalloc(10 * sizeof (struct in6_addr)));
		  tmp->ipv6_addr_count = 0;
		  tmp->ipv6_addr_max = 10;
		}
	      else if (tmp->ipv6_addr_count >= tmp->ipv6_addr_max)
		{
		  struct in6_addr *ta;
		  int newmax = tmp->ipv6_addr_max * 2;
		  ta = (struct in6_addr *)safemalloc(tmp->ipv6_addr_max *
						     sizeof *ta);
		  memcpy (ta, tmp->ipv6s, tmp->ipv6_addr_max * sizeof *ta);
		  tmp->ipv6s = ta;
		  tmp->ipv6_addr_max = newmax;
		}

	      /* Remember the index of the link-local address, because we
	       * must always use that as our source address when sending
	       * DHCP packets.
	       */
	      if (IN6_IS_ADDR_LINKLOCAL(&in6.sin6_addr))
		tmp->ipv6_ll_index = tmp->ipv6_addr_count;
	      tmp->ipv6s[tmp->ipv6_addr_count++] = in6.sin6_addr;

	      /* Grab the address... */
	      addr.len = 16;
	      memcpy(addr.iabuf, &in6.sin6_addr, addr.len);
	      if (dhcp_interface_setup_hook)
		(*dhcp_interface_setup_hook) (tmp, &addr);
#ifdef DEBUG_INTERFACE_DISCOVERY
	    }
	  else
	    {
	      log_info("unknown family: %d",
		       ifp->ifa_addr->sa_family);
#endif
	    }
    }

  freeifaddrs(ifaddrs);
}

void interface_snorf (struct interface_info *tmp)
{
  tmp->circuit_id = (u_int8_t *)tmp->name;
  tmp->circuit_id_len = strlen (tmp->name);
  tmp->remote_id = 0;
  tmp->remote_id_len = 0;
  tmp->next = interfaces;
  interfaces = tmp;
}

/* Local Variables:  */
/* mode:C++ */
/* c-file-style:"gnu" */
/* end: */
