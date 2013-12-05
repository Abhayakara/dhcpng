/* getifaddrs.cpp
 *
 * Compatibility implementation of getifaddrs() for Solaris.
 */

/* Copyright (c) 2006 Nominum, Inc.   All rights reserved.
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
 * 3. Neither the name of Nominum nor the names of its contributors may
 *    be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY NOMINUM AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL NOMINUM OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* This is a replacement version of getifaddrs() which has been written
 * with Solaris in mind, because as far as I know that's the only operating
 * system we care about that doesn't have getifaddrs as a regular libc
 * call.   This code could probably be easily ported to some other system,
 * but you'd have to replace all the SIOCGL* calls with SIOCG* calls, since
 * I *think* SIOCGL* calls are a Solaris-specific thing.   There is code
 * in here that's not Solaris-specific - for example, Solaris doesn't have
 * sa_len in the sockaddr structure.
 */
#ifndef lint
static char copyright[] __attribute__((unused)) =
  "$Id: ifaddrs.cpp,v 1.6 2006/09/02 08:34:49 mellon Exp $ Copyright (c) 2005-2006 Nominum, Inc.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"
#if defined(NEED_GETIFADDRS)
#include "ifaddrs_compat.h"
#include <sys/ioctl.h>
#include <sys/sockio.h>

#include <fcntl.h>
#include <stropts.h>
#include <sys/dlpi.h>

#define MAXDLBUF 256

static void getifaddr_dlpi_link_addr_fetch(const char *name,
					   struct sockaddr_dl *dladdr)
{
  /* Based on code provided in Sun Technical Note 3281-05. */

  static char fnpref[] = "/dev/";
  char *fnbuf = (char *)safemalloc(sizeof fnpref + strlen(name));
  const char *instance;

  int fd, flags;
  long buffer[MAXDLBUF];
  struct strbuf ctl;
  dl_phys_addr_req_t phys_addr_req;
  dl_info_req_t info_req;
  dl_attach_req_t attach_req;
  dl_phys_addr_ack_t *dlpadd;
  dl_info_ack_t *dlpinfo;

  instance = name + strlen(name) - 1;
  while (*instance >= '0' && *instance <= '9' && instance > name)
    --instance;
  ++instance;

  sprintf(fnbuf, "%s%s", fnpref, name);
  fnbuf[(sizeof fnpref) - 1 + (instance - name)] = 0;

  if ((fd = open(fnbuf, O_RDWR, 0)) < 0)
    {
      log_fatal("Can't open %s: %m", fnbuf); 
      exit(1);
    }


  attach_req.dl_primitive = DL_ATTACH_REQ;
  attach_req.dl_ppa = atoi (instance);

  ctl.maxlen = 0;
  ctl.len = sizeof (attach_req);
  ctl.buf = (char *)&attach_req;
  flags = 0;

  if (putmsg(fd, &ctl, (struct strbuf *)NULL, flags) < 0)
    log_fatal("can't dlattach %s/%ld: %m", fnbuf, attach_req.dl_ppa);

  ctl.maxlen = MAXDLBUF;
  ctl.len = 0;
  ctl.buf = (char *) &buffer;

  if ((getmsg(fd, &ctl, (struct strbuf *)0, &flags) < 0))
    log_fatal("getmsg for dlattachack on %s/%ld: %m",
	      fnbuf, attach_req.dl_ppa);

  if (((size_t)ctl.len > sizeof (dl_ok_ack_t)) ||
      ((size_t)ctl.len < sizeof(dl_ok_ack_t)) ||
      (flags != RS_HIPRI))
    log_fatal("bogus dl_ok_ack message on %s/%ld", fnbuf, attach_req.dl_ppa);

  phys_addr_req.dl_primitive = DL_PHYS_ADDR_REQ;
  phys_addr_req.dl_addr_type = DL_CURR_PHYS_ADDR;

  ctl.maxlen = 0;
  ctl.len = sizeof (phys_addr_req);
  ctl.buf = (char *)&phys_addr_req;
  flags = 0;

  if (putmsg(fd, &ctl, (struct strbuf *)NULL, flags) < 0)
    log_fatal("putmsg for phys_addr_req on %s/%ld: %m",
	      fnbuf, attach_req.dl_ppa);

  ctl.maxlen = MAXDLBUF;
  ctl.len = 0;
  ctl.buf = (char *)buffer;

  if (getmsg(fd, &ctl, (struct strbuf *)0, &flags) < 0)
    log_fatal("getmsg for phys_addr_ack on %s/%ld: %m",
	      fnbuf, attach_req.dl_ppa);

  if ((size_t)ctl.len < sizeof(dl_phys_addr_ack_t))
    log_fatal("bogus phys_addr_ack message (%d < %d) on %s/%ld",
	      ctl.len, sizeof (dl_phys_addr_ack_t),
	      fnbuf, attach_req.dl_ppa);
  if (flags != RS_HIPRI)
    log_fatal("bogus phys_addr_ack message (flags = %d) on %s/%ld",
	      flags, fnbuf, attach_req.dl_ppa);

  dlpadd = (dl_phys_addr_ack_t *)buffer;

  dladdr->sdl_family = AF_LINK;
  dladdr->sdl_index = 0; /* XXX */
  dladdr->sdl_nlen = strlen(name) + 1;
  dladdr->sdl_alen = dlpadd->dl_addr_length;
  dladdr->sdl_slen = 0;
  strcpy(dladdr->sdl_data, name);
  memcpy(&dladdr->sdl_data[dladdr->sdl_nlen],
	 ((char *)buffer) + dlpadd->dl_addr_offset,
	 dlpadd->dl_addr_length);

  info_req.dl_primitive = DL_INFO_REQ;

  ctl.maxlen = 0;
  ctl.len = sizeof (info_req);
  ctl.buf = (char *)&info_req;
  flags = 0;

  if (putmsg(fd, &ctl, (struct strbuf *)NULL, flags) < 0)
    log_fatal("putmsg for info_req on %s/%ld: %m",
	      fnbuf, attach_req.dl_ppa);

  ctl.maxlen = MAXDLBUF;
  ctl.len = 0;
  ctl.buf = (char *)buffer;

  if (getmsg(fd, &ctl, (struct strbuf *)0, &flags) < 0)
    log_fatal("getmsg for info_ack on %s/%ld: %m",
	      fnbuf, attach_req.dl_ppa);

  if ((size_t)ctl.len < sizeof(dl_phys_addr_ack_t))
    log_fatal("bogus info_ack message (%d < %d) on %s/%ld",
	      ctl.len, sizeof (dl_phys_addr_ack_t),
	      fnbuf, attach_req.dl_ppa);
  if (flags != RS_HIPRI)
    log_fatal("bogus info_ack message (flags = %d) on %s/%ld",
	      flags, fnbuf, attach_req.dl_ppa);

  dlpinfo = (dl_info_ack_t *)buffer;
  switch(dlpinfo->dl_mac_type)
    {
    case DL_ETHER:
    case DL_100BT:
      dladdr->sdl_type = HTYPE_ETHER;
      break;

    case DL_CSMACD:     /* IEEE 802.3 CSMA/CD network */
    case DL_TPB:     /* IEEE 802.4 Token Passing Bus */
    case DL_TPR:     /* IEEE 802.5 Token Passing Ring */
    case DL_METRO:     /* IEEE 802.6 Metro Net */
      dladdr->sdl_type = HTYPE_IEEE802;
      break;

    case DL_FDDI:    /* Fiber Distributed data interface */
      dladdr->sdl_type = HTYPE_FDDI;

    case DL_FC:    /* Fibre Channel interface */
      dladdr->sdl_type = HTYPE_FIBER_CHANNEL;
      break;

    case DL_IB:
      dladdr->sdl_type = HTYPE_INFINIBAND;
      break;

    default:
      log_error("warning: unknown DLPI media type %ld\n",
		dlpinfo->dl_mac_type);
      dladdr->sdl_type = HTYPE_ETHER;
      break;
    }
}

/* Allocate a structure for a sockaddr, and put the address in it.   Use
 * sa_len if it's present; otherwise assume that sockaddr is big enough
 * to hold any valid struct sockaddr_*.
 */
static struct sockaddr *getifaddrs_snorf(struct sockaddr_storage *addr)
{
  socklen_t len;
  struct sockaddr *rv;
  
#if defined(HAVE_SA_LEN)
  len = foo->sa_len;
#else
  len = sizeof (struct sockaddr_storage);
#endif

  rv = (struct sockaddr *)safemalloc(len);
  memcpy(rv, addr, len);
  return rv;
}

/* Allocate a structure to store an interface address; stash the name of
 * the interface, and put the interface on the interface list.
 */
static struct ifaddrs *getifaddrs_new(const char *ifname,
				      u_int64_t flags,
				      struct ifaddrs **interfaces,
				      struct ifaddrs **last)
{
  struct ifaddrs *ip;

  /* Allocate a structure to hold the information. */
  ip = (struct ifaddrs *)safemalloc(sizeof *ip);
  memset(ip, 0, sizeof *ip);
  ip->ifa_name = (char *)safemalloc(strlen(ifname) + 1);
  strcpy(ip->ifa_name, ifname);
  if (*last)
    (*last)->ifa_next = ip;
  else
    *interfaces = ip;
  *last = ip;

  /* Stash the interface flags. */
  ip->ifa_flags = flags;

  return ip;
}

/* Use the SIOCGIFCONF ioctl to get a list of addresses belonging to each of
 * the attached interfaces.  Each interface/address combination appears, in
 * the order it was delivered, on a linked list of struct ifaddrs (see
 * ifaddrs_compat.h).   For links that have broadcast addresses, the broadcast
 * address appears in ifa_dstaddr; for links that are point to point, the
 * destination appears there; for links that have subnet masks, the subnet
 * mask appears in ifa_netmask.   The interface flags appear in each interface/
 * address pair in the ifa_flags element, since flags aren't specific to
 * network addresses.   Currently ifa_data is always null, which differs from
 * the behavior at least on FreeBSD, and probably all the BSDs.   I can't
 * find documentation for the Linux version, so I don't know how this compares.
 */
int getifaddrs(struct ifaddrs **rvp)
{
  struct ifaddrs *interfaces, *ip, *last;
  char buf [2048];
  struct lifconf ic;
  struct lifreq ifr;
  int i;
  int sock;
  int ir;
  struct ifreq *tif;
  isc_result_t status;
  static int setup_fallback = 0;
  int wifcount = 0;

  interfaces = last = 0;

  /* Create an unbound datagram socket to do the SIOCGIFCONF ioctl on. */
  if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    return 0;

  /* Get the interface configuration information... */

  /* otherwise, we just feed it a starting size, and it'll tell us if
   * it needs more */

  memset(&ic, 0, sizeof ic);
  ic.lifc_family = AF_UNSPEC;
  ic.lifc_len = sizeof buf;
  ic.lifc_lifcu.lifcu_buf = (caddr_t)buf;

 gifconf_again:
  i = ioctl(sock, SIOCGLIFCONF, &ic);

  if (i < 0)
    log_fatal("ioctl: SIOCGLIFCONF: %m");

  /* If the SIOCGLIFCONF resulted in more data than would fit in
     a buffer, allocate a bigger buffer. */
  if ((ic.lifc_lifcu.lifcu_buf == buf) && (size_t)ic.lifc_len > sizeof buf)
    {
      ic.lifc_lifcu.lifcu_buf = (caddr_t)safemalloc((size_t)ic.lifc_len);
      if (!ic.lifc_lifcu.lifcu_buf)
	log_fatal("Can't allocate SIOCGLIFCONF buffer.");
      goto gifconf_again;
    }

  /* Cycle through the list of interfaces. */
  for (i = 0; i < ic.lifc_len;)
    {
      struct lifreq *ifp = (struct lifreq *)((caddr_t)ic.lifc_req + i);
#ifdef HAVE_SA_LEN
      if (ifp->ifr_addr.sa_len > sizeof(struct sockaddr))
	i += (sizeof ifp->ifr_name) + ifp->ifr_addr.sa_len;
      else
#endif
	i += sizeof *ifp;

      /* Get interface flags. */
      strcpy(ifr.lifr_name, ifp->lifr_name);
      if (ioctl(sock, SIOCGLIFFLAGS, &ifr) < 0)
	{
	  char *s = strrchr(ifr.lifr_name, ':');
	  if (s)
	    {
	      *s = 0;
	      if (ioctl(sock, SIOCGLIFFLAGS, &ifr) < 0)
	        log_fatal("Can't get interface flags for %s: %m",
			  ifr.lifr_name);
	      *s = ':';
	    }
	  else
	    log_fatal("Can't get interface flags for %s: %m", ifr.lifr_name);
	}

#if defined(NEED_IFADDRS_FAKE_DLADDR)
      if (ifr.lifr_flags & IFF_BROADCAST)
	{
	  struct sockaddr_dl dladdr;
	  char *s;

	  /* Solaris doesn't provide interface hardware addresses in
	   * SIOCGLIFCONF, so we need to fetch them specially.   So the
	   * first time we see the name of a particular interface, go
	   * grab its hardware address and make an entry for it.
	   *
	   * Solaris doesn't provide a standard socket API way to get
	   * the link-layer address of an interface, so unfortunately we
	   * must delve into DLPI land.   :'(
	   */

	  /* Ethernet addresses are specific to the physical
	   * interface, not the logical interface.
	   */
	  s = strrchr(ifr.lifr_name, ':');
	  if (!s)
	    {
	      for (ip = interfaces; ip; ip = ip->ifa_next)
	        {
	          if (!strcmp(ifp->lifr_name, ip->ifa_name))
	            goto nodladdr;
	        }
	      getifaddr_dlpi_link_addr_fetch(ifp->lifr_name, &dladdr);
	      ip = getifaddrs_new(ifp->lifr_name,
			          ifr.lifr_flags, &interfaces, &last);
	      ip->ifa_addr =
		getifaddrs_snorf((struct sockaddr_storage *)&dladdr);
	    nodladdr:
	      ;
	    }
	}
#endif

      ip = getifaddrs_new(ifp->lifr_name, ifr.lifr_flags, &interfaces, &last);

      ip->ifa_addr = getifaddrs_snorf(&ifp->lifr_addr);

      /* Broadcast address and destination address are mutually exclusive. */
      if (ip->ifa_flags & IFF_BROADCAST && ip->ifa_addr->sa_family != AF_INET6)
	{
	  /* Get broadcast address. */
	  if (ioctl(sock, SIOCGIFBRDADDR, &ifr) < 0)
	    log_fatal("Can't get interface broadcast address for %s: %m",
		      ifr.lifr_name);
	  ip->ifa_dstaddr = getifaddrs_snorf(&ifr.lifr_lifru.lifru_broadaddr);
	}
      else if (ip->ifa_flags & IFF_POINTOPOINT)
	{
	  /* Get interface flags. */
	  if (ioctl(sock, SIOCGIFDSTADDR, &ifr) < 0)
	    log_fatal("Can't get interface broadcast address for %s: %m",
		      ifr.lifr_name);
	  ip->ifa_dstaddr = getifaddrs_snorf(&ifr.lifr_lifru.lifru_broadaddr);
	}

      /* Hm, on BSD this is going to be an IFALIASREQ.   I think Solaris
       * is fine because it uses interface aliases to represent multiple
       * addresses on the same physical interface.
       */
      if (ip->ifa_addr->sa_family != AF_INET6 &&
	  ioctl(sock, SIOCGIFNETMASK, &ifr) >= 0)
	ip->ifa_netmask = getifaddrs_snorf(&ifr.lifr_lifru.lifru_addr);
    }

  /* If we allocated a buffer, free it. */
  if (ic.lifc_lifcu.lifcu_buf != buf)
    free(ic.lifc_lifcu.lifcu_buf);

  if (rvp)
    *rvp = interfaces;
  return 1;
}

void freeifaddrs(struct ifaddrs *addrs)
{
  struct ifaddrs *next;

  while (addrs)
    {
      next = addrs->ifa_next;
      if (addrs->ifa_name)
	free(addrs->ifa_name);
      if (addrs->ifa_addr)
	free(addrs->ifa_addr);
      if (addrs->ifa_netmask)
        free(addrs->ifa_netmask);
      if (addrs->ifa_dstaddr)
	free(addrs->ifa_dstaddr);
      free(addrs);
      addrs = next;
    }
}
#endif /* NEED_GETIFADDRS */

/* Local Variables:  */
/* mode:C++ */
/* c-file-style:"gnu" */
/* end: */
