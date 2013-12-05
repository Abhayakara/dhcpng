/* bpf.c
 *
 * BPF socket interface code, originally contributed by Archie Cobbs.
 */

/*
 * Copyright (c) 2007 by Nominum, Inc.
 * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1996-2003 by Internet Software Consortium
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *   Internet Systems Consortium, Inc.
 *   950 Charter Street
 *   Redwood City, CA 94063
 *   <info@isc.org>
 *   http://www.isc.org/
 *
 * This software was contributed to Internet Systems Consortium
 * by Archie Cobbs.
 *
 * Patches for FDDI support on Digital Unix were written by Bill
 * Stapleton, and maintained for a while by Mike Meredith before he
 * managed to get me to integrate them.
 */

#ifndef lint
static char copyright[] __attribute__((unused)) =
  "$Id: bpf.cpp,v 1.1 2007/09/14 23:02:55 mellon Exp $ Copyright (c) 2004 Internet Systems Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

#if defined (NEED_BPF)
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <net/bpf.h>

#include <netinet/in_systm.h>
#include "includes/netinet/ip.h"
#include "includes/netinet/udp.h"
#include "includes/netinet/if_ether.h"

static void if_register_bpf (struct interface_info *info)
{
  int sock;
  char filename[50];
  int b;
  struct ifreq ifp;

  /* Open a BPF device */
  for (b = 0; 1; b++)
    {
      /* %Audit% 31 bytes max. %2004.06.17,Safe% */
      sprintf(filename, BPF_FORMAT, b);
      sock = open (filename, O_RDWR, 0);
      if (sock < 0)
	{
	  if (errno == EBUSY)
	    {
	      continue;
	    }
	  else
	    {
	      if (!b)
		log_fatal ("No bpf devices.   Please read the README "
			   "section for your operating system.");
	      log_fatal ("Can't find free bpf: %m");
	    }
	}
      else
	{
	  break;
	}
    }

  /* Set the BPF device to point at this interface. */
  memcpy(ifp.ifr_name, info->name, IFNAMSIZ);
  if (ioctl(sock, BIOCSETIF, &ifp) < 0)
    log_fatal("Can't attach interface %s to bpf device %s: %m",
	      info->name, filename);

  info->pf_sock = sock;
}

ssize_t bpf_send_packet(struct interface_info *interface,
			void *packet,
			size_t len,
			struct sockaddr_in *to)
{
  unsigned hbufp = 0, ibufp = 0;
  double hw[4];
  double ip[32];
  struct iovec iov[3];
  int result;
  static struct hardware hto = { 7, { 1, 255, 255, 255, 255, 255, 255 } };
  u_int32_t from;

  if (interface->ipv4_addr_count)
    from = interface->ipv4s[0].s_addr;
  else
    from = INADDR_ANY;


  /* Make sure there's a socket. */
  if (!interface->pf_sock)
    if_register_bpf(interface);

  /* Assemble the headers... */
  assemble_ethernet_header(interface, (unsigned char *)hw, &hbufp, &hto);
  assemble_udp_ip_header(interface,
			 (unsigned char *)ip, &ibufp, from,
			  to->sin_addr.s_addr, to->sin_port,
			 (unsigned char *)packet, len);

  /* Fire it off */
  iov[0].iov_base = ((char *)hw);
  iov[0].iov_len = hbufp;
  iov[1].iov_base = ((char *)ip);
  iov[1].iov_len = ibufp;
  iov[2].iov_base = (char *)packet;
  iov[2].iov_len = len;

  result = writev(interface->pf_sock, iov, 3);
  if (result < 0)
    log_error("bpf_send_packet: %m");
  return result;
}
#endif /* NEED_BPF */

/* Local Variables:  */
/* mode:C++ */
/* c-file-style:"gnu" */
/* end: */
