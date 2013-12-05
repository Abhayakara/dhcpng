/* lpf.cpp
 *
 * Linux packet filter code, contributed by Brian Murrel at Interlinx
 * Support Services in Vancouver, B.C.
 *
 * This code is provided as a temporary stopgap until a couple of linux
 * kernel bugs are fixed, and is not intended to be comprehensive.
 */

/*
 * Copyright (c) 2002-2006 Nominum, Inc.   All rights reserved.
 *
 * Copyright (c) 1996-2002 Internet Software Consortium.
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
 * 3. Neither the name of The Internet Software Consortium nor the names
 *    of its contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INTERNET SOFTWARE CONSORTIUM AND
 * CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE INTERNET SOFTWARE CONSORTIUM OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES(INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef lint
static char copyright[] __attribute__((unused)) =
  "$Id: lpf.cpp,v 1.4 2009/09/22 05:33:41 mellon Exp $ Copyright(c) 1996-2002 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"
#if defined(NEED_LPF)
#include <sys/ioctl.h>
#include <sys/uio.h>

#include <asm/types.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <netinet/in_systm.h>
#include "includes/netinet/ip.h"
#include "includes/netinet/udp.h"
#include "includes/netinet/if_ether.h"

#include "dhc++/v4listener.h"

/* Defined in bpf.c.   We can't extern these in dhcpd.h without pulling
 * in bpf includes...
 */
struct sock_filter dhcp_lpf_filter [] = {
	/* Make sure this is an IP packet... */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IP, 0, 10),

	/* Make sure it's a UDP packet... */
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 23),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_UDP, 0, 8),

	/* Make sure this isn't a fragment... */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 20),
	BPF_JUMP(BPF_JMP + BPF_JSET + BPF_K, 0x1fff, 6, 0),

	/* Make sure it's to the all-one's IP address. */
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 30),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0xffffffff, 0, 4),

	/* Get the IP header length... */
	BPF_STMT(BPF_LDX + BPF_B + BPF_MSH, 14),

	/* Make sure it's to the right port... */
	BPF_STMT(BPF_LD + BPF_H + BPF_IND, 16),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 67, 0, 1),             /* patch */

	/* If we passed all the tests, ask for the whole packet. */
	BPF_STMT(BPF_RET+BPF_K, (u_int)-1),

	/* Otherwise, drop it. */
	BPF_STMT(BPF_RET+BPF_K, 0),
};
int dhcp_lpf_filter_len = sizeof dhcp_lpf_filter / sizeof (struct sock_filter);

static void
lpf_gen_filter_setup(int rfdesc)
{
  struct sock_fprog p;

  /* Set up the bpf filter program structure.    This is defined in
     bpf.c */
  p.len = dhcp_lpf_filter_len;
  p.filter = dhcp_lpf_filter;

  /* Patch the server port into the LPF  program...
     XXX changes to filter program may require changes
     to the insn number(s) used below! XXX */
  dhcp_lpf_filter[10].k = ntohs((short)local_port);

  if (setsockopt(rfdesc, SOL_SOCKET, SO_ATTACH_FILTER, &p, sizeof p) < 0)
    {
      if (errno == ENOPROTOOPT || errno == EPROTONOSUPPORT ||
	  errno == ESOCKTNOSUPPORT || errno == EPFNOSUPPORT ||
	  errno == EAFNOSUPPORT)
	{
	  log_error("socket: %m - make sure");
	  log_error("CONFIG_PACKET(Packet socket) %s",
		     "and CONFIG_FILTER");
	  log_error("(Socket Filtering) are enabled %s",
		     "in your kernel");
	  log_fatal("configuration!");
	}
      log_fatal("Can't install packet filter program: %m");
    }
}

static isc_result_t
receive_packet_worker(struct interface_info *ifp)
{
  int length = 0;
  int offset = 0;
  unsigned char ibuf[4096];
  union {
    unsigned char packbuf[4096];
    u_int64_t aligneything;
  } u;
  unsigned bufix = 0;
  unsigned paylen;
  struct sockaddr_in from;
  struct hardware hfrom;
  char buf[100];

  printf("in lpf receive_packet_worker...\n");
  length = read(ifp->pf_sock, ibuf, sizeof ibuf);
  if (length < 0)
    return uerr2isc(errno);

  bufix = 0;
  /* Decode the physical header... */
  offset = decode_ethernet_header(ifp, ibuf, bufix, &hfrom);

  /* If a physical layer checksum failed (dunno of any physical layer
   * that supports this, but WTH), skip this packet.
   */
  if (offset < 0)
    {
      printf("dropping out because link layer decode failed.\n");
      return ISC_R_SUCCESS;
    }

  bufix += offset;
  length -= offset;

  /* Decode the IP and UDP headers... */
  offset = decode_udp_ip_header(ifp, ibuf, bufix, &from,
				(unsigned)length, &paylen);

  /* If the IP or UDP checksum was bad, skip the packet... */
  if (offset < 0)
    {
      printf("dropping out because ip/udp layer decode failed.\n");
      return ISC_R_SUCCESS;
    }

  bufix += offset;
  length -= offset;

  /* Copy out the data in the packet... */
  memcpy(u.packbuf, &ibuf[bufix], paylen);

  if (ifp->v4listener)
    {
      printf("passing it to the listener.\n");
      return ifp->v4listener->got_packet(ifp, &from, u.packbuf, paylen);
    }
  else
    {
      inet_ntop(from.sin_family, (void *)&from.sin_addr, buf, sizeof buf);
      log_error("Dropping packet from %s on %s - no listener object",
		buf, ifp->name);
    }
  return ISC_R_SUCCESS;
}

/* Called by io handler code in dispatch.cpp to get the socket file descriptor
 * so that it can be used in select().
 */

static int
if_readsocket(void *v)
{
  struct interface_info *ip = (struct interface_info *)v;
  return ip->pf_sock;
}

/* Called by io handler code in dispatch.cpp whenever the socket for this
 * lpf reports to select that it is readable.
 */
static isc_result_t
receive_packet(void *v)
{
  struct interface_info *ip = (struct interface_info *)v;
  return receive_packet_worker(ip);
}

/* Called by get_interface_list for each interface that's discovered.
 * Opens a packet filter for each interface and adds it to the select
 * mask.
 */

void
lpf_setup(struct interface_info *info)
{
  int sock;
  struct sockaddr sa;

  /* Make an LPF socket. */
  if ((sock = socket(PF_PACKET, SOCK_PACKET,
		     htons((short)ETH_P_ALL))) < 0)
    {
      if (errno == ENOPROTOOPT || errno == EPROTONOSUPPORT ||
	  errno == ESOCKTNOSUPPORT || errno == EPFNOSUPPORT ||
	  errno == EAFNOSUPPORT || errno == EINVAL)
	{
	  log_error("socket: %m - make sure");
	  log_error("CONFIG_PACKET(Packet socket) %s",
		     "and CONFIG_FILTER");
	  log_error("(Socket Filtering) are enabled %s",
		     "in your kernel");
	  log_fatal("configuration!");
	}
      log_fatal("Open a socket for LPF: %m");
    }

  /* Bind to the interface name */
  memset(&sa, 0, sizeof sa);
  sa.sa_family = AF_PACKET;
  strncpy(sa.sa_data, (const char *)info->name, sizeof sa.sa_data);
  if (bind(sock, &sa, sizeof sa))
    {
      if (errno == ENOPROTOOPT || errno == EPROTONOSUPPORT ||
	  errno == ESOCKTNOSUPPORT || errno == EPFNOSUPPORT ||
	  errno == EAFNOSUPPORT || errno == EINVAL)
	{
	  log_error("socket: %m - make sure");
	  log_error("CONFIG_PACKET(Packet socket) %s",
		     "and CONFIG_FILTER");
	  log_error("(Socket Filtering) are enabled %s",
		     "in your kernel");
	  log_fatal("configuration!");
	}
      log_fatal("Bind socket to interface: %m");
    }

  lpf_gen_filter_setup(sock);

  info->pf_sock = sock;
  register_io_object(info, if_readsocket, 0, receive_packet, 0, 0);
}
#endif

/* Local Variables:  */
/* mode:C++ */
/* c-file-style:"gnu" */
/* end: */
