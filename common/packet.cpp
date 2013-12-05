/* packet.c
 * 
 * Packet assembly code, originally contributed by Archie Cobbs.
 */

/*
 * Copyright (c) 2002-2006 Nominum, Inc.  All rights reserved.
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
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES(INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef lint
static char copyright[] __attribute__((unused)) =
  "$Id: packet.cpp,v 1.5 2009/09/22 05:33:10 mellon Exp $ Copyright(c) 1996-2001 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

#if defined(NEED_PACKET_ASSEMBLY) || defined(NEED_PACKET_DECODING)
#include "includes/netinet/ip.h"
#include "includes/netinet/udp.h"
#include "includes/netinet/if_ether.h"

/* Compute the easy part of the checksum on a range of bytes. */

u_int32_t
checksum(unsigned char *buf, unsigned nbytes, u_int32_t sum)
{
  unsigned i;

#ifdef DEBUG_CHECKSUM
  log_debug("checksum(%x %d %x)", buf, nbytes, sum);
#endif

  /* Checksum all the pairs of bytes first... */
  for (i = 0; i <(nbytes & ~1U); i += 2)
    {
#ifdef DEBUG_CHECKSUM_VERBOSE
      log_debug("sum = %x", sum);
#endif
      sum += (u_int16_t) ntohs(*((u_int16_t *)(buf + i)));
      /* Add carry. */
      if (sum > 0xFFFF)
	sum -= 0xFFFF;
    }	

  /* If there's a single byte left over, checksum it, too.   Network
     byte order is big-endian, so the remaining byte is the high byte. */
  if (i < nbytes)
    {
#ifdef DEBUG_CHECKSUM_VERBOSE
      log_debug("sum = %x", sum);
#endif
      sum += buf[i] << 8;
      /* Add carry. */
      if (sum > 0xFFFF)
	sum -= 0xFFFF;
    }
	
  return sum;
}

/* Finish computing the checksum, and then put it into network byte order. */

u_int32_t
wrapsum(u_int32_t sum)
{
#ifdef DEBUG_CHECKSUM
  log_debug("wrapsum(%x)", sum);
#endif

  sum = ~sum & 0xFFFF;
#ifdef DEBUG_CHECKSUM_VERBOSE
  log_debug("sum = %x", sum);
#endif
	
#ifdef DEBUG_CHECKSUM
  log_debug("wrapsum returns %x", htons(sum));
#endif
  return htons(sum);
}
#endif /* NEED_PACKET_ASSEMBLY || NEED_PACKET_DECODING */

#if defined(NEED_PACKET_ASSEMBLY)
void assemble_ethernet_header (struct interface_info *interface,
			       unsigned char *buf,
			       unsigned *bufix,
			       struct hardware *to)
{
  struct isc_ether_header eh;

  if (to && to->hlen == 7)
    memcpy (eh.ether_dhost, &to->hbuf[1], sizeof eh.ether_dhost);
  else
    memset (eh.ether_dhost, 0xff, sizeof (eh.ether_dhost));
  if (interface->lladdr.hlen - 1 == sizeof (eh.ether_shost))
    memcpy (eh.ether_shost, &interface->lladdr.hbuf[1],
	    sizeof (eh.ether_shost));
  else
    memset (eh.ether_shost, 0x00, sizeof (eh.ether_shost));

  eh.ether_type = htons (ETHERTYPE_IP);

  memcpy (&buf[*bufix], &eh, ETHER_HEADER_SIZE);
  *bufix += ETHER_HEADER_SIZE;
}

/* UDP header and IP header assembled together for convenience. */

void assemble_udp_ip_header(struct interface_info *interface,
			    unsigned char *buf,
			    unsigned *bufix,
			    u_int32_t from,
			    u_int32_t to,
			    u_int32_t port,
			    unsigned char *data,
			    unsigned len)
{
  struct ip ip;
  struct udphdr udp;

  /* Fill out the IP header */
  IP_V_SET(&ip, 4);
  IP_HL_SET(&ip, 20);
  ip.ip_tos = IPTOS_LOWDELAY;
  ip.ip_len = htons(sizeof(ip) + sizeof(udp) + len);
  ip.ip_id = 0;
  ip.ip_off = 0;
  ip.ip_ttl = 64;
  ip.ip_p = IPPROTO_UDP;
  ip.ip_sum = 0;
  ip.ip_src.s_addr = from;
  ip.ip_dst.s_addr = to;
	
  /* Checksum the IP header... */
  ip.ip_sum = wrapsum(checksum((unsigned char *)&ip, sizeof ip, 0));
	
  /* Copy the ip header into the buffer... */
  memcpy(&buf[*bufix], &ip, sizeof ip);
  *bufix += sizeof ip;

  /* Fill out the UDP header */
  udp.uh_sport = local_port;		/* XXX */
  udp.uh_dport = port;			/* XXX */
  udp.uh_ulen = htons(sizeof(udp) + len);
  memset(&udp.uh_sum, 0, sizeof udp.uh_sum);

  /* Compute UDP checksums, including the ``pseudo-header'', the UDP
     header and the data. */

  udp.uh_sum =
    wrapsum(checksum((unsigned char *)&udp, sizeof udp,
		     checksum(data, len, 
			      checksum((unsigned char *)
				       &ip.ip_src,
				       2 * sizeof ip.ip_src,
				       IPPROTO_UDP +
				       (u_int32_t)
				       ntohs(udp.uh_ulen)))));

  /* Copy the udp header into the buffer... */
  memcpy(&buf[*bufix], &udp, sizeof udp);
  *bufix += sizeof udp;
}
#endif /* NEED_PACKET_ASSEMBLY */

#if defined(NEED_PACKET_DECODING)
/* Decode a hardware header... */
ssize_t decode_ethernet_header(struct interface_info *interface,
			       unsigned char *buf,
			       unsigned bufix,
			       struct hardware *from)
{
  struct isc_ether_header eh;

  memcpy (&eh, buf + bufix, ETHER_HEADER_SIZE);

#if defined(NEED_USERLAND_FILTER)
  if (ntohs (eh.ether_type) != ETHERTYPE_IP)
	  return -1;
#endif
  memcpy (&from -> hbuf[1], eh.ether_shost, sizeof (eh.ether_shost));
  from -> hbuf[0] = ARPHRD_ETHER;
  from -> hlen = (sizeof eh.ether_shost) + 1;

  return ETHER_HEADER_SIZE;
}

/* UDP header and IP header decoded together for convenience. */

ssize_t decode_udp_ip_header(struct interface_info *interface,
			     unsigned char *buf,
			     unsigned bufix,
			     struct sockaddr_in *from,
			     unsigned buflen,
			     unsigned *rbuflen)
{
  struct ip *ip;
  struct udphdr *udp;
  u_int32_t ip_len = (buf[bufix] & 0xf) << 2;
  u_int32_t sum, usum;
  static int ip_packets_seen;
  static int ip_packets_bad_checksum;
  static int udp_packets_seen;
  static int udp_packets_bad_checksum;
  static int udp_packets_length_checked;
  static int udp_packets_length_overflow;
  unsigned len;
  unsigned ulen;
  int ignore = 0;
  unsigned char *data;

  ip = (struct ip *)(buf + bufix);
  udp = (struct udphdr *)(buf + bufix + ip_len);

#if defined(NEED_USERLAND_FILTER)
  /* Is it a UDP packet? */
  if (ip->ip_p != IPPROTO_UDP)
    return -1;

  /* Is it to the port we're serving? */
  if (udp->uh_dport != local_port)
    return -1;
#endif /* USERLAND_FILTER */

  /* XXX I took out the code here that eliminates packets not destined
   * XXX either for one of the configured IP addresses or for the limited
   * XXX broadcast address, because I don't think it actually works for the
   * XXX DHCP client, and I don't need to support the DHCP server.   Hopefully
   * XXX the Linux guys will fix the limited broadcast bug and we can just
   * XXX entirely eliminate this code, but if this code were needed e.g. for
   * XXX a relay agent, then you'd need to put those tests back in and make
   * XXX them robust in the presence of a DHCP client.
   */

  /* Check the UDP packet length. */
  ulen = ntohs(udp->uh_ulen);
  if (ulen < sizeof *udp ||
      ((unsigned char *)udp) + ulen > buf + bufix + buflen)
    {
      log_info("bogus UDP packet length: %d", ulen);
      return -1;
    }

  /* Check the IP header checksum - it should be zero. */
  ++ip_packets_seen;
  if (wrapsum(checksum(buf + bufix, ip_len, 0)))
    {
      ++ip_packets_bad_checksum;
      if (ip_packets_seen > 4 &&
	  (ip_packets_seen / ip_packets_bad_checksum) < 2)
	{
	  log_info("%d bad IP checksums seen in %d packets",
		   ip_packets_bad_checksum, ip_packets_seen);
	  ip_packets_seen = ip_packets_bad_checksum = 0;
	}
      return -1;
    }

  /* Check the IP packet length. */
  if ((unsigned)(ntohs(ip->ip_len)) != buflen)
    {
      if ((unsigned)(ntohs(ip->ip_len + 2) & ~1) == buflen)
	ignore = 1;
      else
	log_debug("ip length %d disagrees with bytes received %d.",
		  ntohs(ip->ip_len), buflen);
    }

  /* Copy out the IP source address... */
  memcpy(&from->sin_addr, &ip->ip_src, 4);

  /* Compute UDP checksums, including the ``pseudo-header'', the UDP
     header and the data.   If the UDP checksum field is zero, we're
     not supposed to do a checksum. */

  data = buf + bufix + ip_len + sizeof *udp;
  len = ulen - sizeof *udp;
  ++udp_packets_length_checked;

  if (len + data > buf + bufix + buflen)
    {
      ++udp_packets_length_overflow;
      if (udp_packets_length_checked > 4 &&
	  (udp_packets_length_checked /
	   udp_packets_length_overflow) < 2)
	{
	  log_info("%d udp packets in %d too long - dropped",
		   udp_packets_length_overflow,
		   udp_packets_length_checked);
	  udp_packets_length_overflow =
	  udp_packets_length_checked = 0;
	}
      return -1;
    }

  if (len + data < buf + bufix + buflen &&
      len + data != buf + bufix + buflen && !ignore)
    log_debug("accepting packet with data after udp payload.");

  if (len + data > buf + bufix + buflen)
    {
      log_debug("dropping packet with bogus uh_ulen %ld",
		(long)(len + sizeof *udp));
      return -1;
    }

  usum = udp->uh_sum;
  udp->uh_sum = 0;

  sum = wrapsum(checksum((unsigned char *)udp, sizeof *udp,
			 checksum(data, len,
				  checksum((unsigned char *)
					   &ip->ip_src,
					   2 * sizeof ip->ip_src,
					   IPPROTO_UDP +
					   (u_int32_t)ulen))));

  udp_packets_seen++;
  if (usum && usum != sum)
    {
      udp_packets_bad_checksum++;
      if (udp_packets_seen > 4 &&
	  (udp_packets_seen / udp_packets_bad_checksum) < 2)
	{
	  log_info("%d bad udp checksums in %d packets",
		   udp_packets_bad_checksum, udp_packets_seen);
	  udp_packets_seen = udp_packets_bad_checksum = 0;
	}
      return -1;
    }

  /* Copy out the port... */
  memcpy(&from->sin_port, &udp->uh_sport, sizeof udp->uh_sport);

  *rbuflen = ntohs(ip->ip_len) - ip_len - sizeof *udp;
  return ip_len + sizeof *udp;
}
#endif /* NEED_PACKET_DECODING */

/* Local Variables:  */
/* mode:C++ */
/* c-file-style:"gnu" */
/* end: */
