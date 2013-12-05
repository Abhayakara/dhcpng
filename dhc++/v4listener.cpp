/* v4listener.h
 *
 * Definitions for the DHCPv4Listener class.
 */

/* Copyright (c) 2005-2006 Nominum, Inc.   All rights reserved.
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

#include "dhcpd.h"
#include "dhc++/v4listener.h"

/* Doesn't do anything but make the linker happy.   I'm confused as to
 * why I can't just make the destructor pure and not write any code for
 * it.   Sigh.   I'm sure there's a good reason.
 */
DHCPv4Listener::~DHCPv4Listener()
{
}

/* Called whenever a DHCPv4 packet comes in.   Static. */

isc_result_t DHCPv4Listener::got_packet(struct interface_info *interface,
					struct sockaddr_in *from,
					unsigned char *contents, ssize_t length)
{
  struct dhcp_packet *packet = (struct dhcp_packet *)contents;
  struct option_cache *op;
  struct packet *decoded_packet;

  /* If we didn't at least get the fixed portion of the BOOTP
     packet, drop the packet.  We're allowing packets with no
     sname or filename, because we're aware of at least one
     client that sends such packets, but this definitely falls
     into the category of being forgiving. */
  if (length < DHCP_FIXED_NON_UDP - DHCP_SNAME_LEN - DHCP_FILE_LEN)
    {
      return ISC_R_UNEXPECTED;
    }

  decoded_packet = (struct packet *)safemalloc(sizeof *decoded_packet);
  decoded_packet->raw = packet;
  decoded_packet->packet_length = length;
  decoded_packet->client_port = ntohs(from->sin_port);
  memcpy(decoded_packet->sender_addr.iabuf, &from->sin_addr, 4);
  decoded_packet->sender_addr.len = 4;
  decoded_packet->interface = interface;
	
  if (packet->hlen > sizeof packet->chaddr)
    {
      log_info ("Discarding packet with bogus hlen.");
      return ISC_R_FORMERR;
    }

  /* If there's an option buffer, try to parse it. */
  if (decoded_packet->packet_length >= DHCP_FIXED_NON_UDP + 4)
    {
      if (!parse_options(decoded_packet))
	{
	  return ISC_R_FORMERR;
	}

      if (decoded_packet->options_valid &&
	  (op = lookup_option(&dhcp_option_space, decoded_packet->options, 
			      DHO_DHCP_MESSAGE_TYPE)))
	{
	  if (op->data.len == 1)
	    decoded_packet->packet_type = op->data.data[0];
	  else
	    decoded_packet->packet_type = 0;
	}
    }
		
  /* A DHCPv4 listener could be a client, a server or a relay agent,
   * so in general it probably will only implement those methods that
   * pertain to their particular aspect of the protocol.   However,
   * we dispatch every possible kind of message - if it turns out that
   * the listener doesn't want the message, it'll just go to the appropriate
   * function in this class, which will do nothing.
   *
   * Note that DHCP is really a bag on the side of BOOTP, so the way
   * we determine whether or not we're doing DHCP is to detect the presence
   * of a 'dhcp message type' option; if it's there, this is a DHCP packet,
   * and if it's not, it's a BOOTP packet.   There's a virtual method for
   * each DHCP packet type and each BOOTP packet type.
   */

  if (!decoded_packet->packet_type)
    {
      bootp(decoded_packet);
    }
  else
    {
      dhcp(decoded_packet);
    }
  return ISC_R_SUCCESS;
}

void
DHCPv4Listener::dhcp(struct packet *decoded_packet)
{
  switch(decoded_packet->packet_type)
    {
    case DHCPDISCOVER:
      discover(decoded_packet);
      break;
      
    case DHCPOFFER:
      offer(decoded_packet);
      break;
      
    case DHCPREQUEST:
      request(decoded_packet);
      break;
      
    case DHCPDECLINE:
      decline(decoded_packet);
      break;
      
    case DHCPACK:
      ack(decoded_packet);
      break;
      
    case DHCPNAK:
      nak(decoded_packet);
      break;
      
    case DHCPRELEASE:
      release(decoded_packet);
      break;
      
    case DHCPINFORM:
      inform(decoded_packet);
      break;
      
    default:
      log_info("discarding packet with unknown DHCP type %d",
	       decoded_packet->packet_type);
    }
}

void DHCPv4Listener::bootp(struct packet *decoded_packet)
{
  if (decoded_packet->raw->op == BOOTREQUEST)
    {
      bootrequest(decoded_packet);
    }
  else if (decoded_packet->raw->op == BOOTREPLY)
    {
      bootreply(decoded_packet);
    }
  else
    {
      log_info("discarding BOOTP packet with bogus op = %d",
	       decoded_packet->raw->op);
    }
}

/* DHCP client broadcasts this to find one or more DHCP servers. */
void DHCPv4Listener::bootrequest(struct packet *packet)
{
}

/* DHCP client broadcasts this to find one or more DHCP servers. */
void DHCPv4Listener::bootreply(struct packet *packet)
{
}

/* DHCP client broadcasts this to find one or more DHCP servers. */
void DHCPv4Listener::discover(struct packet *packet)
{
}

/* DHCP servers send this to clients in response to DHCPDISCOVER. */
void DHCPv4Listener::offer(struct packet *packet)
{
}

/* DHCP client, after picking one of the one or more servers that responded
 * to the DHCPDISCOVER, broadcasts this.   It unicasts this to renew a lease,
 * broadcasts it if it fails to contact its server when renewing, and also
 * broadcasts it to reconfirm the lease on startup if it finds that it has
 * a valid lease from before it was shut down.   So this is a busy little
 * packet type.
 */
void DHCPv4Listener::request(struct packet *packet)
{
}

/* DHCP client sends to the server if, after getting a DHCPACK, it gets an
 * ARP reply when it ARPs for the address it got from the server.
 */
void DHCPv4Listener::decline(struct packet *packet)
{
}

/* DHCP server sends this to the client in response to any of the DHCPREQUEST
 * packets mentioned above, in order to tell the client that it can use the
 * address it requested.   The server also sends this in response to a
 * DHCPINFORM.
 */
void DHCPv4Listener::ack(struct packet *packet)
{
}

/* DHCP server sends this to the client in response to any DHCPREQUEST
 * packet (although there's some controversy over whether this is permissible
 * in the RENEWING and REBINDING states.   This indicates that the address
 * the client requested is _not_ valid on the network to which it is attached.
 */
void DHCPv4Listener::nak(struct packet *packet)
{
}

/* DHCP client sends this to the server when it intends to stop using an
 * IP address it acquired previously and for which it still has a valid
 * lease.
 */
void DHCPv4Listener::release(struct packet *packet)
{
}

/* DHCP client sends this to get configuration information without allocating
 * or renewing an IP address.
 */
void DHCPv4Listener::inform(struct packet *packet)
{
}


/* Local Variables:  */
/* mode:c++ */
/* c-file-style:"gnu" */
/* end: */
