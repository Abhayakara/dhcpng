/* v6listener.h
 *
 * Definitions for the DHCPv6Listener class.
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
#include "dhc++/v6listener.h"

/* Doesn't do anything but make the linker happy.   I'm confused as to
 * why I can't just make the destructor pure and not write any code for
 * it.   Sigh.   I'm sure there's a good reason.
 */
DHCPv6Listener::~DHCPv6Listener()
{
}

/* Called whenever a DHCPv6 packet comes in.   Static. */

isc_result_t DHCPv6Listener::got_packet(dhcpv6_response *response, struct sockaddr_in6 *from,
					const unsigned char *contents, ssize_t length)
{
  /* A DHCPv6 listener could be a client, a server or a relay agent,
   * so in general it probably will only implement those methods that
   * pertain to their particular aspect of the protocol.   However,
   * we dispatch every possible kind of message - if it turns out that
   * the listener doesn't want the message, it'll just go to the appropriate
   * function in this class, which will do nothing.
   */

  /* O frabjous day, caloo calay!   We don't have to decode the packet
   * to figure out what kind of packet it is!
   */
  switch(response->message_type)
    {
    case DHCPV6_SOLICIT:
      solicit(response, from, contents, length);
      break;

    case DHCPV6_REQUEST:
      request(response, from, contents, length);
      break;

    case DHCPV6_INFORMATION_REQUEST:
      information_request(response, from, contents, length);
      break;

    case DHCPV6_RENEW:
      renew(response, from, contents, length);
      break;

    case DHCPV6_REBIND:
      rebind(response, from, contents, length);
      break;

    case DHCPV6_RELEASE:
      release(response, from, contents, length);
      break;

    case DHCPV6_DECLINE:
      decline(response, from, contents, length);
      break;

    case DHCPV6_CONFIRM:
      confirm(response, from, contents, length);
      break;

      /* We also shouldn't ever get a relay-forward message. */
    case DHCPV6_RELAY_FORWARD:
      relay_forward(response, from, contents, length);
      break;

      /* At some point we may want to be able to fake up
       * relayed messages for testing, in which case we
       * might unpack a relay-reply message, but for now
       * we're not processing it either.
       */
    case DHCPV6_RELAY_REPLY:
      relay_reply(response, from, contents, length);
      break;

    case DHCPV6_ADVERTISE:
      advertise(response, from, contents, length);
      break;

    case DHCPV6_REPLY:
      reply(response, from, contents, length);
      break;

    case DHCPV6_RECONFIGURE:
      advertise(response, from, contents, length);
      break;
    }
  return ISC_R_SUCCESS;
}

/* Client-sourced message requesting information, but no IP address
 * configuration.
 */
bool DHCPv6Listener::mine(struct dhcpv6_response *rsp)
{
}

/* Client-sourced message requesting information, but no IP address
 * configuration.
 */
void DHCPv6Listener::information_request(struct dhcpv6_response *response, struct sockaddr_in6 *from,
					 const unsigned char *packet, unsigned length)
{
}

/* Client-sourced message requesting that servers identify themselves and
 * indicate what sort of service they are willing to offer.
 */
void DHCPv6Listener::solicit(struct dhcpv6_response *response, struct sockaddr_in6 *from,
			     const unsigned char *contents, unsigned length)
{
}

/* Server-sourced message offering service to a client in response to a
 * solicit.
 */
void DHCPv6Listener::advertise(struct dhcpv6_response *response, struct sockaddr_in6 *from,
			       const unsigned char *packet, unsigned length)
{
}

/* Client-sourced message requesting that a server allocate the particular
 * address to the client that it offered in a previous solicit message.
 */
void DHCPv6Listener::request(struct dhcpv6_response *response, struct sockaddr_in6 *from,
			     const unsigned char *packet, unsigned length)
{
}

/* Client-sourced message requesting that the server extend the preferred
 * lifetimes on whatever addresses the server has given to the client.
 */
void DHCPv6Listener::renew(struct dhcpv6_response *response, struct sockaddr_in6 *from,
			   const unsigned char *packet, unsigned length)
{
}

/* Client-sourced message requesting that any server extend the preferred
 * lifetimes on whatever addresses the client received.
 */
void DHCPv6Listener::rebind(struct dhcpv6_response *response, struct sockaddr_in6 *from,
			    const unsigned char *packet, unsigned length)
{
}

/* Client-sourced message indicating that it is done using the addresses
 * it received, and that the server should return these addresses to the
 * pool of available addresses.
 */
void DHCPv6Listener::release(struct dhcpv6_response *response, struct sockaddr_in6 *from,
			     const unsigned char *packet, unsigned length)
{
}

/* Client-sourced message indicating that the address a server granted to
 * the client actually is in use by some other device.
 */
void DHCPv6Listener::decline(struct dhcpv6_response *response, struct sockaddr_in6 *from,
			     const unsigned char *packet, unsigned length)
{
}

/* Client-sourced message requesting that any available server confirm
 * that the prefixes present in the client's addresses are valid on the
 * link to which the client is presently attached.
 */
void DHCPv6Listener::confirm(struct dhcpv6_response *response, struct sockaddr_in6 *from,
			     const unsigned char *packet, unsigned length)
{
}

/* Reply from the server in response to any client message other than a
 * solicit message.
 */
void DHCPv6Listener::reply(struct dhcpv6_response *response, struct sockaddr_in6 *from,
			   const unsigned char *data, unsigned length)
{
}

/* Message from a relay agent to a server or another relay agent, which
 * encapsulated a message from a client.
 */
void DHCPv6Listener::relay_forward(struct dhcpv6_response *response, struct sockaddr_in6 *from,
				   const unsigned char *data, unsigned length)
{
}

/* Message from a server or relay agent to another relay agent, ultimately
 * containing an encapsulated message from the server to a client.
 */
void DHCPv6Listener::relay_reply(struct dhcpv6_response *response, struct sockaddr_in6 *from,
				 const unsigned char *data, unsigned length)
{
}

/* Unsolicited message from server to client, indicating that it should
 * contact the server for new configuration information.
 */
void DHCPv6Listener::reconfigure(struct dhcpv6_response *response, struct sockaddr_in6 *from,
				 const unsigned char *data, unsigned length)
{
}

/* Local Variables:  */
/* mode:c++ */
/* c-file-style:"gnu" */
/* end: */
