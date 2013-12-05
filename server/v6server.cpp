/* v6server.cpp
 *
 * Dummy DHCPv6 server.   This isn't a real v6 server, but it serves to test
 * the DHCPv6 client's basic code paths to make sure they work.
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

#ifndef lint
static char ocopyright[] __attribute__((unused)) =
  "$Id: v6server.cpp,v 1.2 2006/05/12 21:51:38 mellon Exp $ Copyright (c) 2005-2006 Nominum, Inc.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"
#include "server/v6server.h"

/* Existing client contexts... */
struct dhcpv6_client_context *DHCPv6Server::client_contexts;

/* This is so that we can do option_space_encapsulate without consing up
 * a special data string every time.
 */
static struct data_string dhcpv6 =
  { 0, (const unsigned char *)"dhcpv6", 6, 1 };


DHCPv6Server::DHCPv6Server(struct interface_info *ip, duid_t *duid)
{
  interface = ip;
  server_duid = duid;
}

/* Below are the set of virtual functions for the DHCPv6Listener
 * object that we actually implement - those that a server needs to
 * implement.  Because the client we're testing doesn't currently
 * do release or decline, the server doesn't have hooks for them
 * either.
 */

void DHCPv6Server::information_request(struct sockaddr_in6 *from,
				       unsigned char *contents, ssize_t length)
{
  confreq(from, contents, length, "DHCP Information Request");
}

void DHCPv6Server::solicit(struct sockaddr_in6 *from,
			   unsigned char *contents, ssize_t length)
{
  confreq(from, contents, length, "DHCP Solicit");
}

void DHCPv6Server::request(struct sockaddr_in6 *from,
			   unsigned char *contents, ssize_t length)
{
  confreq(from, contents, length, "DHCP Request");
}

void DHCPv6Server::renew(struct sockaddr_in6 *from,
			   unsigned char *contents, ssize_t length)
{
  confreq(from, contents, length, "DHCP Renew");
}

void DHCPv6Server::rebind(struct sockaddr_in6 *from,
			   unsigned char *contents, ssize_t length)
{
  confreq(from, contents, length, "DHCP Rebind");
}

void DHCPv6Server::confirm(struct sockaddr_in6 *from,
			   unsigned char *contents, ssize_t length)
{
  confreq(from, contents, length, "DHCP Confirm");
}

/* Handle a configuration request from a client.   This actually handles
 * all the possible messages that the current client can send, in an
 * extremely limited way.
 */

void DHCPv6Server::confreq(struct sockaddr_in6 *from,
			   unsigned char *inpacket,
			   ssize_t len, const char *name)
{
  struct option_cache *oc;
  struct option_cache *ias = 0;
  struct data_string packet;
  ssize_t result;
  struct sockaddr_in6 dest;
  char msgbuf[128];
  char addrbuf[128];
  struct ia *ia;
  struct dhcpv6_response *msg;
  struct dhcpv6_client_context *ctx;
  int i;
  const char *respname;
  struct option_state *send_options = new_option_state();
  unsigned char *s;

  /* Make the message to log. */
  inet_ntop(AF_INET6, &from->sin6_addr, addrbuf, sizeof addrbuf);
  snprintf(msgbuf, sizeof msgbuf, "%s from %s/%d on %s",
	   name, addrbuf, ntohs(from->sin6_port), interface->name);

  /* Decode the response.    If it's bogus, drop it right away. */
  msg = decode_dhcpv6_packet((unsigned char *)inpacket, len, name);
  if (!msg)
    return;

  /* Get the DUID option. */
  oc = lookup_option(&dhcpv6_option_space, msg->options, DHCPV6_DUID);
  if (!oc)
    {
      log_info("Dropping %s: no DUID", name);
      return;
    }

  /* Copy the client's DUID into the response. */
  save_option(&dhcpv6_option_space, send_options, oc);

  /* See if there's a client context for this message; if there isn't,
   * make one.
   */
  for (ctx = client_contexts; ctx; ctx = ctx->next)
    {
      if (ctx->duid.len == oc->data.len &&
	  !memcmp(&ctx->duid.data, oc->data.data, oc->data.len))
	{
	  break;
	}
    }
  if (!ctx)
    {
      ctx = (dhcpv6_client_context *)safemalloc(sizeof *ctx);
      memset(ctx, 0, sizeof *ctx);
      data_string_copy(&ctx->duid, &oc->data);
    }


  /* If there are no IAs, this had better be an Information Request
   * message.
   */
  if (!msg->ias && inpacket[0] != DHCPV6_INFORMATION_REQUEST)
    {
      log_info("%s: we weren't asked to configure anything.", msgbuf);
      return;
    }
	
  /* Very simple configuration - give it two IP addresses.   One will be
   * valid and preferred; the other will be deprecated, meaning valid but
   * not preferred.
   */
  i = 0;
  for (ia = msg->ias; ia; ia = ia->next)
    {
      struct ia_addr *addr;
      int j;

      ia->addresses = 0;
      for (j = 2; j < 4; j++)
	{
	  addr = (struct ia_addr *)
	    safemalloc(sizeof *ia->addresses);
	  addr->address.iabuf[0] = 0x20;
	  addr->address.iabuf[1] = 0x01;
	  addr->address.iabuf[2] = 0x04;
	  addr->address.iabuf[3] = 0xf8;
	  addr->address.iabuf[4] = 0x03;
	  addr->address.iabuf[5] = 0xba;
	  addr->address.iabuf[6] = j;
	  addr->address.iabuf[7] = 0x30;
	  addr->address.iabuf[8] = 0x48;
	  addr->address.iabuf[9] = 0xff;
	  addr->address.iabuf[10] = 0xfe;
	  addr->address.iabuf[11] = 0x41;
	  putUShort(&addr->address.iabuf[12], i * 2 + j - 2);
			
	  /* The client should renew in 50 seconds, despite the
	   * expiry of the second address.
	   */
	  if (j == 2)
	    {
	      addr->preferred = cur_time + 100;
	      addr->valid = cur_time + 100;
	    }
	  else
	    {
	      addr->preferred = cur_time;
	      addr->valid = cur_time + 25;
	    }
	  addr->next = ia->addresses;
	  ia->addresses = addr;
	}
    }

  /* Make IA options... */
  for (ia = msg->ias; ia; ia = ia->next)
    {
      oc = (struct option_cache *)safemalloc(sizeof *oc);
      memset(oc, 0, sizeof *oc);
      make_ia_option(&oc->data, ia, 0);
      oc->option = find_option(&dhcpv6_option_space, DHCPV6_IA_NA);

      /* Make a linked list of IA options, and when we've made the
       * last IA option, stash it in client->send_options.
       */
      oc->next = ias;
      ias = oc;
    }
  if (ias)
    save_option(&dhcpv6_option_space, send_options, ias);

  /* Make the server DUID option. */
  oc = (struct option_cache *)safemalloc(sizeof *oc);
  memset(oc, 0, sizeof *oc);
  oc->option = find_option(&dhcpv6_option_space,
			   DHCPV6_SERVER_IDENTIFIER);
  oc->data.data = (unsigned char *)&server_duid->data;
  oc->data.len = server_duid->len;
  save_option(&dhcpv6_option_space, send_options, oc);

  /* Make a DNS server option. */
  oc = (struct option_cache *)safemalloc(sizeof *oc);
  memset(oc, 0, sizeof *oc);
  oc->option = find_option(&dhcpv6_option_space,
			   DHCPV6_DOMAIN_NAME_SERVERS);
  oc->data.data = s = (unsigned char *)safemalloc(16);
  oc->data.len = 16;
  s[0] = 0x20;
  s[1] = 0x01;
  s[2] = 0x04;
  s[3] = 0xf8;
  s[4] = 0x03;
  s[5] = 0xba;
  s[6] = 0x02;
  s[7] = 0x30;
  s[8] = 0x48;
  s[9] = 0xff;
  s[10] = 0xfe;
  s[11] = 0x41;
  putUShort(&s[12], 65534);
	
  save_option(&dhcpv6_option_space, send_options, oc);

  dest.sin6_family = AF_INET6;
  dest.sin6_port = remote_port_dhcpv6;
#ifdef HAVE_SA_LEN
  dest.sin6_len = sizeof dest;
#endif
  memcpy(&dest.sin6_addr, &from->sin6_addr, 16);

  /* Start out with a 200 byte buffer; the option encapsulation code
   * will expand it as needed.
   */
  memset(&packet, 0, sizeof packet);
  packet.buffer = buffer_allocate(200);
  packet.data = packet.buffer->data;

  /* The DHCPv6 message header consists of a single byte of message
   * type, followed by three bytes of transaction ID in sort-of
   * network byte order.   There's no pretty way to do this, but we
   * can at least take advantage of the fact that the MSB of a 32-bit
   * integer stored in network byte order corresponds to the first
   * byte, so what we do is to encode the transaction ID as a 32-bit
   * number, and then overwrite the MSB with the type code.
   */
  putULong(packet.buffer->data, msg->xid);
  if (inpacket[0] == DHCPV6_SOLICIT)
    {
      respname = "DHCP Advertise";
      packet.buffer->data[0] = DHCPV6_ADVERTISE;
    }
  else
    {
      respname = "DHCP Reply";
      packet.buffer->data[0] = DHCPV6_REPLY;
    }
  packet.len = 4;

  /* Now we can just encapsulate the options into the packet fairly
   * painlessly.
   */
  if (!option_space_encapsulate(&packet, send_options, &dhcpv6))
    {
      log_fatal ("%s: couldn't encapsulate", msgbuf);
    }

  inet_ntop(AF_INET6, &dest.sin6_addr, addrbuf, sizeof addrbuf);
  log_info("%s: sending %s to %s port %d",
	   msgbuf, respname, addrbuf, ntohs(dest.sin6_port));

  /* Send out a packet. */
  result = send_packet(interface, packet.buffer->data, packet.len,
		       (struct sockaddr *)&dest);
}

/* Local Variables:  */
/* mode:C++ */
/* c-file-style:"gnu" */
/* end: */
