/* v6client.cpp
 *
 * DHCPv6 protocol engine class.
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
"$Id: v6client.cpp,v 1.22 2012/04/01 21:26:34 mellon Exp $ Copyright (c) 2005-2006 Nominum, Inc.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"
#include "version.h"

#include "client/v6client.h"
#include "client/controller.h"
#include "client/client.h"

/* This is so that we can do option_space_encapsulate without consing up
 * a special data string every time.
 */
static struct data_string dhcpv6 = { 0, (const unsigned char *)"dhcpv6", 6, 1 };

DHCPv6Client::DHCPv6Client(struct interface_info *ip,
			   DHCPClientController *ctlr,
			   u_int8_t *duid_string, int duid_size)
{
  config = ((struct client_config *)safemalloc(sizeof (struct client_config)));
  memcpy(config, &top_level_config, sizeof top_level_config);
  config->interface = ip;
  duid = (duid_t *)safemalloc(duid_size + sizeof (u_int32_t));
  duid->len = duid_size;
  memcpy((char *)&duid->data, duid_string, duid_size);
  log_info("DHCPv6 Client DUID is %s",
           print_hex_1(duid->len,
		       (unsigned char *)&duid->data, 80));
  xid = random();
  state = S6_UNMANAGED;
  next_state = S6_UNMANAGED;
  retransmit_count = 0;

  ias = (struct ia *)safemalloc(sizeof (struct ia));
  memset(ias, 0, sizeof *ias);
  ias->id = htonl(ip->index);

  controller = ctlr;

  responses = selected_response = 0;
  server_identifier = 0;
  send_options = 0;
  recv_options = 0;
  sending_name = 0;

  relay_destination.len = 0;
}

int DHCPv6Client::set_relay_destination(char *dest)
{
  struct in6_addr in6;
  if (!inet_pton(AF_INET6, dest, &in6))
    {
      printf("bad destination: %s\n", dest);
      return 0;
    }
  printf("Destination %s: ", dest);
  fflush(stdout);
  dump_raw(destination.iabuf, 16);
  dump_raw((const unsigned char *)&in6, sizeof in6);

  memcpy(relay_destination.iabuf, &in6, 16);
  relay_destination.len = 16;
  return 1;
}

bool DHCPv6Client::mine(struct dhcpv6_response *rsp)
{
  /* Check for a DUID match.    If it matches, the packet is
   * for this client object.
   */
  struct option_cache *oc =
    lookup_option(&dhcpv6_option_space, rsp->options, DHCPV6_DUID);

  /* Get the DUID option. */
  if (!oc)
    {
      log_info("Dropping %s: no DUID", rsp->name);
      return 0;
    }

  if (duid->len != oc->data.len ||
      memcmp(&duid->data, oc->data.data, oc->data.len))
    return 0;
  return 1;
}

void DHCPv6Client::state_startup()
{
  /* Start up after about five tenths of a second, and then try the
   * S6_SOLICITING or S6_INFORM states.
   */
  if (config->interface->v6configured)
    addTimeout(cur_time + (random() % 5000000) * 1000ULL, S6_INFORM);
  else if (config->interface->ipv6_addr_count > 0)
    addTimeout(cur_time + (random() % 5000000) * 1000ULL, S6_SOLICITING);
  else
    {
      log_info("Can't do DHCPv6 on a non-IPv6 network.");
      state_unmanaged();
    }
  next_state_time = 0;
}


void DHCPv6Client::state_confirm()
{
  /* Make a DHCP Solicit packet, and set appropriate per-interface
     flags. */
  state = S6_CONFIRMING;
  make_client_options(0);

  if (relay_destination.len == 16)
    destination = relay_destination;
  else
    destination = iaddr_all_agents_and_servers;
  first_sending = cur_time;
  sending = DHCPV6_CONFIRM;
  sending_name = "DHCP Confirm";
  next_state_time = 0;
  next_state = S6_CONFIRMING;
  xid = random() & 0xFFFFFF;
  next_state_time = 0;

  /* Send the initial solicit. */
  send_normal_packet();
}

/* Called when a lease has completely expired and we've been unable to
   renew it, or when we're first starting up. */

void DHCPv6Client::state_soliciting()
{
  /* Make a DHCP Solicit packet, and set appropriate per-interface
     flags. */
  state = S6_SOLICITING;
  make_client_options(0);

  if (relay_destination.len == 16)
    destination = relay_destination;
  else
    destination = iaddr_all_agents_and_servers;
  first_sending = cur_time;
  sending = DHCPV6_SOLICIT;
  sending_name = "DHCP Solicit";
  next_state_time = 0;
  next_state = S6_SOLICITING;
  xid = random() & 0xFFFFFF;
  next_state_time = 0;

  /* Send the initial solicit. */
  send_normal_packet();
}

/* Called when a lease has completely expired and we've been unable to
   renew it, or when we're first starting up. */

void DHCPv6Client::state_rapid()
{
  /* Make a DHCP Solicit packet, and set appropriate per-interface
     flags.  Include a rapid commit option. */
  state = S6_RAPID;
  make_client_options(0);

  if (relay_destination.len == 16)
    destination = relay_destination;
  else
    destination = iaddr_all_agents_and_servers;
  first_sending = cur_time;
  sending = DHCPV6_SOLICIT;
  sending_name = "DHCP Solicit";
  next_state_time = 0;
  next_state = S6_RAPID;
  xid = random() & 0xFFFFFF;
  next_state_time = 0;

  /* Send the initial solicit. */
  send_normal_packet();
}

/* Called when a lease has completely expired and we've been unable to
   renew it, or when we're first starting up. */

void DHCPv6Client::state_release()
{
  /* Make a DHCP Solicit packet, and set appropriate per-interface
     flags.  Include a rapid commit option. */
  state = S6_RELEASING;

  make_client_options(server_identifier);

  if (relay_destination.len == 16)
    destination = relay_destination;
  else
    destination = iaddr_all_agents_and_servers;
  first_sending = cur_time;
  sending = DHCPV6_RELEASE;
  sending_name = "DHCP Release";
  next_state_time = 0;
  next_state = S6_UNMANAGED;
  xid = random() & 0xFFFFFF;
  next_state_time = 0;
  retransmit_count = 3;

  /* Send the initial solicit. */
  send_normal_packet();
}

/* Called when we are just doing an information request. */

void DHCPv6Client::state_inform()
{
  /* Make a DHCP Solicit packet, and set appropriate per-interface
     flags. */
  state = S6_INFORM;
  make_client_options(0);

  xid = random();
  if (relay_destination.len == 16)
    destination = relay_destination;
  else
    destination = iaddr_all_agents_and_servers;
  first_sending = cur_time;
  sending = DHCPV6_INFORMATION_REQUEST;
  sending_name = "DHCP Information Request";
  next_state_time = 0;
  next_state = S6_INFORM;
  xid = random() & 0xFFFFFF;
  next_state_time = 0;

  /* Send the initial solicit. */
  send_normal_packet();
}

/* Send out a DHCPDISCOVER packet, and set a timeout to send out another
   one after the right interval has expired.  If we don't get an offer by
   the time we reach the panic interval, call the panic function. */

void DHCPv6Client::send_normal_packet()
{
  struct option *opt;
  struct option_cache *oc;
  struct buffer *bp;
  int elapsed;
  struct data_string packet;
  ssize_t result;
  struct sockaddr_in6 dest;
  char addrbuf[128];
  int caplen_offset = -1;

  memset(&dest, 0, sizeof dest);
  dest.sin6_family = AF_INET6;
  dest.sin6_port = remote_port_dhcpv6;
#ifdef HAVE_SA_LEN
  dest.sin6_len = sizeof dest;
#endif
  memcpy(&dest.sin6_addr, destination.iabuf, 16);

  /* Figure out the next interval.  If it's currently zero (i.e., we
   * haven't sent any packets yet), set it to the preconfigured
   * initial interval; otherwise, add to it a random number between
   * zero and two times itself.  On average, this means that it will
   * double with every transmission.
   */
  if (!interval)
    interval = config->initial + ((random () >> 2) % (2 * config->initial));
  else
    interval += ((random () >> 2) % (2 * interval));

  /* Don't backoff past cutoff. */
  if (interval > config->cutoff)
    interval = ((config->cutoff / 2) + ((random () >> 2) % config->cutoff));
		
  /* Record the number of seconds since we started sending; max it out
   * at 2^16-1.
   */
  delete_option(&dhcpv6_option_space, send_options, DHCPV6_ELAPSED_TIME);

  /* Elapsed time is specified in hundredths of a second. */
  elapsed = (cur_time - first_sending) / (1000000000ULL / 100);
  if (elapsed > 65535)
    elapsed = 65535;
  bp = buffer_allocate(2);
  putUShort(bp->data, elapsed);
  opt = find_option(&dhcpv6_option_space, DHCPV6_ELAPSED_TIME);
  oc = make_const_option_cache(&bp, 0, 2, opt);
  save_option(&dhcpv6_option_space, send_options, oc);

  /* Start out with a 200 byte buffer; the option encapsulation code
   * will expand it as needed.
   */
  memset(&packet, 0, sizeof packet);
  packet.buffer = buffer_allocate(200);
  packet.data = packet.buffer->data;

  packet.len = 0;

  /* If we are faking up a relay header, do it now. */
  if (relay_destination.len == 16)
    {
      packet.buffer->data[0] = DHCPV6_RELAY_FORWARD;
      packet.len++;
      packet.buffer->data[1] = 0; /* hop count */
      packet.len++;
      memcpy(&packet.buffer->data[packet.len], config->interface->ipv6s, sizeof (struct in6_addr));  
      packet.len += 16;
      memcpy(&packet.buffer->data[packet.len], config->interface->ipv6s, sizeof (struct in6_addr));
      packet.len += 16;
      putUShort(&packet.buffer->data[packet.len], DHCPV6_RELAY_MESSAGE);
      packet.len += 2;
      caplen_offset = packet.len;
      putUShort(&packet.buffer->data[packet.len], 0);
      packet.len += 2;
  }

  /* The DHCPv6 message header consists of a single byte of message
   * type, followed by three bytes of transaction ID in sort-of
   * network byte order.   There's no pretty way to do this, but we
   * can at least take advantage of the fact that the MSB of a 32-bit
   * integer stored in network byte order corresponds to the first
   * byte, so what we do is to encode the transaction ID as a 32-bit
   * number, and then overwrite the MSB with the type code.
   */
  putULong(&packet.buffer->data[packet.len], xid);
  packet.buffer->data[packet.len] = sending;
  packet.len = packet.len + 4;

  /* Now we can just encapsulate the options into the packet fairly
   * painlessly.
   */
  if (!option_space_encapsulate(&packet, send_options, &dhcpv6))
    log_fatal ("Couldn't encapsulate %s", sending_name);

  /* If we're faking up a relay-forward message, put a length on the Relay Message option. */
  if (caplen_offset != -1)
    {
      printf("caplen = %d  packet len = %d  offset = %d\n", caplen_offset, packet.len, packet.len - caplen_offset - 2);
      putUShort(&packet.buffer->data[caplen_offset], packet.len - caplen_offset - 2);
    }

  inet_ntop(AF_INET6, &dest.sin6_addr, addrbuf, sizeof addrbuf);
  log_info ("%s on %s to %s xid %x port %d interval %.2lfs", sending_name,
	    (config->name
	     ? config->name : config->interface->name),
	    addrbuf, xid, ntohs(dest.sin6_port),
	    ((double)interval / 1000000000.0));

  /* Send out a packet. */
  result = send_packet(config->interface, packet.buffer->data,
		       packet.len, (struct sockaddr *)&dest);

  /* If there is no next state into which we are going to time out,
   * or if the next resend interval comes before that timeout,
   * schedule a retransmission.   If something comes in before the
   * retransmission, the timeout will be canceled.
   */
  if (!next_state_time || next_state_time > cur_time + interval)
    {
      if (retransmit_count > 0)
	{
	  retransmit_count--;
	  if (retransmit_count == 0)
	    addTimeout(cur_time, next_state);
	  else
	    {
	      retransmit = cur_time + interval;
	      addTimeout(retransmit, state);
	    }
	}
      else
	{
	  retransmit = cur_time + interval;
	  addTimeout(retransmit, state);
	}

      /* If there is a next state, and the next retransmission would happen
       * after the timeout that brings us to the next state, then instead
       * of scheduling a retransmission, schedule the transition into the
       * next state.
       */
    }
  else
    addTimeout(next_state_time, next_state);
}

void DHCPv6Client::make_client_options(struct buffer *sid)
{
  unsigned i;
  struct option_cache *oc;
  struct buffer *bp = (struct buffer *)0;
  struct option *opt;
  struct ia *ia;
  struct option_cache *ia_options = 0;
  char buf[128];

  send_options = new_option_state();

  /* Figure out how many parameters were requested. */
  for (i = 0; config->dhcpv6_requested_options[i]; i++)
    ;
  bp = buffer_allocate(i * 2);
  for (i = 0; config->dhcpv6_requested_options[i]; i++)
    putUShort(&bp->data[i * 2], config->dhcpv6_requested_options [i]);
  opt = find_option(&dhcpv6_option_space, DHCPV6_REQUESTED_OPTIONS);
  oc = make_const_option_cache(&bp, 0, i * 2, opt);
  save_option(&dhcpv6_option_space, send_options, oc);

  /* Rapid commit option. */
  if (state == S6_RAPID)
    {
      bp = buffer_allocate(0);
      opt = find_option(&dhcpv6_option_space, DHCPV6_RAPID_COMMIT);
      oc = make_const_option_cache(&bp, 0, 0, opt);
      save_option(&dhcpv6_option_space, send_options, oc);
    }

  /* Send a DUID option with our DUID. */
  bp = buffer_allocate(duid->len);
  memcpy(bp->data, &duid->data, duid->len);
  opt = find_option(&dhcpv6_option_space, DHCPV6_DUID);
  oc = make_const_option_cache(&bp, 0, duid->len, opt);
  save_option(&dhcpv6_option_space, send_options, oc);

  /* Send a server identifier if we have one. */
  if (sid)
    {
      opt = find_option(&dhcpv6_option_space,
			DHCPV6_SERVER_IDENTIFIER);
      oc = make_const_option_cache(&sid, 0, sid->size, opt);
      save_option(&dhcpv6_option_space, send_options, oc);
    }

  if (gethostname(buf, sizeof buf) == 0)
    {
      int len;
      printf("got FQDN: %s\n", buf);
      opt = find_option(&dhcpv6_option_space, DHCPV6_FQDN);
      bp = buffer_allocate(strlen(buf) + 10); /* XXX */
      len = dns_fqdn_to_wire(&bp->data[1], (unsigned char *)buf, strlen(buf));
      bp->data[0] = 1;
      oc = make_const_option_cache(&bp, 0, len + 2, opt);
      save_option(&dhcpv6_option_space, send_options, oc);
    }
  else
    {
      perror("Client FQDN");
    }
  
  if (state != S6_INFORM)
    {
      /* Make IA options... */
      for (ia = ias; ia; ia = ia->next)
        {
          oc = (struct option_cache *)safemalloc(sizeof *oc);
          memset(oc, 0, sizeof *oc);
          make_ia_option(&oc->data, ia, 1);
          oc->option = find_option(&dhcpv6_option_space, DHCPV6_IA_NA);

          /* Make a linked list of IA options, and when we've made the
           * last IA option, stash it in client->send_options.
           */
          oc->next = ia_options;
          ia_options = oc;
        }
      if (ia_options)
        save_option(&dhcpv6_option_space, send_options, ia_options);
    }
}

/* Given a DHCPv6 response, make sure it's actually destined for the
 * client that received it.   If there's more than one client attached
 * to a particular interface, it's going to be a good idea to cycle
 * through all the clients on the interface that received this packet
 * to see if one of them is the one that's supposed to have gotten it.
 * For now we're only doing one client state object per interface, so
 * this test should always succeed unless the packet is a bogon.
 */

int DHCPv6Client::associate_v6_response(const unsigned char *packet,
					struct dhcpv6_response *response,
					const char *name)
{
  /* If it's a DHCP Reconfigure, we need to look for
   * a matching IA, because we don't yet have a
   * transaction ID to match.    We will never get
   * a reconfigure that doesn't contain any IAs,
   * at least in theory.
   */
  if (packet[0] == DHCPV6_RECONFIGURE)
    {
      if (ias_congruent(&response->ias, ias))
	goto match;
    }
  else if (response->xid == (xid & 0xFFFFFF))
    {
      goto match;
    }

  log_info("Dropping %s: no match for xid = %lx, xid = %lx, duid = %s",
	   name, (unsigned long)response->xid, (unsigned long)xid,
	   print_hex_1(duid->len, (const unsigned char *)&duid->data, 80));
  return false;

 match:
  response->state = this;
  response->interface = config->interface;

  return true;
}

/* Check to see if two sets of IAs contain all the same IAs.   Return 1 if
 * yes, 0 if no.   We do not assume that the lists are sorted the same way,
 * so we just have to go through both lists looking for ias that are not in
 * the other.   We treat empty lists as never being congruent, because the
 * point is to look for a match, not to look for two mistakes.
 *
 * As a side effect, ias_congruent reorders the new list so that it's in
 * the same order as the original list.
 */
int DHCPv6Client::ias_congruent(struct ia **new_ia_list, struct ia *my_ia_list)
{
  struct ia *a, *b;
  struct ia **reordered;
  int num_ias = 0;

  /* Empty lists are never congruent. */
  if (!new_ia_list || !*new_ia_list || !my_ia_list)
    return 0;

  b = *new_ia_list;

  while (b)
    {
      for (a = my_ia_list; a; a = a->next)
	if (b->id == a->id)
	  goto again;

      /* We didn't find the IA that B is pointing for any value
       * of A, so the IA sets aren't congruent.
       */
      return 0;
    again:
      num_ias++;
      b = b->next;
    }

  reordered = (struct ia **)safemalloc(num_ias * sizeof *reordered);
  num_ias = 0;

  a = my_ia_list;
  while (a)
    {
      for (b = *new_ia_list; b; b = b->next)
	if (b->id == a->id)
	  goto more;
      /* We didn't find the IA that A is pointing to for any value
       * of B, so the IA sets aren't congruent.
       */
      return 0;
    more:
      reordered[num_ias++] = b;
      a = a->next;
    }

  /* It was neither the case that the list ia1 contained ias that were
   * not in list ia2, nor that list ia2 contained ias that were not in
   * the list ia1, so the lists are congruent.
   */

  /* Reorder the new list. */
  reordered[num_ias - 1]->next = 0;
  while (--num_ias > 0)
    reordered[num_ias - 1]->next = reordered[num_ias];
  *new_ia_list = reordered[0];

  return 1;
}

/* A server is offering us service in response to a solicit,
 * or at least so one hopes.
 */
void DHCPv6Client::advertise(struct dhcpv6_response *response,
			     struct sockaddr_in6 *from,
			     const unsigned char *packet, unsigned length)
{
  struct ia *ia;
  struct ia_addr *addr;
  u_int64_t next;
  struct option_cache *oc;
  char buf[128];

  if (state != S6_SOLICITING && state != S6_SELECTING && state != S6_RAPID)
    {
      log_info("Dropping DHCP Advertise from %s: not soliciting or selecting",
	       inet_ntop(from->sin6_family,
			 (char *)&from->sin6_addr, buf, sizeof buf));
      return;
    }

  /* We need a server identifier or it's useless. */
  oc = lookup_option(&dhcpv6_option_space,
	 	     response->options, DHCPV6_SERVER_IDENTIFIER);
  if (!oc)
    {
      log_info("Dropping DHCP Advertise from %s: no server identifier",
	       inet_ntop(from->sin6_family,
			 (char *)&from->sin6_addr, buf, sizeof buf));
      return;
    }

  /* Associate it with a transaction.   Associate function will log
   * error if there is one.
   */
  if (!associate_v6_response(packet, response, "DHCP Advertise"))
    {
      log_info("%s: associate failed.",
	       inet_ntop(from->sin6_family,
			 (char *)&from->sin6_addr, buf, sizeof buf));
      return;
    }

  log_info("Accepting DHCP Advertise from %s.",
	   inet_ntop(from->sin6_family,
	   (char *)&from->sin6_addr, buf, sizeof buf));

  /* The packet appears to be a response to us.   However, it may be
   * a negative response: "I can't give you an address - sorry.
   */
  for (ia = response->ias; ia; ia = ia->next)
    {
      if (ia->addresses)
	goto have_addrs;
    }

  /* Okay, no addresses.   We want to save the negative response,
   * because if it's the only one we get within the time limit, we
   * will want to display whatever message it contains, but it's not
   * good enough to trigger us to stop trying to get a useful response,
   * unless we've already passed the selecting timeout.
   */
  goto can_pick;

 have_addrs:
  /* If the IAs are not the ones we asked for, the packet is just bogus,
   * and we can and should ignore it.
   */
  if (!ias_congruent(&response->ias, response->state->ias))
    {
      log_info("Dropping DHCP Advertise from %s: IAs are not congruent.",
	       inet_ntop(from->sin6_family,
			 (char *)&from->sin6_addr, buf, sizeof buf));
      return;
    }

  /* Now make sure that the offered addresses are actually worth having.
   * Right now the criteron is, is there a single offered address with
   * a preferred lifetime greater than zero.   We might get fancier
   * later.   Suggestions solicited.
   *
   * BTW, it's possible that we might get an IA that offers an address
   * with a preferred lifetime of zero, and another address with a non-
   * zero preferred lifetime.   That's not a bad thing - it just means
   * that an address we'd asked to be renewed got deprecated.   But each
   * IA should contain at least one address with a preferred lifetime
   * greater than zero, or else we've effectively been told not to
   * use the network.
   */
  next = MAX_TIME;
  for (ia = response->ias; ia; ia = ia->next)
    {
      ia->expiry = MAX_TIME;
      for (addr = ia->addresses; addr; addr = addr->next)
	{
	  if (addr->preferred && addr->preferred < ia->expiry)
	    ia->expiry = addr->preferred;
	}

      /* No usable addresses. */
      if (ia->expiry == MAX_TIME)
	ia->expiry = 0;

      /* The message contains addresses, but none that we want. */
      if (ia->expiry < next)
	{
	  next = ia->expiry;
	}
    }

  /* If next is zero, at lease one IA had no usable addresses. */
  if (!next)
    {
      log_info("Dropping DHCP Advertise from %s: one or more IAs had "
	       "no usable addresses.",
	       inet_ntop(from->sin6_family,
			 (char *)&from->sin6_addr, buf, sizeof buf));
      return;
    }

  /* If we get this far, the DHCP Advertise is pretty believable,
   * so we'll add it to the list and kick off the countdown to
   * the time when we have to make a decision on what address to
   * use.   We stop retransmitting DHCP Solicit messages at this
   * point, but keep listening for DHCP Advertises.
   *
   * It would be good at this point to pay attention to the preference
   * option; however, my personal opinion on the preference option is
   * that it isn't interesting unless the DHCP Advertise has been
   * authenticated, and since we don't do authentication yet, I'm not
   * putting in any code to pay attention to it.
   *
   * Another point about that is that I think the server preference
   * option is most important in an environment where you (a) want
   * to make a decision as quickly as possible and (b) can't afford
   * to waste bandwidth.
   *
   * XXX So if you, the honored reader, are using this code in,
   * XXX for example, a cell phone, then you may want to put in
   * XXX some code here to correctly handle the preference option,
   * XXX even in the absence of DHCP authentication, particularly
   * XXX since you may have already done some authentication at
   * XXX another layer.
   */
	
 can_pick:
  /* Stop sending DHCP Solicit messages. */
  clearTimeouts();

  /* Save the response. */
  response->next = responses;
  responses = response;

  /* Add a timeout at which we will choose one of the responses, or
   * if that time has already passed, just make the choice.
   */
  if (cur_time < first_sending + config->select)
    addTimeout((first_sending + config->select), S6_SELECTING);
  else
    state_selecting();
}

/* Pick_advertisement gets called when we've gotten at least one response
 * from a DHCP server in response to an ongoing DHCP Solicit attempt.
 * It's possible that none of the advertisements we've gotten include
 * usable IP addresses, and it's also possible that we may have gotten
 * more than one response that contains usable IP addresses.
 */

void DHCPv6Client::state_selecting()
{
  struct ia *my_ia, *offered_ia;
  struct ia_addr *my_addr, *offered_addr;
  struct dhcpv6_response *rsp;
  struct option_cache *oc;

  next_state_time = 0;
  state = S6_SELECTING;

  /* First make sure that we actually asked for some addresses.    If
   * we did not, which will be the case for a newly-booting client, then
   * we don't want to just automatically take the first response because
   * it failed to not extend the zero addresses we requested.
   */
  for (my_ia = ias; my_ia; my_ia = my_ia->next)
    {
      if (my_ia->addresses)
	goto did_ask;
    }

  /* If we fell out of the for loop, we didn't send any IA_ADDRs to
   * the server.
   */
  goto did_not_ask;
 did_ask:
	
  /* See if we can find a response from a DHCPv6 server that
   * extends the lifetimes on all of the addresses we had
   * previously.
   */
  for (rsp = responses; rsp; rsp = rsp->next)
    {
      /* We are able to assume that the list of ias in the response
       * contains the same IAs, in the same order, as the list on
       * the client state object, because we have already called
       * ias_congruent(), which ensures that as one of its exit
       * conditions on success.  We would never see the response
       * here if its IA list were not congruent.
       */
      for ((my_ia = ias), (offered_ia = rsp->ias);
	   my_ia && offered_ia;
	   (my_ia = my_ia->next), (offered_ia = offered_ia->next))
	{
	  for (my_addr = my_ia->addresses; my_addr; my_addr = my_addr->next)
	    {
	      for (offered_addr = offered_ia->addresses;
		   offered_addr;
		   offered_addr = offered_addr->next)
		{
		  if (!memcmp(offered_addr->address.iabuf,
			      my_addr->address.iabuf,
			      16))
		    {
		      if (my_addr->preferred <
			  cur_time + offered_addr->preferred)
			goto good;
		      break;
		    }
		}
	      /* We get here either if my address isn't
	       * on the address list, or if the preferred
	       * lifetime hasn't been extended.  In either
	       * case, we're not going to jump on this offer.
	       */
	      goto not_so_good;

	      /* We get here if the current address on the
	       * my_ia address list that we're looking at
	       * got a good offer.   Basically, a single bad
	       * offer is going to knock us out, so if we
	       * fall off the bottom of the ia for loop
	       * below, we have a good offer.
	       */
	    good:
	      continue;
	    }
	}

      /* At this point we got through all the IAs in the current
       * response, and all the addresses in those IAs, and they
       * were all renewed, so the response at which we are currently
       * looking is the best; there's no need to look further.
       */
      goto happy;

      /* If we get here, this response didn't meet the qualifications
       * described in the previous comment, so we're going to keep
       * looking in hopes of finding a response that does.
       */
    not_so_good:
      continue;
    }
	
  /* If we get to here, it's either because we didn't ask for any
   * specific addresses, or because none of the responses honored
   * whatever request we did make.   So at this point we just need
   * to look for a response that gave us at least one address with
   * a nonzero preferred lifetime for each interface.
   */
 did_not_ask:
  for (rsp = responses; rsp; rsp = rsp->next)
    {
      /* We may have got a response that was just an error message,
       * with no IAs.   In that case, don't try to use it.
       */
      if (!rsp->ias)
	goto unusable;
      for (offered_ia = rsp->ias; offered_ia; offered_ia = offered_ia->next)
	{
	  for (offered_addr = offered_ia->addresses;
	       offered_addr;
	       offered_addr = offered_addr->next)
	    {
	      /* Right now we're saying if the offer is
	       * greater than zero, it's good, but probably
	       * we should make it a useful interval; I
	       * am just not sure how long or short to
	       * make it.   If we're dealing with a
	       * non-hostile server, comparing against
	       * zero is fine - it's only in the case
	       * of a DoS attack that we'd want to be
	       * more picky.   And there are so many
	       * potential DoS attacks.   :'(
	       */
	      if (offered_addr->preferred > 0)
		goto content;
	    }

	  /* If we get here, then the IA we're looking at
	   * didn't get an address.   For now we assume that
	   * in order for an offer to be usable, it has to
	   * satisfy all IAs, so if we get here, the offer
	   * isn't usable.
	   */
	  goto unusable;
	  break;

	  /* If we get here, the IA got a usable address, so
	   * we're content.
	   */
	content:
	  continue;
	}
      /* If we get here, it means that we were content with the
       * addresses offered on all IAs on this response.   So we
       * can use this response: we're happy.
       */
      goto happy;

      /* We skip down to here if one of the IAs in the response
       * didn't get an address; that means that the response we
       * are looking at is unusable, so we keep looking.
       */
    unusable:
      continue;
    }

  /* If we get here, it means that none of the responses were
   * usable - none of them satisfied our request for addresses on
   * all the IAs we sent.   It is possible that one or more
   * responses contain an explanatory message, so now we search
   * for one and print it if we can.
   */

  oc = 0;
  for (rsp = responses; rsp; rsp = rsp->next)
    {
      oc = lookup_option(&dhcpv6_option_space,
			 rsp->options, DHCPV6_STATUS_CODE);
      if (!oc)
	{
	  for (offered_ia = rsp->ias; offered_ia; offered_ia = offered_ia->next)
	    {
	      oc = lookup_option(&dhcpv6_option_space,
				 offered_ia->recv_options, DHCPV6_STATUS_CODE);
	      if (oc)
		break;
	      for (offered_addr = offered_ia->addresses;
		   offered_addr;
		   offered_addr = offered_addr->next)
		{
		  oc = lookup_option(&dhcpv6_option_space,
				     offered_ia->recv_options,
				     DHCPV6_STATUS_CODE);
		  if (oc)
		    break;
		}
	      if (oc)
		break;
	    }

	}
      if (oc)
	break;
    }

  if (oc && oc->data.len >= 2)
    {
      const char *message;
      int status_code = getUShort(oc->data.data);
      if (oc->data.len > 2)
	{
	  char *msg = (char *)safemalloc(oc->data.len - 1);
	  memcpy(msg, oc->data.data + 2, oc->data.len - 2);
	  msg[oc->data.len - 2] = 0;
	  message = msg;
	}
      else
	{
	  switch(status_code)
	    {
	    case DHCPV6_SUCCESS:
	      goto bogus;
	    case DHCPV6_UNSPECIFIED_FAILURE:
	      goto bogus;
	    case DHCPV6_NO_ADDRS_AVAILABLE:
	      message = "No addresses available.";
	      break;

	      /* We should never have to print either of
	       * the following two messages, because the DHCP
	       * server should have offered us some other
	       * binding and just attached this message to
	       * the binding we requested.
	       */
	    case DHCPV6_BINDING_UNAVAILABLE:
	      message = "Requested address not available.";
	      break;
	    case DHCPV6_BINDING_NOT_ON_LINK:
	      message = "Requested address not on link.";
	      break;

	      /* We should never get this because we're
	       * following the protocol (right?).
	       */
	    case DHCPV6_USE_MULTICAST:
	      message = "Server demands multicast.";
	      break;

	    default:
	      goto bogus;
	    }
	}
      /* When we get here, message should be pointing to
       * some string.
       */
      log_info("Advertise Select: %s", message);
      if (controller)
	{
	  controller->start(config, "FAILURE");
	  controller->add_item("MESSAGE", "%s", message);
	  controller->add_item("STATUS6_CODE", "%d", status_code);
	  controller->finish(0, 0, 0);
	}
    }
  else
    {
    bogus:
      log_info("Advertise Select: we received one or more DHCP "
	       "Advertise messages, but none of these included "
	       "any usable IP addresses, and none of them included "
	       "a status message explaining why, so we will keep "
	       "sending Solicit messages in hopes of better luck.");
    }

  /* Because we didn't get any valid responses, we need to keep
   * trying.
   */
  responses = 0;
  if (cur_time >= retransmit)
    send_normal_packet();
  else
    addTimeout(retransmit, state);

  return;

  /* However we get to happy, rsp is pointing to a response that we
   * are willing to take.
   */
 happy:
  /* We can forget about all the other responses. */
  responses = 0;

  /* We need to remember the response we got, so we can compare it to
   * the response we get in the DHCP Reply message.
   */
  selected_response = rsp;
  rsp->next = 0;

  /* Steal the received options and the ia_addrs that we got in the
   * response and put them on our IA.
   */
  for ((my_ia = ias), (offered_ia = rsp->ias);
       my_ia && offered_ia;
       (my_ia = my_ia->next), (offered_ia = offered_ia->next))
    {
      my_ia->addresses = offered_ia->addresses;
      my_ia->recv_options = offered_ia->recv_options;

      /* Set the preferred and valid lifetimes on the addresses
       * we've been offered to zero, so that we don't accidentally
       * try to use these before they're confirmed.   I don't think
       * there will be a code path where this can happen, but better
       * safe than sorry.
       */
      for (my_addr = my_ia->addresses; my_addr; my_addr = my_addr->next)
	{
	  my_addr->preferred = 0;
	  my_addr->valid = 0;
	}
    }

  /* Go into the requesting state (we're sort of borrowing state
   * names from the DHCPv4 client for now, since v6 doesn't define
   * state names (not a complaint, btw!).
   */
  state_requesting();
}

/* Called when we have chosen from amongst one or more DHCP Advertise
 * messages and need to confirm our choice with the DHCP server.
 */

void DHCPv6Client::state_requesting()
{
  /* We don't accept advertises that don't have server identifiers, so
   * this should be safe.
   */
  struct option_cache *oc =
	lookup_option(&dhcpv6_option_space,
	 	      selected_response->options, DHCPV6_SERVER_IDENTIFIER);

  server_identifier = buffer_allocate(oc->data.len);
  memcpy(server_identifier->data, oc->data.data, oc->data.len);

  /* Make a DHCP Request packet, and set appropriate per-interface
     flags. */
  make_client_options(server_identifier);

  /* Generate a new transaction ID. */
  xid = random() & 0xFFFFFF;

  /* client->destination is already set. */

  state = S6_REQUESTING;

  /* We don't update client->first_sending yet. */

  /* We do need to reset the retry interval. */
  interval = 0;

  /* Give up if we don't have a response from the server 90 seconds
   * from now.
   */
  next_state_time = cur_time + NANO_SECONDS(90);
  next_state = S6_SOLICITING;
	
  /* We're now sending a DHCP Request. */
  sending = DHCPV6_REQUEST;
  sending_name = "DHCP Request";

  /* Send the initial solicit. */
  send_normal_packet();
}

/* A response to an information-request message or any message
 * responding to a request to acquire, renew or extend addresses on
 * IAs.
 */
void DHCPv6Client::reply(struct dhcpv6_response *response,
			 struct sockaddr_in6 *from,
			 const unsigned char *data, unsigned length)
{
  struct ia *my_ia, *confirmed_ia;
  struct ia_addr *addr;
  u_int64_t expiry;
  char buf[128];
  const char *reason;

  /* Decode the response.    If it's bogus, drop it and keep waiting.
   * The reason we keep waiting here and for subsequent drops is that
   * it's possible that an attacker could send us a bogus DHCP Reply
   * to get us to go back to soliciting, and we'd like to wait
   * for a legitimate reply from the server we selected instead.
   * It's also possible to get a stray DHCP Reply as a result of a retry,
   * while we're in the wrong state, and again we don't want this to
   * derail us.
   */

  /*
  rsp = decode_dhcpv6_packet(data, length, "DHCP Reply");
  if (!rsp)
    return;
  */

  /* Associate it with a transaction.   Associate function will log
   * error if there is one.
   */
  if (!associate_v6_response(data, response, "DHCP Reply"))
    return;

  if (response->state->state != S6_REQUESTING &&
      response->state->state != S6_RENEWING &&
      response->state->state != S6_INFORM &&
      response->state->state != S6_REBINDING &&
      response->state->state != S6_CONFIRMING &&
      response->state->state != S6_RAPID &&
      response->state->state != S6_RELEASING)
    {
      log_info("Dropping DHCP Reply: not expected in state %d",
	       response->state->state);
      return;
    }

  /* XXX Check all these drops against the spec.   It may not be
   * XXX correct to do all of these drops, except possibly in the
   * XXX S6_REQUESTING case.
   */

  if (response->state->state == S6_INFORM)
    {
      if (response->ias)
	{
	  log_info("Dropping DHCP Information Request Reply:"
		   "contains IA_NA options.");
	  return;
	}
      goto inform;
    }
  if (response->state->state == S6_RELEASING)
    {
      if (response->ias)
	{
	  log_info("Dropping DHCP Release Reply:"
		   "contains IA_NA options.");
	  return;
	}
      goto inform;
    }
  if (response->state->state == S6_CONFIRMING)
    {
      if (response->ias)
	{
	  log_info("Dropping DHCP Confirm Reply:"
		   "contains IA_NA options.");
	  return;
	}

      /* A reply to a Confirm shouldn't contain any configuration
       * information at all; all we really care about is the status
       * code and the transaction ID, which we already checked.
       */

      struct option_cache *oc =
	lookup_option(&dhcpv6_option_space,
		      response->options, DHCPV6_STATUS_CODE);
      if (oc->data.len < 2)
	{
	  log_info("DHCP Confirm Reply: dropping message with short status.");
	  return;
	}

      int status_code = getUShort(oc->data.data);
      switch(status_code)
	{
	case DHCPV6_SUCCESS:
	  log_info("DHCP Confirm Reply: on-link status confirmed");
	  if (rebind_time < cur_time)
	    state_rebinding();
	  if (renewal_time < cur_time)
	    state_renewing();
	  state_bound();
	  return;

	case DHCPV6_UNSPECIFIED_FAILURE:
	case DHCPV6_NO_ADDRS_AVAILABLE:
	case DHCPV6_BINDING_UNAVAILABLE:
	case DHCPV6_USE_MULTICAST:
	default:
	  log_info("Dropping DHCP Confirm Reply:"
		   "contains bogus status code %d.", status_code);
	  return;
	  
	case DHCPV6_BINDING_NOT_ON_LINK:
	  log_info("DHCP Confirm Reply: not on-link.");

	  /* Drop all our addresses. */
	  if (controller)
	    {
	      controller->start(config, "DHCP Reply");

	      for (my_ia = response->state->ias; my_ia; my_ia = my_ia->next)
		{
		  controller->send_ia(my_ia);
		  for (addr = my_ia->addresses; addr; addr = addr->next)
		    controller->send_ia_addr("remove", addr);
		  my_ia->addresses = 0;
		  my_ia->recv_options = 0;
		}
	      controller->finish(0, 0, 0);
	    }
	  state_soliciting();
	  return;
	}
    }
  else
    {
      /* If there are no IAs, or the IAs are not the ones we
       * asked for, the packet is just bogus, and we can and
       * should ignore it.
       */

      if (!response->ias)
	{
	  log_info("Dropping DHCP Reply: no IA_NA options.");
	  return;
	}
      if (!ias_congruent(&response->ias, response->state->ias))
	{
	  log_info("Dropping DHCP Reply: IAs are not congruent.");
	  return;
	}

      /* Make sure that this Reply actually configures all the IAs
       * we asked to have configured.
       */
      for (confirmed_ia = response->ias;
	   confirmed_ia; confirmed_ia = confirmed_ia->next)
	{
	  for (addr = confirmed_ia->addresses; addr; addr = addr->next)
	    {
	      if (addr->preferred > 0 || addr->valid > 0)
		goto ia_has_address;
	    }
	  log_info("Dropping DHCP Reply: does not configure all IAs.");
	  state_soliciting();
	  return;
	ia_has_address:
	  ;
	}
    }

 inform:
  log_info("Accepting DHCP Reply from %s.",
	   inet_ntop(from->sin6_family,
	   (char *)&from->sin6_addr, buf, sizeof buf));
  /* Steal the received options. */
  recv_options = response->options;
  response->options = 0;

  switch(response->state->state)
    {
    case S6_REQUESTING:
    case S6_RENEWING:
    case S6_REBINDING:
    case S6_RAPID:
      reason = "configured";
      break;
    case S6_INFORM:
      reason = "informed";
      break;
    case S6_CONFIRMING:
      reason = "confirmed";
      break;
    case S6_RELEASING:
      reason = "released";
      break;
    default:	/* can't get here. */
      reason = "oops";
      break;
    }
  /* Now we have to say what happened. */
  if (controller)
    controller->start(config, reason);
	
  /* Now we have to do adds and deletes.  In the case of a DHCP Reply
   * while requesting, we actually just have to do adds - for every
   * address in every IA, we do an add.
   */
  for ((my_ia = response->state->ias), (confirmed_ia = response->ias);
       my_ia && confirmed_ia;
       (my_ia = my_ia->next), (confirmed_ia = confirmed_ia->next))
    {
      if (controller)
	controller->send_ia(confirmed_ia);

      /* If we're in the requesting state, we are only going to be
       * adding addresses, not deleting any.
       */
      if (state == S6_REQUESTING)
	goto just_adds;

      /* Look for addresses we had, but no longer have, and
       * do deletes on them.   At the same time, for any address
       * that we had, and still have, do an update.
       */
      for (addr = my_ia->addresses; addr; addr = addr->next)
	{
	  struct ia_addr *na;

	  for (na = confirmed_ia->addresses; na; na = na->next)
	    {
	      if (!memcmp(na->address.iabuf, addr->address.iabuf, 16))
		{
		  if (controller)
		    controller->send_ia_addr("update", na);
		  goto found_addr;
		}
	    }
	  /* If we fall out the bottom of the loop, this is an
	   * address that *didn't* get renewed.
	   */
	  if (controller)
	    controller->send_ia_addr("remove", addr);
	found_addr:
	  ;
	}

      /* Now look for addresses we didn't have, but now do have. */
      for (addr = confirmed_ia->addresses; addr; addr = addr->next)
	{
	  struct ia_addr *na;

	  for (na = my_ia->addresses; na; na = na->next)
	    {
	      if (!memcmp(na->address.iabuf, addr->address.iabuf, 16))
		{
		  goto found_addr_1;
		}
	    }
	  /* If we fall out the bottom of the loop, this is an
	   * address that is in the server message, but not in
	   * our old list of addresses - thus, a new address.
	   */
	  if (controller)
	    controller->send_ia_addr("add", addr);
	found_addr_1:
	  ;
	}

      /* Skip over the code for the selecting state. */
      goto steal_conf;

      /* Look for addresses that are valid. */
    just_adds:
      for (addr = confirmed_ia->addresses; addr; addr = addr->next)
	{
	  if (addr->preferred > 0 || addr->valid > 0)
	    {
	      if (controller)
	        controller->send_ia_addr("add", addr);
	    }
	}

    steal_conf:
      /* Steal the new address configuration and options from each
       * IA as we go.
       */
      my_ia->addresses = confirmed_ia->addresses;
      confirmed_ia->addresses = 0;
      my_ia->recv_options = confirmed_ia->recv_options;
      confirmed_ia->recv_options = 0;
    }

  /* If we're releasing, we should exit the loop with my_ia still pointing
   * at something.
   */
  if (state == S6_RELEASING && my_ia != NULL)
    {
      for (addr = my_ia->addresses; addr; addr = addr->next)
	{
	  if (controller)
	    controller->send_ia_addr("remove", addr);
	}
      my_ia->addresses = 0;
      my_ia->recv_options = 0;
    }

  if (controller)
    {
      controller->send_options(recv_options);
      controller->finish(0, 0, 0);
    }

  /* For DHCP Release, we are done. */
  if (state == S6_RELEASING)
    {
      state_unmanaged();
      return;
    }

  /* XXX for DHCP Information Request, we need to extract the information
   * XXX request time according to the new draft and set up a timeout
   * XXX at which time we will send another information request.
   * XXX Actually, maybe Network Manager should do this.
   */
  if (state == S6_INFORM)
    {
      struct option_cache *option =
	lookup_option(&dhcpv6_option_space,
		      recv_options, DHCPV6_INFORMATION_REFRESH_TIME);
      if (!option)
	{
#if 0
	  log_info("choosing IRT_DEFAULT expiry time.\n");
#endif
	  expiry = DHCPV6_IRT_DEFAULT;
	}
      else if (option->next)
	{
	  log_info("Dropping DHCP Information Request Reply:"
		   "contains multiple refresh times.");
	  return;
	}
      else
	{
	  if (option->data.len != 4)
	    {
	      log_info("Dropping DHCP Information Request "
		       "Reply: contains multiple refresh "
		       "times.");
	      return;
	    }

	  expiry = getULong(option->data.data);
	  if (expiry < DHCPV6_IRT_MINIMUM)
	    {
	      log_info("Ignoring DHCP Information Refresh "
		       "Time: renewal time is too short.");
	      expiry = DHCPV6_IRT_MINIMUM;
	    }
	  else if (expiry > DHCPV6_IRT_MAXIMUM)
	    {
	      log_info("Ignoring default Information "
		       "Refresh Time: renewal time is too "
		       "long; either it's misconfigured or "
		       "it's a denial of service attack.");
	      return;
	    }
#if 0
	  else
	    log_info("choosing expiry time from option.\n");
#endif
	}

      /* Add a timeout to refresh the information at the
       * interval we figured out.
       */
      clearTimeouts();
      addTimeout(cur_time + NANO_SECONDS(expiry), S6_INFORM);

      time_t t = SECONDS(cur_time + NANO_SECONDS(expiry));
      ctime_r(&t, buf);
      buf[strlen(buf) - 1] = 0;
      log_info("Information refresh time: %s", buf);

      /* XXX we haven't taken into account that the user might ask for
       * XXX an information request even though we're not doing lite
       * XXX on this client.
       */
      return;
    }

  /* Figure out when we need to send a renewal.   Also, tweak preferred and
   * valid times to be relative to the epoch, rather than relative to when the
   * server generated the packet, and get rid of IA_ADDRs that no longer
   * contain usable addresses.
   */
  expiry = MAX_TIME;
  renewal_time = MAX_TIME;
  rebind_time = MAX_TIME;

  for (my_ia = response->state->ias; my_ia; my_ia = my_ia->next)
    {
      struct ia_addr *prev = 0;

      /* Figure out when *this* IA expires.   This is going to be the
       * longest preferred time of all the IA_ADDRS in the IA.
       */
      my_ia->expiry = 0;

      /* Do the IA_ADDR cleanup and find expiry time. */
      for (addr = my_ia->addresses; addr; addr = addr->next)
	{
	  if (addr->preferred > my_ia->expiry)
	    {
	      my_ia->expiry = addr->preferred;
	    }

	  /* Get rid of any IA_ADDRs in the response that are
	   * just telling us something we asked for is no
	   * longer valid.
	   */
	  if (addr->preferred == 0 && addr->valid == 0)
	    {
	      if (prev)
		prev->next = addr->next;
	      else
		my_ia->addresses = addr->next;
	    }
	  else
	    {
	      /* Make the preferred and valid times absolute
	       * instead of relative.
	       */
	      addr->preferred = response->received_time + NANO_SECONDS(addr->preferred);
	      addr->valid = response->received_time + NANO_SECONDS(addr->valid);
	    }
	  prev = addr;
	}

      /* If the renewal, rebind or expiry times on this IA are shorter than
       * the times we've figured out for other IAs, use the times from this
       * IA - this IA needs to be renewed sooner.
       * This is problematic, since RFC3315 wants us not to renew an IA earlier
       * than the t1 time on that IA, but I don't really see a way around it
       * other than handling IAs in separate messages.   Maybe that's the
       * right thing to do, but I don't particularly want to do it this way.
       * We talked about this quite extensively, but that discussion doesn't
       * seem to be reflected in RFC3315, more's the pity.
       */
      if (renewal_time > my_ia->t1)
	renewal_time = my_ia->t1;
      if (rebind_time > my_ia->t2)
	rebind_time = my_ia->t2;
      if (expiry > my_ia->expiry)
	expiry = my_ia->expiry;
    }

  /* Server doesn't have to specify T1/T2? */
  if (renewal_time == 0)
    renewal_time = expiry * 5 / 8;
  if (rebind_time == 0)
    rebind_time = expiry * 7 / 8;

  /* At this point client->expiry should contain the lowest of the maximum
   * preferred times from each IA in the response.   The DHCP
   * server specifies when to try to renew the IAs and when to try to
   * rebind them; we decide when to start doing a solicit based on the
   * minumum preferred lifetime.
   */
  renewal_time = cur_time + NANO_SECONDS(renewal_time);
  rebind_time = cur_time + NANO_SECONDS(rebind_time);
  solicit_time = cur_time + NANO_SECONDS(expiry);
  if (renewal_time > solicit_time)
    renewal_time = solicit_time;
  if (rebind_time > solicit_time)
    rebind_time = solicit_time;
  state_bound();
}

/* We enter this state when we've finished either getting a new IP address
 * for the first time, or renewing an IP address subsequently.
 */
void DHCPv6Client::state_bound()
{
  char buf[128];
  char vtbuf[26];
  char ptbuf[26];
  struct ia *my_ia;
  struct ia_addr *addr;
  time_t t;

  for (my_ia = ias; my_ia; my_ia = my_ia->next)
    {
      for (addr = my_ia->addresses; addr; addr = addr->next)
	{
	  t = SECONDS(cur_time + addr->valid);
	  ctime_r(&t, vtbuf);
	  vtbuf[strlen(vtbuf) - 1] = 0;
	  t = SECONDS(cur_time + addr->preferred);
	  ctime_r(&t, ptbuf);
	  ptbuf[strlen(ptbuf) - 1] = 0;
	  log_info("Bound to %s, valid = %s, preferred = %s",
		   inet_ntop(AF_INET6, addr->address.iabuf, buf, sizeof buf),
		   vtbuf, ptbuf);
	}
    }
  t = SECONDS(renewal_time);
  ctime_r(&t, buf);
  buf[strlen(buf) - 1] = 0;
  log_info("Renewal time: %s", buf);

  clearTimeouts();
  state = S6_BOUND;
  addTimeout(renewal_time, S6_RENEWING);
}

/* Called when we have chosen from amongst one or more DHCP Advertise
 * messages and need to confirm our choice with the DHCP server.
 */

void DHCPv6Client::state_renewing()
{
  /* Make a DHCP Request packet, and set appropriate per-interface
     flags. */
  make_client_options(server_identifier);

  /* Generate a transaction ID for the renewal. */
  xid = random() & 0xFFFFFF;

  /* XXX We should handle the case here where the server sent the unicast
   * XXX option.
   */
  if (relay_destination.len == 16)
    destination = relay_destination;
  else
    destination = iaddr_all_agents_and_servers;

  state = S6_RENEWING;
  first_sending = cur_time;
  interval = 0;

  /* Give up if we don't have a response from the server 90 seconds
   * from now.
   */
  next_state_time = rebind_time;
  next_state = S6_REBINDING;
	
  /* We're now sending a DHCP Renew. */
  sending = DHCPV6_RENEW;
  sending_name = "DHCP Renew";

  /* Send the initial renew. */
  send_normal_packet();
}

/* Called when we've been trying to renew a particular client state and
 * have been unable to do so.   When 7/8th of the time available on the
 * shortest valid address has expired, we send a DHCP Rebind message in
 * hopes that some other server will be able to help us.
 */

void DHCPv6Client::state_rebinding()
{
  /* Make a DHCP Request packet, and set appropriate per-interface
     flags. */
  make_client_options(0);

  /* Make a new transaction ID for the rebinding state. */
  xid = random() & 0xFFFFFF;

  /* When we're rebinding, we always multicast. */
  if (relay_destination.len == 16)
    destination = relay_destination;
  else
    destination = iaddr_all_agents_and_servers;

  state = S6_REBINDING;

  /* Keep client->first_sending from the renew. */
  interval = 0;

  /* Give up if we don't have a response from the server 90 seconds
   * from now.
   */
  next_state_time = solicit_time;
  next_state = S6_SOLICITING;
	
  /* We're now sending a DHCP Rebind. */
  sending = DHCPV6_REBIND;
  sending_name = "DHCP Rebind";

  /* Send the initial solicit. */
  send_normal_packet();
}

/* When we get into the unmanaged state, only some kind of user or management
 * tool intervention can get us back out of it - this is where we go when
 * we've determined that we're not supposed to manage this interface.
 */

void DHCPv6Client::state_unmanaged()
{
  clearTimeouts();
  state = S6_UNMANAGED;
  next_state_time = 0;
}

/* This is called whenever a timer expires for this client state machine.
 * If the timeout requires us to change states, we do so; otherwise we
 * assume that we have to retransmit the current packet, since there's no
 * other cause for a timeout to happen.
 */

void DHCPv6Client::event(const char *evname, int newState, int status)
{
  /* If this timeout triggers a state transition, make the transition. */
  if (newState != state)
    {
      switch(newState)
	{
	case S6_SOLICITING:
	  state_soliciting();
	  break;

	case S6_SELECTING:
	  state_selecting();
	  break;

	case S6_REQUESTING:
	  state_requesting();
	  break;

	case S6_BOUND:
	  state_bound();
	  break;

	case S6_RENEWING:
	  state_renewing();
	  break;

	case S6_REBINDING:
	  state_rebinding();
	  break;

	case S6_INFORM:
	  state_inform();
	  break;

	case S6_UNMANAGED:
	  state_unmanaged();
	  break;
	}
    }

  /* Otherwise, it's triggering a retransmission. */
  send_normal_packet();
}

/* Local Variables:  */
/* mode:c++ */
/* c-file-style:"gnu" */
/* end: */
