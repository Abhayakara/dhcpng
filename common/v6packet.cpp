/* v6packet.c
 *
 * General-purpose routines for composing and decomposing DHCPv6 packets.
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
  "$Id: v6packet.cpp,v 1.9 2012/04/01 21:26:34 mellon Exp $ Copyright (c) 2005-2006 Nominum, Inc.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"
#include "version.h"

/* This is so that we can do option_space_encapsulate without consing up
 * a special data string every time.
 */
static struct data_string dhcpv6 = { 0, (const unsigned char *)"dhcpv6", 6, 1 };

/* Given an ia data structure and its associated ia_address substructures,
 * generate an IA option and the associated IA_ADDRESS options in wire
 * format.
 */

void make_ia_option(struct data_string *output, struct ia *ia, int clientp)
{
  struct ia_addr *addr;
  struct option_cache *addropts = 0;
  struct option_cache *oc;

  output->buffer = buffer_allocate(40);
	
  putULong(&output->buffer->data[0], ia->id);
  putULong(&output->buffer->data[4], ia->t1);
  putULong(&output->buffer->data[8], ia->t2);
  output->data = output->buffer->data;
  output->len = 12;

  /* Make a space in the ia->send_options structure for the IA_ADDRESS
   * options, but only if there are IA_ADDRESS options.
   */
  if (ia->addresses)
    {
      if (!ia->send_options)
	ia->send_options = new_option_state();
      else
	{
	  /* Delete any stale IA_ADDRESS options from the options
	   * for this IA.
	   */
	  delete_option(&dhcpv6_option_space,
			ia->send_options, DHCPV6_IA_ADDRESS);
	}
    }

  /* For each IA_ADDRESS option, either add it to ia->send_options, or if
   * we've already added one, chain this one to the end.
   */
  for (addr = ia->addresses; addr; addr = addr->next)
    {
      /* Make an option cache for this IA_ADDRESS option. */
      oc = (struct option_cache *)safemalloc(sizeof *oc);
      memset(oc, 0, sizeof *oc);
      oc->data.buffer = buffer_allocate(24);
      oc->data.data = oc->data.buffer->data;

      /* Stash the IA_ADDRESS address. */
      memcpy(oc->data.buffer->data, addr->address.iabuf, 16);

      /* Client always sets preferred and valid lifetimes to zero. */
      if (clientp)
	{
	  memset(&oc->data.buffer->data[16], 0, 8);
	}
      else
	{
	  putULong(&oc->data.buffer->data[16],
		   addr->valid - cur_time);
	  putULong(&oc->data.buffer->data[20],
		   addr->preferred - cur_time);
	}
      oc->data.len = 24;

      /* If this IA_ADDRESS has options, encapsulate them. */
      if (addr->send_options &&
	  !option_space_encapsulate(&oc->data,
				    addr->send_options, &dhcpv6))
	{
	  log_fatal ("Couldn't encapsulate IA_ADDRESS");
	}

      oc->option = find_option(&dhcpv6_option_space, DHCPV6_IA_ADDRESS);

      /* Make a linked list of the IA_ADDRESS options.   When we
       * get to the end, stash it in ia->send_options.
       */
      oc->next = addropts;
      addropts = oc;
    }
  if (addropts)
    save_option(&dhcpv6_option_space, ia->send_options, addropts);
	
  /* We've finished populating ia->send_options, so now we can
   * generate the wire-format IA option contents.
   */
  if (ia->send_options &&
      !option_space_encapsulate(output, ia->send_options, &dhcpv6))
    {
      log_fatal ("Couldn't encapsulate IA");
    }
}

/* Store the DUID in an option buffer in network order. */
void
store_duid(unsigned char *buf, unsigned len, duid_t *duid)
{
  if (len > duid->len)
    len = duid->len;

  if (len >= 2)
    putUShort(buf, duid->data.type);
  switch(duid->data.type)
    {
    case DUID_LLT:
      if (len >= 4)
	putUShort(buf + 2, duid->data.llt.hardware_type);
      if (len >= 8)
	putULong(buf + 4, duid->data.llt.time);
      if (len > 8)
 	memcpy(buf + 8, duid->data.llt.lladdr, len - 8);
      break;

    case DUID_LL:
      if (len >= 4)
	putUShort(buf + 2, duid->data.ll.hardware_type);
      if (len > 6)
 	memcpy(buf + 6, duid->data.ll.lladdr, len - 6);
      break;

    case DUID_EN:
      if (len >= 6)
	putULong(buf + 2, duid->data.en.enterprise_number);
      if (len > 6)
 	memcpy(buf + 8, duid->data.en.id, len - 6);
      break;

    default:
      if (len > 2)
 	memcpy(buf + 2, duid->data.en.id, len - 2);
      break;
    }
}

/* Extract the transaction ID from the DHCPv6 packet. */

u_int32_t
dhcpv6_extract_xid(const unsigned char *packet, unsigned len)
{
  unsigned char xid[4];

  if (len < 4)
    return 0;

  /* The transaction ID is actually three bytes, with the first byte
   * of the packet being the packet type, so make a copy of it with
   * the packet type byte set to zero so we can extract it in the
   * native byte order.
   */
  memcpy(xid, packet, 4);
  xid[0] = 0;
  return getULong(xid);
}

#ifdef DEBUG_V6_PACKETS
static void
dhcpv6_option_dumper(struct option_cache *oc, struct option_state *state,
		     struct option_space *os, void *vcaller)
{
  const char *caller = (const char *)vcaller;

  log_debug("%s: %s.%s: %s", caller, os->name, oc->option->name,
	    print_hex_1(oc->data.len, oc->data.data, 60));
}
#endif

/* Given an incoming packet, decode it into a list of IAs and into lists of
 * IA_ADDRESSes, as well as a top-level option state context.   Find a matching
 * transaction for it, unless it's a DHCP Reconfigure (in which case it's
 * starting a transaction, so there won't be a matching one).
 */
struct dhcpv6_response *
decode_dhcpv6_packet(const unsigned char *packet, unsigned len, struct dhcpv6_response *outer)
{
  struct option_state *top;
  struct dhcpv6_response *response;
  unsigned header_len;

  if (len > 1 && packet[0] != DHCPV6_RELAY_FORWARD && packet[0] != DHCPV6_RELAY_REPLY)
    header_len = 4;
  else
    header_len = 34;
  if (len < header_len)
    {
      log_info("Dropping DHCP packet: too short");
      return 0;
    }

  response = (struct dhcpv6_response *)safemalloc(sizeof *response);
  memset(response, 0, sizeof *response);
  response->message_type = packet[0];
  response->outer = outer;

  switch(response->message_type)
    {
    case DHCPV6_SOLICIT:
      response->name = "solicit";
      break;

    case DHCPV6_REQUEST:
      response->name = "request";
      break;

    case DHCPV6_INFORMATION_REQUEST:
      response->name = "information_request";
      break;

    case DHCPV6_RENEW:
      response->name = "renew";
      break;

    case DHCPV6_REBIND:
      response->name = "rebind";
      break;

    case DHCPV6_RELEASE:
      response->name = "release";
      break;

    case DHCPV6_DECLINE:
      response->name = "decline";
      break;

    case DHCPV6_CONFIRM:
      response->name = "confirm";
      break;

    case DHCPV6_RELAY_FORWARD:
      response->name = "relay_forward";
      break;

    case DHCPV6_RELAY_REPLY:
      response->name = "relay_reply";
      break;

    case DHCPV6_ADVERTISE:
      response->name = "advertise";
      break;

    case DHCPV6_REPLY:
      response->name = "reply";
      break;

    case DHCPV6_RECONFIGURE:
      response->name = "reconfigure";
      break;
    }
  /* Decode the top-level option space. */
  top = new_option_state();
  if (!decode_option_space(top, (unsigned char *)packet + header_len,
			   (unsigned)len - header_len, &dhcpv6_option_space))
    {
      /* There was something wrong with the option data. */
      printf("Dropping %s: bad option data.", response->name);
      return 0;
    }

#if DEBUG_V6_PACKETS
  option_space_foreach(top, &dhcpv6_option_space,
		       (void *)"v6pi-top", dhcpv6_option_dumper);
#endif

  response->options = top;
  response->received_time = cur_time;

  if (header_len == 4)
    {
      response->xid = dhcpv6_extract_xid(packet, len);
      log_info("xid: %x\n", response->xid);
      if (!extract_ias(response, DHCPV6_IA_NA))
	{
	  log_info("Dropping %s: malformed IA_NA option.", response->name);
	  return 0;
	}
    }
  else
    {

      /* XXX extract the link address, peer address and hop count. */
      response->xid = 0;

      /* Find the encapsulated message. */
      struct option_cache *oc =
	lookup_option(&dhcpv6_option_space, response->options, DHCPV6_RELAY_MESSAGE);

      if (!oc)
	{
	  log_info("Dropping %s: no Relay Message option.", response->name);
	  return 0;
	}
      response = decode_dhcpv6_packet(oc->data.data, oc->data.len, response);
    }

  return response;
}

/* Given an option_state structure, find all the IA_NA options.   Create
 * ia structures from them, and parse out any IA_ADDRESS suboptions.
 */

int
extract_ias(struct dhcpv6_response *response, int code)
{
  struct option_cache *option, *optr;

  /* Look for IA options and de-encapsulate them: */
  option = lookup_option(&dhcpv6_option_space, response->options, code);
  for (optr = option; optr; optr = optr->next)
    {
      struct ia *nouveau;

      /* The IA isn't valid if it's not long enough to contain an
       * IA_ID, T1 and T2 values.
       */
      if (optr->data.len < 12)
	{
	  return 0;
	}
		
      /* Make a new IA structure. */
      nouveau = (struct ia *)safemalloc(sizeof *nouveau);
      memset(nouveau, 0, sizeof nouveau);

      /* Decode IA_ID. */
      nouveau->id = getULong(optr->data.data);
      nouveau->t1 = getULong(optr->data.data + 4);
      nouveau->t2 = getULong(optr->data.data + 8);

      /* Decode suboptions, if any. */
      if (optr->data.len > 4)
	{
	  nouveau->recv_options = new_option_state();
	  if (!decode_option_space(nouveau->recv_options,
				   optr->data.data + 12,
				   optr->data.len - 12,
				   &dhcpv6_option_space))
	    {
	      /* There was something wrong with the
	       * option data.
	       */
	      return 0;
	    }
	  
#if DEBUG_V6_PACKETS
	  option_space_foreach(nouveau->recv_options, &dhcpv6_option_space,
			       (void *)"v6pi-ia", dhcpv6_option_dumper);
#endif

	  extract_ia_addrs(nouveau);
	}
      nouveau->next = response->ias;
      response->ias = nouveau;
    }
  return 1;
}

/* Given an IA, extract any IA_ADDRESS suboptions. */
int
extract_ia_addrs(struct ia *ia)
{
  struct option_cache *option, *optr;

  /* Look for IA_ADDRESS options and de-encapsulate them: */
  option = lookup_option(&dhcpv6_option_space,
			 ia->recv_options, DHCPV6_IA_ADDRESS);
  for (optr = option; optr; optr = optr->next)
    {
      struct ia_addr *nouveau;

      /* The IA_ADDRESS isn't valid if it's not long enough to
       * contain an IPv6 address and the two times.
       */
      if (optr->data.len < 24)
	{
	  return 0;
	}
		
      /* Make a new IA_ADDRESS structure. */
      nouveau = (struct ia_addr *)safemalloc(sizeof *nouveau);
      memset(nouveau, 0, sizeof nouveau);

      /* Copy out address, preferred and valid times: */
      memcpy(&nouveau->address.iabuf, optr->data.data, 16);
      nouveau->address.len = 16;
      nouveau->valid = getULong(&optr->data.data[16]);
      nouveau->preferred = getULong(&optr->data.data[20]);

      /* Decode suboptions, if any. */
      if (optr->data.len > 24)
	{
	  nouveau->recv_options = new_option_state();
	  if (!decode_option_space(nouveau->recv_options, optr->data.data + 24,
				   optr->data.len - 24, &dhcpv6_option_space))
	    {
	      /* There was something wrong with the
	       * option data.
	       */
	      return 0;
	    }
#if DEBUG_V6_PACKETS
	  option_space_foreach(nouveau->recv_options, &dhcpv6_option_space,
			       (void *)"v6pi-iaaddr", dhcpv6_option_dumper);
#endif
	}

      /* Link it in. */
      nouveau->ia = ia;
      nouveau->next = ia->addresses;
      ia->addresses = nouveau;
    }
  return 1;
}

/* Local Variables:  */
/* mode:C++ */
/* c-file-style:"gnu" */
/* end: */
