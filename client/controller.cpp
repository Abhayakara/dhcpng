/* controller.cpp
 *
 * The code in this file provides an interface between the DHCP client and
 * a controller of some kind.   This controller tells the client when to
 * configure an interface, and in turn the client tells the controller what
 * it's gotten in its communications with the DHCP server.   Some parts of the
 * protocol state machine require a round trip to the controller (which may
 * be an external program like NetworkManager) before the next step in the
 * protocol can be followed.
 */

/*
 * Copyright (c) 2005-2006 Nominum, Inc.   All rights reserved.
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
  "$Id: controller.cpp,v 1.11 2012/03/30 23:10:25 mellon Exp $ Copyright (c) 2002-2005 Nominum, Inc.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"
#include "version.h"
#include "client/v4client.h"
#include "client/v6client.h"
#include "client/controller.h"

static char qq[] = { 0 };

DHCPClientController::DHCPClientController()
{
  /* XXX */
  config = 0;
  prefix = qq;
}

DHCPClientController::~DHCPClientController()
{
}

/* Start a transmission.    Sends the basic information out. */
void DHCPClientController::start(struct client_config *nc, const char *reason)
{
  if (!nc)
    return;

  initialize();

  config = nc;

  if (nc->interface)
    prefix = nc->interface->name;
  else if (nc->name)
    prefix = config->name;
  else
    prefix = qq;

  add_item("reason", "%s", reason);
  add_item("pid", "%ld", (long int)getpid ());
}

/* Static function called when we're traversing the options.   All it does
 * is get the object out of stuff and call its option_internal() method
 * on the rest of the arguments.
 */
void DHCPClientController::option(struct option_cache *oc,
				  struct option_state *options,
				  struct option_space *u, void *stuff)
{
  DHCPClientController *me = (DHCPClientController *)stuff;
#if 0
  log_info("option: %s.%s %s",
	   oc->option->name, u->name,
	   print_hex_1(oc->data.len, oc->data.data, 60));
#endif
  me->option_internal(oc, options, u);
}

/* Send the contents of an individual option to the controller. */
void DHCPClientController::option_internal(struct option_cache *oc,
					   struct option_state *options,
					   struct option_space *u)
{
  if (oc->data.len)
    {
      char name[256];

      /* Certain DHCPV6 options shouldn't get dumped. */
      if (oc->option->option_space == &dhcpv6_option_space &&
	  (oc->option->code == DHCPV6_DUID ||
	   oc->option->code == DHCPV6_SERVER_IDENTIFIER ||
	   oc->option->code == DHCPV6_IA_NA ||
	   oc->option->code == DHCPV6_IA_TA ||
	   oc->option->code == DHCPV6_IA_ADDRESS ||
	   oc->option->code == DHCPV6_AUTHENTICATION ||
	   oc->option->code == DHCPV6_VENDOR_SPECIFIC_INFORMATION ||
	   oc->option->code == DHCPV6_IA_PD))
	return;

      if (option_name_clean(name, sizeof name, oc->option))
	{
	  add_item(name, "%s", pretty_print_option(oc->option,
						   oc->data.data,
						   oc->data.len,
						   1));
	}
    }
}

/* This is called to configure or deconfigure a lease. */

void DHCPClientController::send_lease(const char *pfx,
				      struct client_lease *lease,
				      struct option_state *options)
{
  struct option_cache *oc;

  prefix = (char *)safemalloc(strlen(pfx) + 1);
  strcpy(prefix, pfx);

  if (lease)
    add_item("ip_address", "%s", piaddr(lease->address));

  /* Compute the network address based on the supplied ip
   * address and netmask, if provided.  Also compute the
   * broadcast address (the host address all ones broadcast
   * address, not the host address all zeroes broadcast
   * address).
   */

  oc = lookup_option(&dhcp_option_space, options, DHO_SUBNET_MASK);
  if (lease && oc)
    {
      if (oc->data.len > 3)
	{
	  struct iaddr netmask, subnet, broadcast;

	  memcpy(netmask.iabuf, oc->data.data, oc->data.len);
	  netmask.len = oc->data.len;

	  subnet = subnet_number(lease->address, netmask);
	  if (subnet.len)
	    {
	      add_item("network_number", "%s", piaddr (subnet));

	      oc = lookup_option(&dhcp_option_space,
				 lease->options,
				 DHO_BROADCAST_ADDRESS);
	      if (!oc)
		{
		  broadcast = broadcast_addr(subnet, netmask);
		  if (broadcast.len)
		    {
		      add_item("broadcast_address", "%s", piaddr (broadcast));
		    }
		}
	    }
	}
    }

  if (lease && lease->filename)
    add_item("filename", "%s", lease->filename);
  if (lease && lease->server_name)
    add_item("server_name", "%s", lease->server_name);

  send_options(options);

  if (lease)
    add_item("expiry", "%lu", (long)SECONDS(lease->expiry));
}

void DHCPClientController::compose_ia_prefix(struct ia *ia)
{
  char *pptr;
  int pblen;

  pblen = (/*(config->duid->len * 2 + 1) +*/		/* DUID as hex */
	   8 + 1 +					/* IAID, 4 bytes. */
	   1);						/* NUL. */

  pptr = prefix = (char *)safemalloc(pblen);
#if 0
  unsigned i;
  for (i = 0; i < config->duid->len; i++)
    {
      /* You could argue that this should be network byte order, but
       * it's just being used as a key, and for any given machine it
       * will always be consistent, so I don't think it's worth the
       * complexity.  The controller should be treating the DUID as
       * opaque.  You can flame me later if this turns into a problem.
       */
      sprintf(pptr, "%02x", ((unsigned char *)&config->duid->data)[i]);
      pptr += 2;
    }
  *pptr++ = '/';
#endif

  sprintf(pptr, "%08lx", (unsigned long)(ia->id));
  pptr += 8;
  *pptr = 0;
}

void DHCPClientController::send_ia_addr(const char *type,
					struct ia_addr *address)
{
  char *oprefix = prefix;
  char addrbuf[128];
  unsigned i;

  /* Make an IP address. */
  inet_ntop(AF_INET6, address->address.iabuf, addrbuf, sizeof addrbuf);

  i = strlen(oprefix);
  prefix = (char *)safemalloc(strlen(addrbuf) + i + 2);
  strcpy(prefix, oprefix);
  prefix[i] = '/';
  strcpy(prefix + i + 1, addrbuf);

  /* Type says what we're doing with this address - add, delete or
   * update.   We don't do a dbus_add_item() for the address, since
   * it's part of the name of the object.
   */
  add_item("action", "%s", type);

  /* If we're deleting the address, we needn't say anything more. */
  if (!strcmp(type, "delete"))
    return;

  add_item("valid", "%ld", (unsigned long)address->valid);
  add_item("preferred", "%ld", (unsigned long)address->preferred);
	
  /* Now emit the options attached to this address, if it's
   * valid.
   */
  send_options(address->recv_options);
  prefix = oprefix;
}

void DHCPClientController::send_ia(struct ia *ia)
{
  char *oprefix = prefix;

  compose_ia_prefix(ia);

  /* Now emit the options attached to this address, if it's
   * valid.
   */
  send_options(ia->recv_options);
  prefix = oprefix;
}

void DHCPClientController::send_options(struct option_state *state)
{
  unsigned i;

  if (!state)
    return;

  for (i = 0; i < state->option_space_count; i++)
    {
      option_space_foreach(state, option_spaces[i],
			   (void *)this, DHCPClientController::option);
    }
}

/* Local Variables:  */
/* mode:c++ */
/* c-file-style:"gnu" */
/* end: */
