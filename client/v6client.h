/* v6client.h
 *
 * Definitions for the DHCPv6Client class.
 */

/* Copyright (c) 2005, 2006 Nominum, Inc.   All rights reserved.
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

#ifndef DHCPP_CLIENT_DHCPV6_H
#define DHCPP_CLIENT_DHCPV6_H

#include "dhc++/timeout.h"
#include "dhc++/v6listener.h"
#include "client/controller.h"

class DHCPv6Client; /* forward */

/* Possible states in which the DHCPv4 client can be. */
enum dhcpv6_state {
  S6_SOLICITING,
  S6_SELECTING,
  S6_REQUESTING,
  S6_BOUND,
  S6_RENEWING,
  S6_REBINDING,
  S6_INFORM,
  S6_UNMANAGED,
  S6_CONFIRMING,
  S6_RAPID,
  S6_RELEASING
};

class DHCPv6Client: public Timeout, public DHCPv6Listener
{
public:
  DHCPv6Client(struct interface_info *ip, DHCPClientController *ctlr,
	       u_int8_t *duid_string, int duid_size);
  void state_startup();
  void state_confirm();
  void state_soliciting();
  void state_rapid();
  void state_inform();
  void state_release();
  void state_selecting();
  void state_requesting();
  void state_bound();
  void state_renewing();
  void state_rebinding();
  void state_unmanaged();
  int set_relay_destination(char *dest);

  bool mine(struct dhcpv6_response *rsp);
  void done(void);

protected:

  void advertise(struct dhcpv6_response *response, struct sockaddr_in6 *, const unsigned char *packet, unsigned length);
  void reply(struct dhcpv6_response *response, struct sockaddr_in6 *, const unsigned char *data, unsigned length);

  void event(const char *evname, int selector, int status);

private:
  void send_normal_packet();
  void make_client_options(struct buffer *sid);
  int associate_v6_response(const unsigned char *packet,
			    struct dhcpv6_response *response,
			    const char *name);
  int ias_congruent(struct ia **new_ia_list, struct ia *my_ia_list);

  DHCPClientController *controller;

  duid_t *duid;					  /* DHCP Unique Identifier. */

  struct ia *ias;			    /* IAs belonging to this client. */
  
  struct dhcpv6_response *responses;	       /* Responses received so far. */
  struct dhcpv6_response *selected_response;		/* The one we chose. */
  struct buffer *server_identifier;	   /* Identifier of server we chose. */
  enum dhcpv6_state state;		/* Current state for this interface. */
  struct iaddr relay_destination;		/* When configured to always */
	     /* unicast, send unicasts that should have been multicast here. */
  struct iaddr destination;			    /* Where to send packet. */
  u_int32_t xid;					  /* Transaction ID. */
  u_int64_t first_sending;			/* When was first copy sent? */
  u_int64_t interval;		      /* What's the current resend interval? */
  u_int64_t retransmit;			  /* When's the next retransmission? */
  u_int64_t renewal_time;		        /* When do we need to renew? */
  u_int64_t rebind_time;		       /* When do we need to rebind? */
  u_int64_t solicit_time;	/* When do we need to look for a new server? */
  
  struct client_config *config;			    /* Client configuration. */

  struct option_state *send_options;			 /* Options we send. */
  struct option_state *recv_options;	      /* Options we got from server. */

  /* Information for send_normal_dhcpv6_packet: */
  int sending;		     /* Type of DHCPv6 message we're trying to send. */
  const char *sending_name;		     /* Human-readable name of same. */
  u_int64_t next_state_time;		/* Time at which we should stop
					 * retrying and enter next state.
					 */
  int retransmit_count;		/* Instead of a timeout, specify a number of
				 * retransmissions.
				 */
  enum dhcpv6_state next_state;			     /* Next state to enter. */
};

#endif

/* Local Variables:  */
/* mode:c++ */
/* c-file-style:"gnu" */
/* end: */
