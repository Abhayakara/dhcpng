/* v4client.h
 *
 * Definitions for the DHCPv4Client class.
 */

/* Copyright (c) 2005, 2006 Nominum, Inc.   All rights reserved.
 *
 * Copyright (c) 1995-2002 Internet Software Consortium.
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
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This code is based on the original client state machine that was
 * written by Elliot Poger.  The code has been extensively hacked on
 * by Ted Lemon since then, so any mistakes you find are probably his
 * fault and not Elliot's.
 *
 * This code has been hacked over pretty thoroughly since it branched
 * from the ISC release...
 */

#ifndef DHCPP_CLIENT_DHCPV4_H
#define DHCPP_CLIENT_DHCPV4_H

#include "dhc++/timeout.h"
#include "dhc++/v4listener.h"
#include "client/controller.h"

/* Possible states in which the DHCPv4 client can be. */
enum dhcp_state {
	S4_INIT_REBOOT,
	S4_INIT_REBOOT_NOT_CONFIGURED,
	S4_INIT_REBOOT_CONFIGURED,
	S4_CONFIRM,
#define STATE_INIT_REBOOT(x) ((x) == S4_INIT_REBOOT || (x) == S4_CONFIRM || \
			      (x) == S4_INIT_REBOOT_NOT_CONFIGURED || \
			      (x) == S4_INIT_REBOOT_CONFIGURED)
	S4_INIT,
	S4_INIT_NOT_CONFIGURED,
	S4_INIT_CONFIGURED,
#define STATE_INIT(x) ((x) == S4_INIT || \
		       (x) == S4_INIT_NOT_CONFIGURED ||	\
		       (x) == S4_INIT_CONFIGURED)
	S4_SELECTING,
#define STATE_SELECTING(x) ((x) == S4_SELECTING)
	S4_REQUESTING,
#define STATE_REQUESTING(x) ((x) == S4_REQUESTING)
	S4_BOUND,
	S4_BOUND_NOT_CONFIGURED,
	S4_BOUND_CONFIGURED,
#define STATE_BOUND(x) ((x) == S4_BOUND || \
			(x) == S4_BOUND_NOT_CONFIGURED ||	\
			(x) == S4_BOUND_CONFIGURED)
	S4_DECLINE,
#define STATE_DECLINE(x) ((x) == S4_DECLINE)
	S4_RENEWING,
#define STATE_RENEWING(x) ((x) == S4_RENEWING)
	S4_REBINDING,
#define STATE_REBINDING(x) ((x) == S4_REBINDING)
	S4_STOPPED,
#define STATE_STOPPED(x) ((x) == S4_STOPPED)
	S4_INFORM,
#define STATE_INFORM(x) ((x) == S4_INFORM)
	S4_RELEASING,
#define STATE_RELEASING(x) ((x) == S4_RELEASING)
	S4_UNMANAGED
#define STATE_UNMANAGED(x) ((x) == S4_UNMANAGED)
};

/* DHCP client lease structure... */
struct client_lease
{
  struct client_lease *next;			      /* Next lease in list. */
  u_int64_t expiry;		       /* When the lease completely expires. */
  u_int64_t renewal;			     /* When we should try to renew. */
  u_int64_t rebind;			 /* When we should broadcast renews. */
  struct iaddr address;				    /* Address being leased. */
  char *server_name;				     /* Name of boot server. */
  char *filename;		     /* Name of file we're supposed to boot. */
  auth_key_t *key;		   /* Key used in basic DHCP authentication. */
  
  unsigned int is_bootp: 1;	    /* If set, lease was aquired with BOOTP. */
  
  struct option_state *options;		     /* Options supplied with lease. */
};

class DHCPv4Client: public Timeout, public DHCPv4Listener
{
public:
  DHCPv4Client(struct interface_info *ip, DHCPClientController *ctlr,
	       u_int8_t *duid_string, int duid_size);
  void state_startup();
  void state_confirm();
  void state_init_reboot();
  void state_init_reboot_not_configured();
  void state_init_reboot_configured();
  void state_init();
  void state_init_not_configured();
  void state_init_configured();
  void state_selecting();
  void state_requesting();
  void state_decline();
  void state_bound();
  void state_bound_not_configured();
  void state_bound_configured();
  void state_renewing();
  void state_rebinding();
  void state_inform();
  void state_releasing();
  void state_stopped();
  void state_unmanaged();
  void bootp(struct packet *packet);
  void dhcp(struct packet *packet);

private:
  void bind_lease();
  void dhcpack(struct packet *packet);
  void dhcpoffer(struct packet *packet);
  struct client_lease *packet_to_lease(struct packet *packet);
  void dhcpnak(struct packet *packet);
  void send_v4_packet(bool retransmit);
  void make_client_options(struct client_lease *lease,
			   u_int8_t *type,
			   struct option_cache *sid,
			   struct iaddr *rip,
			   u_int32_t *prl,
			   struct option_state **op);
  void make_packet(struct client_lease *lease, u_int8_t type);
  void event(const char *evname, int newState, int status);
  void set_destination();
  void interface_configure(enum dhcp_state reportState,
			   const char *oldName,
			   struct client_lease *oldLease,
			   const char *newName,
			   struct client_lease *newLease,
			   enum dhcp_state failState,
			   enum dhcp_state succeedState);

  duid_t *duid;					  /* DHCP Unique Identifier. */

  DHCPClientController *controller;

  struct client_lease *active;			  /* Currently active lease. */
  struct client_lease *nouveau;				       /* New lease. */
  struct client_lease *offered_leases;		    /* Leases offered to us. */
  struct client_lease *leases;			/* Leases we currently hold. */

  enum dhcp_state state;	       	/* Current state for this interface. */
  struct sockaddr_in destination;		    /* Where to send packet. */
  u_int32_t xid;					  /* Transaction ID. */
  u_int16_t secs;			    /* secs value from DHCPDISCOVER. */
  u_int64_t first_sending;			/* When was first copy sent? */
  u_int64_t interval;		      /* What's the current resend interval? */
  struct dhcp_packet packet;			    /* Outgoing DHCP packet. */
  unsigned packet_length;	       /* Actual length of generated packet. */
  
  struct iaddr requested_address;	    /* Address we would like to get. */
  
  struct client_config *config;			    /* Client configuration. */
  struct string_list *env;		       /* Client script environment. */
  int envc;				/* Number of entries in environment. */

  const char *packet_type_name;	 /* Name of packet we are currently sending. */
  
  struct option_state *sent_options;			 /* Options we sent. */
};

#endif

/* Local Variables:  */
/* mode:C++ */
/* c-file-style:"gnu" */
/* end: */
