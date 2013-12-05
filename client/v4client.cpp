/* v4client.c
 *
 * DHCPv4 protocol engine.
 */

/* Copyright (c) 2005-2006 Nominum, Inc.   All rights reserved.
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

#ifndef lint
static char ocopyright[] __attribute__((unused)) =
  "$Id: v4client.cpp,v 1.9 2012/03/30 23:10:25 mellon Exp $ Copyright (c) 2005-2006 Nominum, Inc.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"
#include "version.h"

#include "client/v4client.h"
#include "client/controller.h"
#include "client/client.h"

TIME default_lease_time = 43200; /* 12 hours... */
TIME max_lease_time = 86400; /* 24 hours... */

int dhcp_max_agent_option_packet_length = 0;

/* New DHCPv4Client objects are always associated with interfaces.   The
 * constructor grabs the interface, sets up a copy of the top level config
 * structure, generates a new xid, and that's it.
 */

DHCPv4Client::DHCPv4Client(struct interface_info *ip,
			   DHCPClientController *ctlr,
			   u_int8_t *duid_string, int duid_size)
{
  active = nouveau = offered_leases = leases = 0;
  state = S4_UNMANAGED;
  memset(&destination, 0, sizeof destination);
  xid = random();
  secs = 0;
  first_sending = 0;
  interval = 0;
  memset(&packet, 0, sizeof packet);
  packet_length = 0;
  memset(&requested_address, 0, sizeof requested_address);
  config = ((struct client_config *)safemalloc(sizeof (struct client_config)));
  memcpy(config, &top_level_config, sizeof top_level_config);
  config->interface = ip;
  duid = (duid_t *)safemalloc(duid_size + sizeof (u_int32_t));
  duid->len = duid_size;
  memcpy((char *)&duid->data, duid_string, duid_size);
  env = 0;
  envc = 0;
  packet_type_name = "bogon";
  sent_options = 0;
  controller = ctlr;
}

/* Called to start the process - mainly this just delays for a random
 * amount of time so as to avoid having a lot of clients sending their
 * initial packets at the same time after recovering from a power loss.
 */

void DHCPv4Client::state_startup()
{
  /* Start up after about five seconds, and try the INIT-REBOOT state
   * or fall back to INIT if we don't still have a valid lease.
   */
  addTimeout(cur_time + (random() % 5000000) * 1000ULL, S4_INIT_REBOOT);
}

/* Start in the INIT-REBOOT state if we have a valid lease; otherwise,
 * calls state_init() to start in the INIT state.
 */
void DHCPv4Client::state_init_reboot()
{
  /* If we don't remember an active lease, go straight to INIT. */
  if (!active || active->is_bootp || active->expiry <= cur_time)
    {
      state_init();
      return;
    }

  /* Get rid of any pending timeouts - the exit from this state will
   * set any back up again that need to be set back up.
   */
  clearTimeouts();

  /* We are in the rebooting state. */
  state = S4_INIT_REBOOT;

  /* Set up a null configuration. */
  interface_configure(state, 0, 0, 0, 0,
		      S4_INIT_REBOOT_NOT_CONFIGURED, S4_INIT_REBOOT_CONFIGURED);

  /* If it doesn't happen within 30 seconds, get uppity. */
  addTimeout(cur_time + NANO_SECONDS(30), S4_INIT_REBOOT_NOT_CONFIGURED);
}

/* This gets called if the process of configuring the interface into the
 * null state times out; there's not much we can do in this case other than
 * to go to the unmanaged state.
 */
void DHCPv4Client::state_init_reboot_not_configured()
{
  clearTimeouts();

  log_error("dbus interface reboot-state configure failed on %s.",
	    config->interface->name);
  state_unmanaged();
}

/* This gets called after the interface has been successfully configured
 * into the null state - at this point we can send our DHCPREQUEST.
 */
void DHCPv4Client::state_init_reboot_configured()
{
  clearTimeouts();
  state = S4_INIT_REBOOT_CONFIGURED;

  /* Make a DHCPREQUEST packet, and set appropriate per-interface flags. */
  make_packet(active, DHCPREQUEST);
  set_destination();

  /* Send out the first DHCPREQUEST packet. */
  send_v4_packet(true);

  /* Normally we should hear an answer almost immediately; this answer will
   * be a DHCPNAK or a DHCPACK.   There's no requirement that the server ping
   * in this case.   If we hear neither within four seconds, start using the
   * address.
   */
  addTimeout(cur_time + NANO_SECONDS(4), S4_BOUND);
}

/* This is called when we get an indication that we're in a different
 * location, in order to confirm that the address we currently have
 * configured is still valid.   We don't deconfigure the address, but we
 * do broadcast, so it's a lot like the REBINDING state.
 */
void DHCPv4Client::state_confirm()
{
  int oldState = state;

  clearTimeouts();
  state = S4_CONFIRM;

  /* T1 has expired. */
  make_packet(active, DHCPREQUEST);
  set_destination();
  send_v4_packet(true);

  /* If we don't get a reply, we can't do anything else, so just go back
   * to the previous state.
   */
  addTimeout(cur_time + NANO_SECONDS(30), oldState);
}  

/* Called when a lease has completely expired and we've been unable to
 * renew it, or when we start up and don't have an active lease, or after
 * we have received a DHCPNAK.
 */

void DHCPv4Client::state_init()
{
  clearTimeouts();

  state = S4_INIT;

  /* Set up a null configuration. */
  interface_configure(state, 0, 0, 0, 0,
		      S4_INIT_NOT_CONFIGURED, S4_INIT_CONFIGURED);

  /* If it doesn't happen within 30 seconds, get uppity. */
  addTimeout(cur_time + NANO_SECONDS(30), S4_INIT_NOT_CONFIGURED);
}

/* We tried to configure a null address, and didn't hear back.
 * Nothing we can do at this point.
 */
void DHCPv4Client::state_init_not_configured()
{
  clearTimeouts();

  log_error("dbus interface init-state configure failed on %s.",
	    config->interface->name);
  state_unmanaged();
}

/* Our null address got configured, so we can now send a DHCPDISCOVER. */

void DHCPv4Client::state_init_configured()
{
  /* Make a DHCPDISCOVER packet, and set appropriate per-interface
     flags. */
  make_packet(active, DHCPDISCOVER);
  set_destination();

  /* Send the first discover packet. */
  send_v4_packet(true);

  /* We never time out of the init state. */
}

/* One or more DHCPOFFER packets have been received, and the select timeout
 * has passed.
 */

void DHCPv4Client::state_selecting()
{
  struct client_lease *lp, *next, *picked;

  clearTimeouts();
  state = S4_SELECTING;

  /* Pick an offered lease.   Mainly we take the first one that we were
   * offered, but if we requested an address, and we were offered a lease
   * with that address, that lease will be at the head of the list, so
   * we'll wind up choosing it.
   */
  picked = (struct client_lease *)0;
  for (lp = offered_leases; lp; lp = next)
    {
      next = lp->next;

      /* Check to see if we got an ARPREPLY for the address
       * in this particular lease.
       * (As you can see, we don't actually check.)
       */
      if (!picked)
	{
	  picked = lp;
	  picked->next = (struct client_lease *)0;
	}
    }
  offered_leases = (struct client_lease *)0;

  /* If we just tossed all the leases we were offered, go back
   * to square one.
   */
  if (!picked)
    {
      state_init();
      return;
    }

  /* If it was a BOOTREPLY, we can just take the address right now. */
  if (picked->is_bootp)
    {
      nouveau = picked;

      /* Make up some lease expiry times
	 XXX these should be configurable. */
      nouveau->expiry = cur_time + 12000;
      nouveau->renewal += cur_time + 8000;
      nouveau->rebind += cur_time + 10000;

      /* Bind to the lease. */
      state_bound();
      return;
    }

  /* Ask for the lease we picked. */
  nouveau = picked;
  state_requesting();
}

/* We reach this state when we've picked a lease, and we want to request
 * it from the DHCP server that offered it to us.
 */

void DHCPv4Client::state_requesting()
{
  clearTimeouts();

  /* We shouldn't ever get here without a selected lease. */
  if (!nouveau)
    state_init();

  state = S4_REQUESTING;

  /* Make a DHCPREQUEST packet. */
  make_packet(nouveau, DHCPREQUEST);
  set_destination();

  /* Send it. */
  send_v4_packet(true);

  /* If we don't get a DHCPACK within 30 seconds, something's wrong,
   * and we need to go back to init.
   */
  addTimeout(cur_time + NANO_SECONDS(30), S4_INIT);
}  

/* This is called by the external controller class when for some
 * reason installing the lease turns out to have been a mistake.
 * Right now I'm not sure when this would happen, but here it is.
 *
 * Oh, the code here assumes that we didn't actually configure the
 * address we were offered.   This is consistent with the way the
 * process is supposed to run: we are supposed to ARP for the address,
 * and we can do that _before_ we configure the interface with the
 * address.   However, it's possible that in some cases we may
 * try to configure the address on the interface and thereby discover
 * that it's already in use; in that case the thing that tells us to
 * decline it must put the interface into the null address state
 * before telling us to decline the address we were given.
 */
void DHCPv4Client::state_decline()
{
  clearTimeouts();
  state = S4_DECLINE;

  /* We don't get an acknowledgement for a DHCPDECLINE, so only
   * send it once.
   */
  make_packet(active, DHCPDECLINE);
  set_destination();
  send_v4_packet(false);

  /* Ditch the lease we declined. */
  active = (struct client_lease *)0;

  /* Go try to get a new lease. */
  state_init();
}

/* Bind to the lease that we decided on. */
void DHCPv4Client::state_bound()
{
  enum dhcp_state oldState = state;
  clearTimeouts();

  /* After we launch the dbus message, we should get an immediate reply
   * back indicating that the interface was configured.   If we don't
   * get a reply after thirty seconds, we're hosed.   We can tell that
   * we haven't gotten a state-changing reply yet (it could come in before
   * the call to interface_configure() returns) because state will still
   * be S4_BOUND; don't set the timeout if it's not.
   *
   * We put the call to addTimeout() here because it's entirely possible
   * that the succeed event will be called during our call to
   * interface_configure() below, and we don't want to accidentally
   * install the timeout *after* the handler is called.
   */
  if (state == S4_BOUND)
    addTimeout(cur_time + NANO_SECONDS(30), S4_BOUND_NOT_CONFIGURED);

  state = S4_BOUND;

  if (STATE_INIT_REBOOT(oldState))
    {
      /* Nothing's changing except the active lease is actually being
       * configured on the interface.
       */
      interface_configure(oldState, 0, 0, "", active,
			  S4_DECLINE, S4_BOUND_CONFIGURED);
    }
  else
    {
      struct client_lease *old = active;

      /* Replace the old active lease with the new one. */
      active = nouveau;
      nouveau = (struct client_lease *)0;

      interface_configure(oldState, "old", old, "new", active,
			  S4_DECLINE, S4_BOUND_CONFIGURED);
    }

}

/* The process of configuring the interface with the new address failed.
 * Not much we can do.
 */
void DHCPv4Client::state_bound_not_configured()
{
  active = 0;
  log_error("dbus address bind on %s.",
	    config->interface->name);
  state_unmanaged();
}

/* The process of configuring the interface completed successfully.
 * Set up a timeout to renew the lease.
 */
void DHCPv4Client::state_bound_configured()
{
  clearTimeouts();

  /* Set up a timeout to start the renewal process. */
  addTimeout(active->renewal, S4_RENEWING);

  log_info("bound to %s -- renewal in %ld seconds.",
	   piaddr(active->address),
	   (long)(SECONDS(active->renewal - cur_time)));
}

/* This is called when the renewal time on the lease we've bound to has
 * expired.   We are expected to unicast a DHCPREQUEST to the server
 * that gave us our original lease.
 */
void DHCPv4Client::state_renewing()
{
  clearTimeouts();
  state = S4_RENEWING;

  /* T1 has expired. */
  make_packet(active, DHCPREQUEST);
  set_destination();
  send_v4_packet(true);

  addTimeout(active->rebind, S4_REBINDING);
}  

/* This is called when the rebinding time on the lease we've bound to has
 * expired.   We are expected to unicast a DHCPREQUEST to the server
 * that gave us our original lease.
 */
void DHCPv4Client::state_rebinding()
{
  clearTimeouts();
  state = S4_REBINDING;

  /* T1 has expired. */
  make_packet(active, DHCPREQUEST);
  set_destination();
  send_v4_packet(true);

  /* If the lease actually expires, we have to go get a new one. */
  addTimeout(active->expiry, S4_INIT);
}  

/* We've been asked to release the lease.   Do so. */

void DHCPv4Client::state_releasing()
{
  /* is there even a lease to release? */
  if (active)
    {
      /* Get rid of any pending timeouts. */
      clearTimeouts();

      state = S4_RELEASING;

      /* Make a DHCPRELEASE packet, and set appropriate per-interface
	 flags. */
      make_packet(active, DHCPRELEASE);
      set_destination();

      /* Send out the first and only DHCPRELEASE packet. */
      send_v4_packet(false);

      /* Inform the external controller that we released the lease. */
      controller->start(config, "RELEASE");
      controller->send_lease("old_", active, active->options);
      controller->finish(0, 0, 0);
    }

  /* Until we're told to manage the interface again, go to the
   * unmanaged state.
   */
  state_unmanaged();
}

/* Send a DHCPINFORM.   This is a temporary state transition, and is only
 * allowed from the BOUND and UNMANAGED states.   Once the DHCPINFORM has been
 * acknowledged or ignored, we return to the former state.
 */

void DHCPv4Client::state_inform()
{
  enum dhcp_state oldState = state;

  /* Alone of all the state_() functions, this one doesn't cancel existing
   * timeouts.   This is because it can only be called in the BOUND state
   * or the UNMANAGED state; in the former case, if the time comes to renew,
   * we want to renew; in the latter case, there are no pending timeouts.
   */

  if (config->interface->ipv4_addr_count < 1)
    {
      log_error ("Can't send DHCPINFORM: interface %s has no IP address!",
		 config->interface->name);

      /* Can't do anything further. */
      return;
    }

  /* We are in the information request state. */
  state = S4_INFORM;

  /* Make a DHCPINFORM packet, set the destination, and send it off. */
  make_packet(0, DHCPINFORM);
  set_destination();
  send_v4_packet(true);

  /* If we don't get a response in 30 seconds, give up and go back
   * to our previous state, which should be either S4_BOUND or S4_STOPPED.
   */
  addTimeout(cur_time + NANO_SECONDS(30), oldState);
}

/* This is called when we've been told to shut down.  We unconfigure
 * the interfaces, and then stop operating until told otherwise.
 */

void DHCPv4Client::state_stopped()
{
  /* Cancel all timeouts. */
  clearTimeouts();

  /* If we have an address, unconfigure it. */
  if (active)
    {
      controller->start(config, "STOP");
      controller->send_lease("old_", active, active->options);
      controller->finish(0, 0, 0);
    }
  log_info("stopping activity on %s", config->interface->name);
}  

/* This is called when we've been told not to manage the interface's IP
 * address.
 */

void DHCPv4Client::state_unmanaged()
{
  /* If we were doing something, stop doing it. */
  clearTimeouts();

  state = S4_UNMANAGED;
  log_info("no longer managing %s", config->interface->name);
}  

/*
 * dhcpack is called when we receive a DHCPACK message.   Which of course
 * can happen at any time, although in the protocol normally it only happens
 * after we have sent a DHCPREQUEST or a DHCPINFORM.
 */

void DHCPv4Client::dhcpack(struct packet *packet)
{
  struct option_cache *oc;
  enum dhcp_state old_state;
  
  /* If we aren't expecting a DHCPACK, log it and drop it. */
  if (state != S4_INIT_REBOOT_CONFIGURED && state != S4_CONFIRM &&
      state != S4_REQUESTING && state != S4_RENEWING &&
      state != S4_REBINDING && state != S4_INFORM)
    {
#if defined (DEBUG)
      log_debug ("DHCPACK in wrong state.");
#endif
      return;
    }

  log_info ("DHCPACK from %s", piaddr(packet->sender_addr));

  /* Save the current value of the state so that we can cancel the
   * upcoming timeout if all goes well.
   */
  old_state = state;

  /* If we aren't doing a DHCPINFORM, make a lease structure out of
   * what was offered and do some lease time math. */
  if (!STATE_INFORM(state))
    {
      nouveau = packet_to_lease(packet);
      /* Figure out the lease time. */
      oc = lookup_option (&dhcp_option_space,
			  nouveau->options, DHO_DHCP_LEASE_TIME);
      if (oc)
	{
	  if (oc->data.len > 3)
	    nouveau->expiry = getULong (oc->data.data);
	  else
	    nouveau->expiry = 0;
	}
      else
	nouveau->expiry = 0;

      /* If the lease doesn't have an expiry time, it's invalid, so all we
       * can do is drop it and keep waiting to see if something useful
       * comes in.
       */
      if (!nouveau->expiry)
	{
	  log_error ("no expiry time on offered lease.");
	  return;
	}

      /* Take the server-provided renewal time if there is one. */
      oc = lookup_option (&dhcp_option_space,
			  nouveau->options, DHO_DHCP_RENEWAL_TIME);
      if (oc)
	{
	  if (oc->data.len > 3)
	    nouveau->renewal = getULong (oc->data.data);
	  else
	    nouveau->renewal = 0;
	}
      else
	nouveau->renewal = 0;
		
      /* If it wasn't specified by the server, calculate it. */
      if (!nouveau->renewal)
	nouveau->renewal = nouveau->expiry / 2;

      /* Same deal with the rebind time. */
      oc = lookup_option(&dhcp_option_space,
			 nouveau->options, DHO_DHCP_REBINDING_TIME);
      if (oc)
	{
	  if (oc->data.len > 3)
	    nouveau->rebind = getULong(oc->data.data);
	  else
	    nouveau->rebind = 0;
	}
      else
	nouveau->rebind = 0;
		
      /* Rebinding time is 7/8ths of expiry time. */
      if (!nouveau->rebind)
	nouveau->rebind = nouveau->expiry - nouveau->expiry / 8;
		
      /* Compute the times relative to the present.   Note that because
       * we are now using u_int64_t's instead of u_int32_t's for the math,
       * there is no chance of an overflow, even if cur_time == TIME_MAX,
       * because there are still three binary orders of magnitude of headroom
       * in that case.
       */
      nouveau->expiry = cur_time + NANO_SECONDS(nouveau->expiry);
      nouveau->renewal = cur_time + NANO_SECONDS(nouveau->renewal);
      nouveau->rebind = cur_time + NANO_SECONDS(nouveau->rebind);

      /* Bind to the lease. */
      state_bound();
    }
  else
    {
      /* Run the client script with the new parameters. */
      controller->start(config, "DHCPINFORM");
      controller->send_lease("inform_",
			       (struct client_lease *)0, packet->options);
      controller->finish(0, 0, 0);

      /* We only ever do DHCPINFORM when we're in BOUND or UNMANAGED states,
       * so go back to whichever of those states is appropriate.
       */
      if (active)
	state_bound_configured();
      else
	state_unmanaged();
    }
}

/* We received a DHCP packet - see if it's for this instance, and if so
 * possibly do something with it.
 */
void DHCPv4Client::dhcp(struct packet *packet)
{
  struct iaddrlist *ap;
  const char *type;
  struct option_cache *oc;

  /* Check to see if this is out packet.   If it's not a packet that a
   * client should ever receive, just drop it - don't bother to see if it
   * was directed at us.
   */
  switch (packet->packet_type)
    {
    case DHCPOFFER:
      type = "DHCPOFFER";
      break;

    case DHCPNAK:
      type = "DHCPNACK";
      break;

    case DHCPACK:
      type = "DHCPACK";
      break;

    default:
      return;
    }

  /* Okay, we got a DHCP packet that might be interesting.   Is it for us? */

  /* If the xid is wrong, not our packet. */
  if (packet->raw->xid != xid)
    return;
  
  /* See if the client identifier matches. */
  oc = lookup_option(&dhcp_option_space,
		     packet->options, DHO_DHCP_CLIENT_IDENTIFIER);

  /* If the client identifier is present and doesn't match, it doesn't
   * belong to this instance.
   */
  if (oc)
    {
      /* Length doesn't match? */
      if (oc->data.len != duid->len + 5)
	return;

      /* We only send RFC4361-style client identifiers, so if this ain't one,
       * it ain't ours, and it doesn't belong to any DHCPv4 client, so we
       * can just claim it and drop it.
       */
      if (oc->data.data[0] != 255)
	return;

      /* Interface ID has to match. */
      if (getLong(&oc->data.data[1]) != config->interface->index)
	return;

      /* DUID has to match. */
      if (!memcmp(&duid->data, &oc->data.data[6], duid->len))
	return;
      /* Guess it's ours... */
    }
  else if ((packet->interface->lladdr.hlen - 1 != packet->raw->hlen) ||
	   config->interface->lladdr.hbuf[0] != packet->raw->htype ||
	   memcmp (&packet->interface->lladdr.hbuf [1],
		   packet->raw->chaddr, packet->raw->hlen))
    return;

  /* If there's a reject list, make sure this packet's sender isn't
     on it. */
  for (ap = config->reject_list; ap; ap = ap->next)
    {
      if (addr_eq (packet->sender_addr, ap->addr))
	{
	  log_info ("%s from %s rejected.", type, piaddr (ap->addr));
	  return;
	}
    }

  switch (packet->packet_type)
    {
    case DHCPOFFER:
      dhcpoffer(packet);
      break;

    case DHCPNAK:
      dhcpnak(packet);
      break;

    case DHCPACK:
      dhcpack(packet);
      break;
    }
  return;
}

/* We got a DHCPOFFER.   If we can use it, use it; otherwise, drop it. */

void DHCPv4Client::dhcpoffer(struct packet *packet)
{
  struct client_lease *lease, *lp;
  int i;
  int stop_selecting;
  const char *name = packet->packet_type ? "DHCPOFFER" : "BOOTREPLY";
  char obuf [1024];
	
#ifdef DEBUG_PACKET
  dump_packet(packet);
#endif	

  /* If we're not receptive to an offer right now, just drop it. */
  if (state != S4_SELECTING && !STATE_INIT(state))
    {
#if defined (DEBUG)
      log_debug ("%s in wrong transaction.", name);
#endif
      printf("dropping packet because we're in state %d, not state %d\n",
	     state, S4_SELECTING);
      return;
    }

  sprintf(obuf, "%s for %s from %s", name, inet_ntoa(packet->raw->yiaddr),
	  piaddr(packet->sender_addr));

  /* If this lease doesn't supply the minimum required parameters,
   * blow it off.
   */
  if (config->required_options)
    {
      for (i = 0; config->required_options[i]; i++)
	{
	  if (!lookup_option(&dhcp_option_space, packet->options,
			     config->required_options[i]))
	    {
	      struct option *opt = find_option(&dhcp_option_space,
					       config->required_options[i]);
	      log_info ("%s: no %s option.", obuf, opt->name);
	      return;
	    }
	}
    }

  /* XXX there's an obvious opportunity for a DoS here. */

  /* If we've already seen this lease, don't record it again. */
  for (lease = offered_leases; lease; lease = lease->next)
    {
      if (lease->address.len == sizeof packet->raw->yiaddr &&
	  !memcmp (lease->address.iabuf,
		   &packet->raw->yiaddr, lease->address.len))
	{
	  log_debug ("%s: already seen.", obuf);
	  return;
	}
    }

  lease = packet_to_lease(packet);

  /* If this lease was acquired through a BOOTREPLY, make a note of it. */
  if (!packet->options_valid || !packet->packet_type)
    lease->is_bootp = 1;

  /* Figure out when we're supposed to stop selecting. */
  stop_selecting = first_sending + config->select;

  /* XXX there's another obvious opportunity for a DoS here. */

  /* If this is the lease we asked for, put it at the head of the
   * list, and don't mess with the arp request timeout.
   */
  if (lease->address.len == requested_address.len &&
      !memcmp (lease->address.iabuf, requested_address.iabuf,
	       requested_address.len))
    {
      lease->next = offered_leases;
      offered_leases = lease;
    }
  else
    {
      /* Put the lease at the end of the list. */
      lease->next = (struct client_lease *)0;
      if (!offered_leases)
	offered_leases = lease;
      else
	{
	  for (lp = offered_leases; lp->next; lp = lp->next)
	    ;
	  lp->next = lease;
	}
    }

  /* If the selecting interval has expired, go immediately to
   * state_selecting().  Otherwise, time out into state_selecting
   * at the select interval.
   */
  log_info ("%s", obuf);

  if (stop_selecting <= 0)
    state_selecting();
  else
    {
      /* We don't need to send any more DHCPDISCOVER packets - just
       * set a select timeout.
       */
      clearTimeouts();
      addTimeout(stop_selecting, S4_SELECTING);
    }
}

/* We received a BOOTP packet - see if it's for this instance, and if so
 * possibly do something with it.
 */
void DHCPv4Client::bootp(struct packet *packet)
{
  struct iaddrlist *ap;

  /* We're a client, so BOOTREQUESTs that we hear aren't for us. */
  if (packet->raw->op != BOOTREPLY)
    return;

  /* If the xid doesn't match, it's not for us. */
  if (packet->raw->xid != xid)
    return;

  /* See if the hardware address sent in the packet matches our own. */
  if (packet->interface->lladdr.hlen - 1 != packet->raw->hlen ||
      packet->interface->lladdr.hbuf[0] != packet->raw->htype ||
      memcmp (&packet->interface->lladdr.hbuf[1],
	      packet->raw->chaddr, packet->raw->hlen))
    return;

  /* It is for us, apparently. */

  /* If there's a reject list, make sure this packet's sender isn't on it. */
  for (ap = config->reject_list; ap; ap = ap->next)
    {
      if (addr_eq (packet->sender_addr, ap->addr))
	{
	  log_info ("BOOTREPLY from %s rejected.", piaddr (ap->addr));
	  return;
	}
    }
	
  dhcpoffer (packet);
  return;
}

/* We got a DHCPNAK.   If we just sent a DHCPREQUEST, the address we asked
 * for isn't valid, and we need to get a new one.*/

void DHCPv4Client::dhcpnak(struct packet *packet)
{
  if (state != S4_INIT_REBOOT_CONFIGURED && state != S4_CONFIRM &&
      state != S4_REQUESTING && state != S4_RENEWING && state != S4_REBINDING)
    {
#if defined (DEBUG)
      log_debug ("DHCPNAK in wrong state.");
#endif
      return;
    }

  log_info ("DHCPNAK from %s", piaddr(packet->sender_addr));

  /* In the requesting state we don't have an active lease; otherwise
   * we should have one.
   */
  if (!STATE_REQUESTING(state) && !active)
    {
#if defined (DEBUG)
      log_info ("DHCPNAK with no active lease.\n");
#endif
      return;
    }

  /* In this case we need to deconfigure the IP address from the
   * interface.
   */
  if (!STATE_REQUESTING(state))
    {
      
    }
  active = (struct client_lease *)0;

  /* Stop sending DHCPREQUEST packets... */
  clearTimeouts();

  /* Try to get an IP address. */
  state_init();
}

/* Allocate a client_lease structure and initialize it from the parameters
   in the specified packet. */

struct client_lease *DHCPv4Client::packet_to_lease(struct packet *packet)
{
  struct client_lease *lease;
  unsigned i;
  struct option_cache *oc;

  lease = (struct client_lease *)safemalloc(sizeof *lease);

  /* Copy the lease options. */
  lease->options = packet->options;

  lease->address.len = sizeof(packet->raw->yiaddr);
  memcpy(lease->address.iabuf, &packet->raw->yiaddr, lease->address.len);

  if (config->vendor_space_name)
    {
      i = DHO_VENDOR_ENCAPSULATED_OPTIONS;

      /* See if there was a vendor encapsulation option. */
      oc = lookup_option (&dhcp_option_space, lease->options, i);
      if (oc && config->vendor_space_name)
	{
	  if (oc->data.len)
	    {
	      struct option *opt = find_option(&dhcp_option_space, i);
	      parse_encapsulated_suboptions(packet->options, opt,
					    oc->data.data, oc->data.len,
					    &dhcp_option_space,
					    config->vendor_space_name);
	    }
	}
    }
  else
    i = 0;

  /* Figure out the overload flag. */
  oc = lookup_option (&dhcp_option_space, lease->options,
		      DHO_DHCP_OPTION_OVERLOAD);
  if (oc)
    {
      if (oc->data.len > 0)
	i = oc->data.data [0];
      else
	i = 0;
    } else
    i = 0;

  /* If the server name was filled out, copy it. */
  if (!(i & 2) && packet->raw->sname[0])
    {
      unsigned len;

      /* Don't count on the NUL terminator. */
      for (len = 0; len < DHCP_SNAME_LEN; len++)
	if (!packet->raw->sname[len])
	  break;
      lease->server_name = (char *)safemalloc(len + 1);
      memcpy(lease->server_name, packet->raw->sname, len);
      lease->server_name[len] = 0;
    }

  /* Ditto for the filename. */
  if (!(i & 1) && packet->raw->file[0])
    {
      unsigned len;

      /* Don't count on the NUL terminator. */
      for (len = 0; len < DHCP_FILE_LEN; len++)
	if (!packet->raw->file[len])
	  break;
      lease->filename = (char *)safemalloc(len + 1);
      memcpy(lease->filename, packet->raw->file, len);
      lease->filename[len] = 0;
    }

  return lease;
}	

/* This is called whenever a timer expires for this client state machine.
 * If the timeout requires us to change states, we do so; otherwise we
 * assume that we have to retransmit the current packet, since there's no
 * other cause for a timeout to happen.
 */

void DHCPv4Client::event(const char *evname, int newState, int status)
{
  /* If this timeout triggers a state transition, make the transition. */
  if (newState != state)
    {
      switch(newState)
	{
	case S4_INIT_REBOOT:
	  state_init_reboot();
	  return;

	case S4_INIT_REBOOT_NOT_CONFIGURED:
	  state_init_reboot_not_configured();
	  return;

	case S4_INIT_REBOOT_CONFIGURED:
	  state_init_reboot_configured();
	  return;

	case S4_CONFIRM:
	  state_confirm();
	  return;

	case S4_INIT:
	  state_init();
	  return;

	case S4_INIT_NOT_CONFIGURED:
	  state_init_not_configured();
	  return;

	case S4_INIT_CONFIGURED:
	  state_init_configured();
	  return;

	case S4_SELECTING:
	  state_selecting();
	  return;

	case S4_REQUESTING:
	  state_requesting();
	  return;

	case S4_BOUND:
	  state_bound();
	  return;

	case S4_BOUND_NOT_CONFIGURED:
	  state_bound_not_configured();
	  return;

	case S4_BOUND_CONFIGURED:
	  state_bound_configured();
	  return;

	case S4_RENEWING:
	  state_renewing();
	  return;

	case S4_REBINDING:
	  state_rebinding();
	  return;

	case S4_STOPPED:
	  state_stopped();
	  return;

	case S4_INFORM:
	  state_inform();
	  return;

	case S4_RELEASING:
	  state_releasing();
	  return;

	case S4_UNMANAGED:
	  state_unmanaged();
	  return;
	}
    }

  /* Otherwise, it's triggering a retransmission. */
  send_v4_packet(true);
}

/* Set the destination for the outgoing packet according to the current
 * state.   We always broadcast unless we're in the S4_RENEWING state, so
 * it's pretty easy.
 */
void DHCPv4Client::set_destination()
{
  first_sending = cur_time;
	
  if (STATE_RENEWING(state) || STATE_RELEASING(state))
    {
      struct option_cache *oc = lookup_option (&dhcp_option_space,
					       active->options,
					       DHO_DHCP_SERVER_IDENTIFIER);
      if (oc)
	{
	  if (oc->data.len > 3)
	    memcpy(&destination.sin_addr, oc->data.data, 4);
	}
      else
	destination.sin_addr = sockaddr_broadcast.sin_addr;
    }
  else
    destination.sin_addr = sockaddr_broadcast.sin_addr;

  destination.sin_port = remote_port;
  destination.sin_family = AF_INET;
#ifdef HAVE_SA_LEN
  destination.sin_len = sizeof destination;
#endif
}

/* Send a packet, and possibly set up for retransmission. */

void DHCPv4Client::send_v4_packet(bool retransmit)
{
  unsigned elapsed = (cur_time - first_sending) / 1000000000ULL;

  /* XXX this "exponential backoff" algorithm seems weird and may
   * XXX need rethinking.
   */

  /* Do the exponential backoff... */
  if (cur_time == first_sending)
      interval = config->initial;
  else
    interval += (NANO_SECONDS(random () >> 2) % (2 * interval));

  /* Don't backoff past cutoff. */
  if (interval > config->cutoff)
    interval = ((config->cutoff / 2) + (NANO_SECONDS(random () >> 2) %
					config->cutoff));
  /* Record the number of seconds since we started sending. */
  if (state == S4_REQUESTING)
    packet.secs = secs;
  else
    {
      if (elapsed < 65536)
	packet.secs = htons(elapsed);
      else
	packet.secs = htons(65535);
      secs = elapsed;
    }

  /* Increment the transaction ID. */
  ++xid;
  packet.xid = xid;

  log_info ("%s on %s to %s port %d",
	    packet_type_name,
	    (config->name ? config->name : config->interface->name),
	    inet_ntoa(destination.sin_addr),
	    ntohs(destination.sin_port));

  send_packet(config->interface, &packet, packet_length,
	      (struct sockaddr *)&destination);

  /* Add a timeout, with the state set to the current state. */
  if (retransmit)
    addTimeout(cur_time + interval, state);

  return;
}

/* Set up all the common options to send to the server. */

void DHCPv4Client::make_client_options(struct client_lease *lease,
				       u_int8_t *type,
				       struct option_cache *sid,
				       struct iaddr *rip,
				       u_int32_t *prl,
				       struct option_state **op)
{
  unsigned i;
  struct option_cache *oc;
  struct buffer *bp = (struct buffer *)0;
  struct option *opt;

  *op = new_option_state();

  /* Send the server identifier if provided. */
  if (sid)
    save_option(&dhcp_option_space, *op, sid);

  /* Send the requested address if provided. */
  if (rip)
    {
      opt = find_option(&dhcp_option_space, DHO_DHCP_REQUESTED_ADDRESS);
      requested_address = *rip;
      oc = make_const_option_cache((struct buffer **)0,
				   rip->iabuf, rip->len, opt);
      save_option (&dhcp_option_space, *op, oc);
    }
  else
    {
      requested_address.len = 0;
    }

  opt = find_option(&dhcp_option_space, DHO_DHCP_MESSAGE_TYPE);
  oc = make_const_option_cache((struct buffer **)0, type, 1, opt);
  save_option(&dhcp_option_space, *op, oc);

  if (prl)
    {
      /* Figure out how many parameters were requested. */
      for (i = 0; prl [i]; i++)
	;
      bp = buffer_allocate(i);
      for (i = 0; prl [i]; i++)
	bp->data [i] = prl [i];
      opt = find_option(&dhcp_option_space,
			DHO_DHCP_PARAMETER_REQUEST_LIST);
      oc = make_const_option_cache(&bp, (u_int8_t *)0, i, opt);
      save_option(&dhcp_option_space, *op, oc);
    }

  /* Set up client identifier option according to the method defined
   * in draft-ietf-dhc-3315id-for-dhcpv4.txt.
   */
  /* Figure out how many parameters were requested. */
  bp = buffer_allocate(duid->len + 5);
  bp->data[0] = 255;
  putULong(&bp->data[1], config->interface->index);
  memcpy(&bp->data[5], &duid->data, duid->len);
  opt = find_option(&dhcp_option_space, DHO_DHCP_CLIENT_IDENTIFIER);
  oc = make_const_option_cache(&bp, 0, duid->len + 5, opt);
  save_option (&dhcp_option_space, *op, oc);
}

/* Make a DHCPv4 packet.   If lease is null, state had better be S4_INFORM. */

void DHCPv4Client::make_packet(struct client_lease *lease, u_int8_t type)
{
  struct iaddr *address = 0;
  struct option_cache *oc = 0;
  u_int32_t *requested_options = 0;

  switch(type)
    {
    case DHCPDISCOVER:
      packet_type_name = "DHCPDISCOVER";
      break;
    case DHCPREQUEST:
      packet_type_name = "DHCPREQUEST";
      break;
    case DHCPDECLINE:
      packet_type_name = "DHCPDECLINE";
      break;
    case DHCPINFORM:
      packet_type_name = "DHCPINFORM";
      break;
    case DHCPRELEASE:
      packet_type_name = "DHCPRELEASE";
      break;
    default:
      packet_type_name = "DHCP Unknown Packet Type!";
      break;
    }

  memset (&packet, 0, sizeof (packet));

  /* If we're in REQUESTING or INIT-REBOOT, we need to set the
   * 'requested address' option.
   */
  if (STATE_REQUESTING(state) || STATE_INIT_REBOOT(state))
    address = &lease->address;

  /* If we're in REQUESTING, declining or RELEASING, we need to send the
   * server identifier.
   */
  if (STATE_REQUESTING(state) ||
      STATE_DECLINE(state) || STATE_RELEASING(state))
    oc = lookup_option (&dhcp_option_space, lease->options,
			DHO_DHCP_SERVER_IDENTIFIER);

  /* If we're not declining or releasing, we need to request the options
   * we want.
   */
  if (!(STATE_DECLINE(state) && STATE_RELEASING(state)))
    requested_options = config->requested_options;

  sent_options = 0;
  make_client_options(lease, &type, oc, address, requested_options,
		      &sent_options);

  /* Set up the option buffer... */
  packet_length = cons_options (&packet,
				/* maximum packet size */1500,
				sent_options,
				/* overload */ 0,
				/* terminate */0,
				/* bootpp    */0,
				(struct data_string *)0,
				config->vendor_space_name);

  /* Ensure the packet is long enough. */
  if (packet_length < BOOTP_MIN_LEN)
    packet_length = BOOTP_MIN_LEN;

  packet.op = BOOTREQUEST;
  packet.htype = config->interface->lladdr.hbuf [0];
  packet.hlen = config->interface->lladdr.hlen - 1;
  packet.hops = 0;

  /* If we're in REQUESTING or INIT-REBOOT, we need the server to broadcast
   * its response.   Technically, if we can receive a unicast prior to being
   * configured we don't need to request this; for now we're not addressing
   * that optimization.
   */
  if (STATE_REQUESTING(state) || STATE_INIT_REBOOT(state) || STATE_INIT(state))
    packet.flags = ntohs(BOOTP_BROADCAST);

  /* If we own the address, and we're operating on a lease, put that address
   * in ciaddr.   If we're doing a DHCPINFORM, and we've been configured
   * using DHCP, use the IP address of the active lease.   If we're doing
   * DHCPINFORM and we weren't configured using DHCP, use the first IPv4
   * address on the interface.   Otherwise, we're not entitled to set ciaddr.
   */
  if (STATE_RENEWING(state) ||
      STATE_REBINDING(state) || STATE_RELEASING(state))
      memcpy(&packet.ciaddr, lease->address.iabuf, sizeof packet.ciaddr);
  else if (STATE_INFORM(state) && active)
      memcpy(&packet.ciaddr, active->address.iabuf, sizeof packet.ciaddr);
  else if (STATE_INFORM(state))
    packet.ciaddr = config->interface->ipv4s[0];
  else
    memset (&packet.ciaddr, 0, sizeof packet.ciaddr);

  memset (&packet.yiaddr, 0, sizeof packet.yiaddr);
  memset (&packet.siaddr, 0, sizeof packet.siaddr);

  /* We make be doing a simulation, where we fake giaddr.   In that case,
   * though, we don't fake giaddr in the RENEWING state, because renews
   * are supposed to be unicast, meaning they don't go through the relay
   * agent.
   */
  if (STATE_RENEWING(state) || STATE_RELEASING(state))
    packet.giaddr.s_addr = 0;
  else
    packet.giaddr = giaddr;

  /* Set the hardware address if we have one. */
  if (config->interface->lladdr.hlen > 0)
    memcpy (packet.chaddr, &config->interface->lladdr.hbuf [1],
	    (unsigned)(config->interface->lladdr.hlen - 1));

#ifdef DEBUG_PACKET
  dump_raw ((unsigned char *)&packet, packet_length);
#endif
}

/* Contact the external controller to remove an existing address from the
 * interface and/or to add a new address to the interface.
 */
void DHCPv4Client::interface_configure(enum dhcp_state reportState,
				       const char *oldName,
				       struct client_lease *oldLease,
				       const char *newName,
				       struct client_lease *newLease,
				       enum dhcp_state failState,
				       enum dhcp_state succeedState)
{
  const char *stateName;

  switch(reportState)
    {
    case S4_INIT_REBOOT:
    case S4_INIT_REBOOT_NOT_CONFIGURED:
    case S4_INIT_REBOOT_CONFIGURED:
    case S4_CONFIRM:
      stateName = "INIT_REBOOT";
      break;

    case S4_INIT:
    case S4_INIT_NOT_CONFIGURED:
    case S4_INIT_CONFIGURED:
      stateName = "INIT";
      break;

    case S4_SELECTING:
      stateName = "SELECTING";
      break;

    case S4_REQUESTING:
      stateName = "REQUESTING";
      break;

    case S4_BOUND:
    case S4_BOUND_NOT_CONFIGURED:
    case S4_BOUND_CONFIGURED:
      stateName = "BOUND";
      break;

    case S4_DECLINE:
      stateName = "DECLINE";
      break;

    case S4_RENEWING:
      stateName = "RENEW";
      break;

    case S4_REBINDING:
      stateName = "REBIND";
      break;

    case S4_STOPPED:
      stateName = "STOP";
      break;

    case S4_INFORM:
      stateName = "INFORM";
      break;

    case S4_RELEASING:
      stateName = "RELEASE";
      break;

    case S4_UNMANAGED:
      stateName = "UNMANAGED";
      break;

    default:
      stateName = "!!!ERROR!!!";
      break;
    }

  /* Send the parameters to the external controller. */
  controller->start(config, stateName);

  /* If there's an old lease that might be configured on an interface,
   * mention it to the external controller.
   */
  if (oldLease)
      controller->send_lease(oldName, oldLease, oldLease->options);
  if (newLease)
    controller->send_lease(newName, newLease, newLease->options);

  /* Launch the external controller.   In some cases, this will result in
   * an immediate callback, before this function returns, so the caller needs
   * to take this into account, and we can't do anything here after the
   * controller's finish() call.
   */
  controller->finish(this, failState, succeedState);
}

/* Local Variables:  */
/* mode:C++ */
/* c-file-style:"gnu" */
/* end: */
