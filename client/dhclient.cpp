/* dhclient.cpp
 * 
 * Main control code for DHCP Client.   Most of the protocol-specific stuff
 * is in dhcpv4.c and dhcpv6.c.
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

/* Addendum: this version of dhclient represents a *major* rehack of the
 * client.   Things are a lot different - we haven't just strapped in
 * a DHCPv6 state machine.
 *
 * Some of the major differences:
 *
 *  - The old client will operate without being configured with a DHCP
 *    client identifier.
 *  + The new client will not operate until it has been configured with a
 *    DHCP client identifier over the d-bus.   Generally speaking, the DHCP
 *    client should be configured with an identifier that is acceptable for
 *    DHCPv4 and DHCPv6; however, in cases where the DHCPv4 identifier must
 *    be shared with a boot PROM whose identifier can't be configured, the
 *    DHCPv4 client can be configured with a different identifier.
 *
 *  - In older versions of dhclient, the client just goes looking for
 *    interfaces and configures anything that looks like it ought to
 *    be configured.   It winds up stepping on a lot of stuff.
 *  + In this version, the client only tries to do the DHCPv4 protocol
 *    on interfaces when specifically requested to do so via the d-bus.
 *
 *  + The only way that the DHCPv6 client will try to configure an
 *    interface is if it is directed to do so over the d-bus.   This is
 *    because in DHCPv6, we don't do any kind of autoconfiguration until
 *    we see a router advertisement message, and then we autoconfigure
 *    based on the directions in that message.   So in order for a DHCPv6
 *    protocol to start up on any given interface, 
 *
 *  - Older versions of dhclient have a configuration file and a lease
 *    database store.
 *  + This version has neither.   It does nothing until directed to do so,
 *    either on the command line or over the d-bus.   If you want it to do
 *    something special, you tell it to do something special over the
 *    d-bus.
 *
 *  + This version of the client does not attempt to set up anything
 *    based on the options it receives.   It simply announces the values
 *    of those options on the d-bus, and trusts that if something needs
 *    to happen as a result of those options being set, something listening
 *    on the d-bus will make it happen.
 *
 *  - Previous versions of the client configured the network using a shell
 *    script.
 *  + This version of the client initially configures non-configured network
 *    interfaces to a usable state using ioctls.   It does no other
 *    configuration.   If a network interface already has an IP address,
 *    the DHCP client will do nothing.
 *  + The DHCP client can be directed to treat the single non-link-local IPv4
 *    address on an interface as a DHCP-acquired address with an indefinite
 *    lease but a rebinding time of two hours; in this case, it will enter
 *    the REBINDING state and attempt to reconfirm the address indefinitely.
 *    Until such time as a response is heard from a DHCP server, nothing
 *    having to do with that IP address will be announced on the d-bus;
 *    effectively, the address is treated as manually configured until
 *    such time as the DHCP server is found.
 *  + No such provision is made for DHCPv6.   If you netbooted with DHCPv6,
 *    you need to provide lease information to the DHCP client over the
 *    d-bus on startup, and then it can take over doing DHCPv6 for you.
 *
 * At the time of this writing, some of the above bullet points are not
 * yet implemented, but generally speaking the stuff that's supposed to be
 * gone is already gone.   The only exception is the client identifier,
 * and this is a very temporary exception.
 */

#ifndef lint
static char ocopyright[] __attribute__((unused)) =
  "$Id: dhclient.cpp,v 1.17 2010/01/14 20:27:00 mellon Exp $ Copyright (c) 2005-2006 Nominum, Inc.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"
#include "version.h"
#include "client/v4client.h"
#include "client/v6client.h"
#include "client/controller.h"
#include "client/dbus.h"
#include "client/script.h"
#include "client/client.h"

const char *path_dhclient_pid = _PATH_DHCLIENT_PID;
const char *path_dhclient_duid = _PATH_DHCLIENT_DUID;

int interfaces_requested = 0;

struct iaddr iaddr_broadcast = { 4, { 255, 255, 255, 255 } };
struct iaddr iaddr_any = { 4, { 0, 0, 0, 0 } };
struct in_addr inaddr_any;
struct sockaddr_in sockaddr_broadcast;
struct sockaddr_in6 sockaddr_in6_all_agents_and_servers;
struct sockaddr *sockaddr_all_agents_and_servers =
  (struct sockaddr *)&sockaddr_in6_all_agents_and_servers;
struct in_addr giaddr;
struct iaddr iaddr_all_agents_and_servers;

struct client_config top_level_config;

u_int32_t default_requested_options [] = {
  DHO_SUBNET_MASK,
  DHO_BROADCAST_ADDRESS,
  DHO_TIME_OFFSET,
  DHO_ROUTERS,
  DHO_DOMAIN_NAME,
  DHO_DOMAIN_NAME_SERVERS,
  DHO_HOST_NAME,
  0
};

u_int32_t default_dhcpv6_requested_options [] = {
  DHCPV6_IA_NA,
  DHCPV6_SERVER_IDENTIFIER,
  DHCPV6_PREFERENCE,
  DHCPV6_STATUS_CODE,
  DHCPV6_DOMAIN_NAME_SERVERS,
  DHCPV6_DOMAIN_SEARCH_LIST,
  DHCPV6_INFORMATION_REFRESH_TIME,
  DHCPV6_FQDN,
  0
};

static char copyright[] = "Copyright 2005-2006 Nominum, Inc.\nCopyright 1995-2002 Internet Software Consortium.";
static char arr[] = "All rights reserved.";
static char message[] = "Nominum DHCP Client";
static char freeSoftware[] =
  ("The Nominum DHCP Client comes with ABSOLUTELY NO WARRANTY.\n"
   "This is free software, and you are welcome to redistribute it\n"
   "under certain conditions; see the file COPYING, included with the\n"
   "Nominum DHCP Client for details.\n");
static char url[] = "For info, please visit http://www.nominum.com/";

u_int16_t local_port_dhcpv6 = 0;
u_int16_t remote_port_dhcpv6 = 0;
int no_daemon = 0;
struct string_list *client_env = NULL;
int client_env_count = 0;
int onetry = 0;
int quiet = 0;
int nowait = 0;

DHCPClientController *v4Controller;
DHCPClientController *v6Controller;

static void usage(void);
static void go_daemon(void);
static void write_client_pid_file(void);

int
main(int argc, char **argv)
{
  int i, j;
  struct servent *ent;
  struct interface_info *ip;
  unsigned seed;
  char *server = (char *)0;
  char *v6_server = (char *)0;
  char *relay = (char *)0;
  int release_mode = 0;
  int persist = 0;
  int no_dhclient_pid = 0;
  int no_dhclient_duid = 0;
  char *s;
  int do_dhcpinform = 0;
  struct client_config *config;
  int do_dhcpv4 = 0;
  int do_dhcpv6 = 0;
  char *v4script = 0;
  char *v6script = 0;
  duid_t *duid;

  /* Make sure we have stdin, stdout and stderr. */
  i = open ("/dev/null", O_RDWR);
  if (i == 0)
    i = open ("/dev/null", O_RDWR);
  if (i == 1)
    {
      i = open ("/dev/null", O_RDWR);
      log_perror = 0; /* No sense logging to /dev/null. */
    }
  else if (i != -1)
    close (i);

#ifdef SYSLOG_4_2
  openlog ("dhclient", LOG_NDELAY);
  log_priority = LOG_DAEMON;
#else
  openlog ("dhclient", LOG_NDELAY, LOG_DAEMON);
#endif

#if !defined(DEBUG) && !defined(SYSLOG_4_2)
  setlogmask(LOG_UPTO (LOG_INFO));
#endif	

  /* Discover all the network interfaces. */
  discover_interfaces();

  for (i = 1; i < argc; i++)
    {
      if (!strcmp (argv [i], "-r"))
	{
	  release_mode = 1;
	  no_daemon = 1;
	}
      else if (!strcmp (argv [i], "-4"))
	{
	  do_dhcpv4 = 1;
	}
      else if (!strcmp (argv [i], "-6"))
	{
	  do_dhcpv6 = 1;
	}
      else if (!strcmp (argv [i], "-p"))
	{
	  if (++i == argc)
	    usage();
	  local_port = htons(atoi(argv[i]));
	  log_debug("binding to user-specified dhcpv4 port %d",
		    ntohs(local_port));
	}
      else if (!strcmp (argv [i], "-P"))
	{
	  if (++i == argc)
	    usage();
	  local_port_dhcpv6 = htons(atoi(argv[i]));
	  log_debug ("binding to user-specified dhcpv6 port %d",
		     ntohs(local_port_dhcpv6));
	}
      else if (!strcmp (argv [i], "-d"))
	{
	  no_daemon = 1;
	}
      else if (!strcmp (argv [i], "-pf"))
	{
	  if (++i == argc)
	    usage ();
	  path_dhclient_pid = argv [i];
	  no_dhclient_pid = 1;
	}
      else if (!strcmp (argv [i], "-df"))
	{
	  if (++i == argc)
	    usage ();
	  path_dhclient_duid = argv [i];
	  no_dhclient_duid = 1;
	}
      else if (!strcmp (argv [i], "-q"))
	{
	  quiet = 1;
	  quiet_interface_discovery = 1;
	}
      else if (!strcmp (argv [i], "-s"))
	{
	  if (++i == argc)
	    usage ();
	  server = argv [i];
	}
      else if (!strcmp (argv [i], "-S"))
	{
	  if (++i == argc)
	    usage ();
	  v6_server = argv [i];
	}
      else if (!strcmp (argv [i], "-g"))
	{
	  if (++i == argc)
	    usage ();
	  relay = argv [i];
	}
      else if (!strcmp (argv [i], "-nw"))
	{
	  nowait = 1;
	}
      else if (!strcmp (argv [i], "-i"))
	{
	  do_dhcpinform = 1;
	  no_daemon = 1;
	}
      else if (!strcmp (argv [i], "-n"))
	{
	  /* do not start up any interfaces */
	  interfaces_requested = 1;
	}
      else if (!strcmp (argv [i], "-w"))
	{
	  /* do not exit if there are no broadcast interfaces. */
	  persist = 1;
	}
      else if (!strcmp (argv [i], "-e"))
	{
	  struct string_list *tmp;
	  if (++i == argc)
	    usage ();
	  tmp = (struct string_list *)safemalloc(strlen (argv [i]) +
						 sizeof *tmp);
	  strcpy (tmp->string, argv [i]);
	  tmp->next = client_env;
	  client_env = tmp;
	  client_env_count++;
	}
      else if (!strcmp (argv [i], "--v4script"))
	{
	  if (++i == argc)
	    usage();
	  v4script = argv[i];
	}
      else if (!strcmp (argv [i], "--v6script"))
	{
	  if (++i == argc)
	    usage();
	  v6script = argv[i];
	}
      else if (!strcmp (argv [i], "--version"))
	{
	  log_info ("nom-dhclient-%s", DHCP_VERSION);
	  exit (0);
	}
      else if (argv [i][0] == '-')
	{
	  usage ();
	}
      else
	{
	  struct interface_info *tmp;

	  for (tmp = interfaces; tmp; tmp = tmp->next)
	    if (!strcmp(tmp->name, argv[i]))
	      break;
	  if (!tmp)
	    log_error("Interface %s does not exist.\n",
		      argv [i]);
	  else
	    tmp->requested = 1;
	}
    }

  /* XXX Take this out later. */
  /* Right now there's no way for the user's agent to trigger a
   * client state machine, so we always trigger one for every interface
   * that was requested, and unless a specific protocol was requested,
   * we do both.   When the netconf glue is done, all this should go
   * away.
   */
  if (!do_dhcpv4 && !do_dhcpv6)
    do_dhcpv4 = do_dhcpv6 = 1;

  limited_broadcast.s_addr = INADDR_BROADCAST;
	
  /* If pid file and/or duid file weren't specified on command line,
   * allow them to be specified in the environment.
   */
  if (!no_dhclient_pid && (s = getenv ("PATH_DHCLIENT_PID")))
    {
      path_dhclient_pid = s;
    }
  if (!no_dhclient_duid && (s = getenv ("PATH_DHCLIENT_DUID")))
    {
      path_dhclient_duid = s;
    }

  if (!quiet)
    {
      log_info ("%s %s", message, DHCP_VERSION);
      log_info ("%s", copyright);
      log_info ("%s", arr);
      log_info ("%s", freeSoftware);
      log_info ("%s", url);
      log_info ("%s", "");
    } else
    log_perror = 0;

  /* If we're given a relay agent address to insert, for testing
     purposes, figure out what it is. */
  if (relay)
    {
      if (!inet_aton (relay, &giaddr))
	{
	  struct hostent *he;
	  he = gethostbyname (relay);
	  if (he)
	    {
	      memcpy (&giaddr, he->h_addr_list [0],
		      sizeof giaddr);
	    }
	  else
	    {
	      log_fatal ("%s: no such host", relay);
	    }
	}
    }

  /* Default to the DHCP/BOOTP port. */
  if (!local_port)
    {
      if (relay && giaddr.s_addr != htonl (INADDR_LOOPBACK))
	{
	  local_port = htons (67);
	}
      else
	{
	  ent = getservbyname ("dhcpc", "udp");
	  if (!ent)
	    local_port = htons (68);
	  else
	    local_port = ent->s_port;
	  printf("port is %d\n", ntohs(local_port));
	  endservent ();
	}
    }

  /* Default to the DHCPv6 port. */
  if (!local_port_dhcpv6)
    {
      ent = getservbyname ("dhcpc6", "udp");
      if (!ent || !ent->s_port)
	local_port_dhcpv6 = htons (546);
      else
	local_port_dhcpv6 = ent->s_port;
      printf("dhcpv6 port is %d\n", ntohs(local_port_dhcpv6));
      endservent ();
    }
  remote_port_dhcpv6 = htons(ntohs(local_port_dhcpv6) + 1);

  /* If we're faking a relay agent, and we're not using loopback,
     use the server port, not the client port. */
  if (relay && giaddr.s_addr != htonl (INADDR_LOOPBACK))
    {
      local_port = htons (ntohs (local_port) - 1);
      remote_port = local_port;
    }
  else
    remote_port = htons (ntohs (local_port) - 1);	/* XXX */
  
  /* Get the current time... */
  fetch_time();

  sockaddr_broadcast.sin_family = AF_INET;
  sockaddr_broadcast.sin_port = remote_port;
  if (server)
    {
      if (!inet_aton (server, &sockaddr_broadcast.sin_addr))
	{
	  struct hostent *he;
	  he = gethostbyname (server);
	  if (he)
	    {
	      memcpy (&sockaddr_broadcast.sin_addr,
		      he->h_addr_list [0],
		      sizeof sockaddr_broadcast.sin_addr);
	    } else
	    sockaddr_broadcast.sin_addr.s_addr = INADDR_BROADCAST;
	}
    }
  else
    {
      sockaddr_broadcast.sin_addr.s_addr = INADDR_BROADCAST;
    }

  /* We normally send all packets to the all_agents_and_servers
   * multicast address.   However, for debugging, we may want to
   * unicast to a specific IPv6 address.   We may also unicast
   * to the server if it requested us to do so, but that's handled
   * elsewhere.
   */
  sockaddr_in6_all_agents_and_servers.sin6_family = AF_INET6;
  sockaddr_in6_all_agents_and_servers.sin6_port = remote_port;
  inet_pton(AF_INET6, v6_server ? v6_server : "FF02::1:2",
	    &sockaddr_in6_all_agents_and_servers.sin6_addr);

  /* Set this up as an iaddr as well as a sockaddr_in6. */
  iaddr_all_agents_and_servers.len = 16;
  memcpy(iaddr_all_agents_and_servers.iabuf,
	 &sockaddr_in6_all_agents_and_servers.sin6_addr, 16);

  inaddr_any.s_addr = INADDR_ANY;

  /* Parse the dhclient.conf file. */
  /* Set up the initial dhcp option universe. */
  initialize_common_option_spaces ();

  /* Initialize the top level client configuration. */
  memset (&top_level_config, 0, sizeof top_level_config);

  /* Set some defaults... */
  top_level_config.select = NANO_SECONDS(1);
  top_level_config.reboot = NANO_SECONDS(10);
  top_level_config.retry = NANO_SECONDS(300);
  top_level_config.cutoff = NANO_SECONDS(15);
  top_level_config.initial = NANO_SECONDS(3);
  top_level_config.bootp_policy = P_ACCEPT;
  top_level_config.requested_options = default_requested_options;
  top_level_config.dhcpv6_requested_options =
    default_dhcpv6_requested_options;

  /* Get the DHCP Unique Identifier.   First we try to read it out of
   * a file that's in a well known location.   That can fail either
   * because there's no such file or because the DUID's size is
   * implausible, or because there's a surprising I/O error reading
   * or seeking the file.
   */
  duid = 0;
  i = open(path_dhclient_duid, O_RDONLY);
  if (i >= 0)
    {
      off_t len = lseek(i, 0, SEEK_END);
      if (len > 10 && len < 64)
	{
	  lseek(i, 0, SEEK_SET);
	  duid = (duid_t *)safemalloc(sizeof (u_int32_t) + len);
	  duid->len = (u_int32_t)len;
	  j = read(i, &duid->data, len);
	  if (j != len)
	    duid = 0;
	  else
	    log_info("Loaded DUID %s from %s",
		     print_hex_1(duid->len, (unsigned char *)&duid->data, 80),
		     path_dhclient_duid);
	}
      close(i);
    }

  /* Now if we didn't get the DUID out of a file for some reason, it's
   * time to generate one from scratch.   Right now, the only type of
   * DUID we will generate is the DUID_LLT type.
   *
   * We scan the list of interfaces looking for one that has a link-
   * layer address of some sort, and we just take the first one.
   * We combine that with the system clock value to produce an identifier
   * that is very unlikely to be duplicated on another node.
   */
  if (!duid)
    {
      for (ip = interfaces; ip; ip = ip -> next)
	if (ip->lladdr.hlen &&
	    strncmp(ip->name, "vmnet", 5) && strncmp(ip->name, "lo", 2))
	  break;

      /* No interfaces with a link-layer identifier? */
      if (!ip)
	log_fatal("Can't generate DUID: no interfaces have "
		  "link-layer addresses.");

      duid = (duid_t *)safemalloc(sizeof (u_int32_t) +
				  ip->lladdr.hlen - 1 + 12);
      duid->len = ip->lladdr.hlen - 1 + 8;
      duid->data.llt.type = htons(DUID_LLT);
      duid->data.llt.time = htonl(cur_time);
      duid->data.llt.hardware_type =
	htons((int)ip->lladdr.hbuf[0]);
      memcpy(duid->data.llt.lladdr, &ip->lladdr.hbuf[1],
	     ip->lladdr.hlen - 1);
      log_info("Generated DUID %s from %s",
	       print_hex_1(duid->len,
			   (unsigned char *)&duid->data, 80), ip->name);

      /* Now remember the DUID for the next run. */
      i = open(path_dhclient_duid, O_WRONLY | O_CREAT, 0600);
      if (i >= 0)
	{
	  j = write(i, &duid->data, duid->len);
	  if (j != (int)duid->len)
	    {
	      if (j < 0)
		log_error("unable to store DUID: %m");
	      else
		log_error("short write when storing DUID.");
	      unlink(path_dhclient_duid);
	    }
	  close(i);
	}
      else
	{
	  log_error("Unable to create DUID file: %m");
	}
    }

  /* Make up a seed for the random number generator from current
   * time plus the sum of the last four bytes of each
   * interface's hardware address interpreted as an integer.
   *
   * No entropy, but we're booting, so we're not likely to
   * find anything better, and the main thing is to keep our
   * numbers separate from other clients that may also be booting.
   *
   * There's a risk of guessing initial xids on startup, but
   * I'm not sure how it would be useful as an attack; if it were
   * useful, then it might be better to stir in some entropy here.
   */
  seed = 0;
  for (ip = interfaces; ip; ip = ip->next)
    {
      int junk;
      memcpy(&junk,
	     &ip->lladdr.hbuf[ip->lladdr.hlen - sizeof seed], sizeof seed);
      seed += junk;
    }
  srandom(seed + cur_time);

  config = 0;

  /* Set up the controller - a script if one is specified, otherwise
   * a connection to the dbus.
   */
  if (v4script)
    v4Controller = new Script(v4script);
  else
    {
#if defined(HAVE_DBUS)
      v4Controller = new DBus("v4");
#else
      if (do_dhcpv4)
	log_fatal("no DHCPv4 client script specified.");
#endif
    }

  /* Allow different controllers for IPv4 and IPv6. */
  if (v6script)
    v6Controller = new Script(v6script);
  else
    {
#if defined(HAVE_DBUS)
      v6Controller = new DBus("v6");
#else
      if (do_dhcpv6)
	log_fatal("no DHCPv6 client script specified.");
#endif
    }

  for (ip = interfaces; ip; ip = ip->next)
    {
      if (!ip->requested)
	{
	  if_statusprint(ip, "Not configuring ");
	  continue;
	}
      if_statusprint(ip, "Configuring     ");

      if (!ip->v4listener)
	ip->v4listener = new DHCPv4Client(ip, v4Controller,
					  (u_int8_t *)&duid->data,
					  (int)duid->len);

      if (!ip->v6listener)
	ip->v6listener = new DHCPv6Client(ip, v6Controller,
					  (u_int8_t *)&duid->data,
					  (int)duid->len);
    }

  if (!release_mode && !do_dhcpinform)
    {
      /* Call the script with the list of interfaces. */
      for (ip = interfaces; ip; ip = ip->next)
	{
	  if (!ip->v4listener)
	    continue;
	  log_info("need to initialize %s", ip->name);
	}
    }

  /* Open the network socket(s). */
  if (do_dhcpv6)
    dhcpv6_socket_setup();
  if (do_dhcpv4)
    dhcpv4_socket_setup();

  /* XXX Delete this whole section.   Let the client be started
   * XXX by a dbus message.
   */

  /* Start a configuration state machine for each interface. */
  for (ip = interfaces; ip; ip = ip->next)
    {
      if (!ip->requested)
	continue;

      if (do_dhcpv4)
	{
	  if (do_dhcpinform)
	    {
	      ((DHCPv4Client *)(ip->v4listener))->state_inform();
	      continue;
	    }

	  ((DHCPv4Client *)(ip->v4listener))->state_startup();
	}

      if (do_dhcpv6)
	{
	  if (do_dhcpinform)
	    {
	      ((DHCPv6Client *)(ip->v6listener))->state_inform();
	      continue;
	    }

	  ((DHCPv6Client *)(ip->v6listener))->state_soliciting();
	}

    }

  if (release_mode)
    return 0;

  /* Daemonize if we're going to; otherwise, write out a pid file. */
  if (!no_daemon)
    go_daemon();
  else
    write_client_pid_file();

  /* Start dispatching packets and timeouts... */
  dispatch();

  /*NOTREACHED*/
  return 0;
}

static void usage()
{
  log_info("%s %s", message, DHCP_VERSION);
  log_info("%s", copyright);
  log_info("%s", arr);
  log_info("%s", freeSoftware);
  log_info("%s", url);

  log_error("Usage: dhcp-client [-1dqr] [-nw] [-p <port>] "
	    "[-s server]");
  log_error("                [-cf config-file] [-lf lease-file] "
	    "[-pf pid-file] [-e VAR=val]");
  log_fatal("                [-sf script-file] [interface] "
	    "[-S v6-server]");
}

static void go_daemon()
{
  static int state = 0;
  int pid;
  int i;

  /* Don't become a daemon if the user requested otherwise. */
  if (no_daemon)
    {
      write_client_pid_file();
      return;
    }

  /* Only do it once. */
  if (state)
    return;
  state = 1;

  /* Stop logging to stderr... */
  log_perror = 0;

  /* Become a daemon... */
  if ((pid = fork()) < 0)
    log_fatal ("Can't fork daemon: %m");
  else if (pid)
    exit(0);
  /* Become session leader and get pid... */
  pid = setsid();

  /* Close standard I/O descriptors. */
  close(0);
  close(1);
  close(2);

  /* Reopen them on /dev/null. */
  i = open("/dev/null", O_RDWR);
  if (i == 0)
    i = open("/dev/null", O_RDWR);
  if (i == 1)
    {
      i = open("/dev/null", O_RDWR);
      log_perror = 0; /* No sense logging to /dev/null. */
    }
  else if (i != -1)
    close(i);

  write_client_pid_file();
}

static void write_client_pid_file ()
{
  FILE *pf;
  int pfdesc;

  pfdesc = open(path_dhclient_pid, O_CREAT | O_TRUNC | O_WRONLY, 0644);

  if (pfdesc < 0)
    {
      log_error("Can't create %s: %m", path_dhclient_pid);
      return;
    }

  pf = fdopen(pfdesc, "w");
  if (!pf)
    log_error("Can't fdopen %s: %m", path_dhclient_pid);
  else
    {
      fprintf(pf, "%ld\n", (long)getpid ());
      fclose(pf);
    }
}

/* Local Variables:  */
/* mode:C++ */
/* c-file-style:"gnu" */
/* end: */
