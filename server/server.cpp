/* server.cpp
 *
 * Dummy DHCPv6 server.   This isn't a real v6 server, but it serves to test
 * the DHCPv6 client's basic code paths to make sure they work.
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
 */

#ifndef lint
static char ocopyright[] __attribute__((unused)) =
  "$Id: server.cpp,v 1.5 2009/09/19 21:53:28 mellon Exp $ Copyright (c) 2005-2006 Nominum, Inc.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"
#include "version.h"
#include "server/v6server.h"

static char copyright[] = "Copyright 2005-2006 Nominum, Inc.";
static char arr[] = "All rights reserved.";
static char message[] = "Nominum DHCPv6 Test Server";
static char caveat[] = ("Please be aware that this can't be used as "
			"a real DHCP server!");
static char url[] = "For info, please visit http://www.nominum.com/";

u_int16_t local_port_dhcpv6 = 0;
u_int16_t remote_port_dhcpv6 = 0;

static void usage(void);

int
main(int argc, char **argv)
{
  int i;
  struct servent *ent;
  struct interface_info *ip;
  unsigned seed;
  int unicast_only = 0;
  duid_t *server_duid;


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

  /* Discover all the network interfaces. */
  discover_interfaces();

  for (i = 1; i < argc; i++)
    {
      if (!strcmp (argv [i], "-p"))
	{
	  if (++i == argc)
	    usage();
	  local_port_dhcpv6 = htons (atoi (argv [i]));
	  log_debug ("binding to user-specified dhcpv6 port %d",
		     ntohs (local_port_dhcpv6));
	}
      else if (!strcmp (argv [i], "-u"))
	{
	  unicast_only = 1;
	}
      else if (!strcmp (argv [i], "--version"))
	{
	  log_info ("nom-dhcp-dummy-%s", DHCP_VERSION);
	  exit (0);
	}
      else if (argv [i][0] == '-')
	{
	  usage();
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

  log_perror = 1;
  log_syslog = 0;

  log_info("%s %s", message, DHCP_VERSION);
  log_info("%s", caveat);
  log_info("%s", copyright);
  log_info("%s", arr);
  log_info("%s", url);
  log_info("%s", "");


  /* Default to the DHCP/BOOTP port. */
  if (!local_port_dhcpv6)
    {
      ent = getservbyname ("dhcps6", "udp");
      if (!ent || !ent->s_port)
	local_port_dhcpv6 = htons (547);
      else
	local_port_dhcpv6 = ent->s_port;
      printf("port is %d\n", ntohs(local_port_dhcpv6));
#ifndef __CYGWIN32__
      endservent ();
#endif
    }

  remote_port_dhcpv6 = htons(ntohs(local_port_dhcpv6) - 1);
  
  local_port = 68; remote_port = 67;

  /* Get the current time... */
  fetch_time();

  /* Set up the initial dhcp option universe. */
  initialize_common_option_spaces ();

  /* Generate a server DUID.   For now, generate from scratch every
   * time since we don't need it to be persistent - maybe when the
   * client gets smarter we will want to make it persistent, though.
   *
   * We scan the list of interfaces looking for one that has a link-
   * layer address of some sort, and we just take the first one.
   * We combine that with the system clock value to produce an identifier
   * that is very unlikely to be duplicated on another node.
   */
  for (ip = interfaces; ip; ip = ip -> next)
    {
      if (ip->lladdr.hlen && strncmp(ip->name, "vmnet", 5))
	break;
    }

  /* No interfaces with a link-layer identifier? */
  if (!ip)
    log_fatal("Can't generate DUID: no interfaces have "
	      "link-layer addresses.");
  server_duid = (duid_t *)safemalloc(sizeof (u_int32_t) +
				     ip->lladdr.hlen - 1 + 8);
  server_duid->len = ip->lladdr.hlen - 1 + 8;
  server_duid->data.llt.type = htons(DUID_LLT);
  server_duid->data.llt.time = htonl(cur_time);
  server_duid->data.llt.hardware_type =
    htons((int)ip->lladdr.hbuf[0]);
  memcpy(server_duid->data.llt.lladdr, &ip->lladdr.hbuf[1],
	 ip->lladdr.hlen - 1);
  log_info("Generated DUID %s from %s",
	   print_hex_1(server_duid->len,
		       (unsigned char *)&server_duid->data, 80),
	   ip->name);

  /* Make up a seed for the random number generator from current
     time plus the sum of the last four bytes of each
     interface's hardware address interpreted as an integer.
     Not much entropy, but we're booting, so we're not likely to
     find anything better. */
  seed = 0;
  for (ip = interfaces; ip; ip = ip->next)
    {
      int junk;
      memcpy (&junk,
	      &ip->lladdr.hbuf [ip->lladdr.hlen - sizeof seed], sizeof seed);
      seed += junk;
    }
  srandom (seed + cur_time);

  /* Open the network socket(s). */
  dhcpv6_socket_setup();

  /* If we haven't been asked to only listen for unicast packets,
   * bind to both dhcp multicast groups.
   */
  if (!unicast_only)
    {
      for (ip = interfaces; ip; ip = ip->next)
	{
	  if (ip->requested && ip->v6configured)
	    {
	      dhcpv6_multicast_relay_join(ip);
	      dhcpv6_multicast_server_join(ip);
	    }
	}
    }

  /* Set up listeners on all the interfaces we're covering. */
  for (ip = interfaces; ip; ip = ip->next)
    {
      if (ip->requested)
	ip->v6listener = new DHCPv6Server(ip, server_duid);
    }			

  /* Start dispatching packets and timeouts... */
  dispatch();

  /*NOTREACHED*/
  return 0;
}

static void usage()
{
  log_info ("%s %s", message, DHCP_VERSION);
  log_info ("%s", caveat);
  log_info ("%s", copyright);
  log_info ("%s", arr);
  log_info ("%s", url);

  log_fatal("Usage: dhcp-server [-p <port>] [-u] [<interface> ...]");
}

/* Local Variables:  */
/* mode:C++ */
/* c-file-style:"gnu" */
/* end: */
