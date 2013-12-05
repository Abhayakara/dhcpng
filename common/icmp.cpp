/* icmp.cpp

   ICMP Protocol engine - for sending out pings and receiving
   responses. */

/*
 * Copyright (c) 1996-2002 Internet Software Consortium.
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
static char copyright[] __attribute__((unused)) =
"$Id: icmp.cpp,v 1.2 2006/05/12 21:51:35 mellon Exp $ Copyright (c) 1996-2002 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"
#include "netinet/ip.h"
#include "netinet/ip_icmp.h"

struct icmp_state *icmp_state;
static int no_icmp;

/* Initialize the ICMP protocol. */

void icmp_startup (int routep,
		   void (*handler) PROTO ((struct iaddr, u_int8_t *, int)))
{
	struct protoent *proto;
	int protocol = 1;
	int state;
	isc_result_t result;

	icmp_state = (struct icmp_state *)safemalloc(sizeof *icmp_state);
	icmp_state->icmp_handler = handler;

	/* Get the protocol number (should be 1). */
	proto = getprotobyname ("icmp");
	if (proto)
		protocol = proto -> p_proto;
	
	/* Get a raw socket for the ICMP protocol. */
	icmp_state -> socket = socket (AF_INET, SOCK_RAW, protocol);
	if (icmp_state -> socket < 0) {
		no_icmp = 1;
		log_error ("unable to create icmp socket: %m");
		return;
	}

#if defined (HAVE_SETFD)
	if (fcntl (icmp_state -> socket, F_SETFD, 1) < 0)
		log_error ("Can't set close-on-exec on icmp: %m");
#endif

	/* Make sure it does routing... */
	state = 0;
	if (setsockopt (icmp_state -> socket, SOL_SOCKET, SO_DONTROUTE,
			(char *)&state, sizeof state) < 0)
		log_fatal ("Can't disable SO_DONTROUTE on ICMP: %m");
	
	result = register_io_object((void *)icmp_state,
				    icmp_readsocket, 0, icmp_echoreply, 0, 0);
	if (result != ISC_R_SUCCESS)
		log_fatal ("Can't register icmp handle: %s",
			   isc_result_totext (result));
}

int icmp_readsocket(void *v)
{
	struct icmp_state *state = (struct icmp_state *)v;
	return state->socket;
}

int icmp_echorequest(struct iaddr *addr)
{
	struct sockaddr_in to;
	struct icmp icmp;
	int status;

	if (no_icmp)
		return 1;
	if (!icmp_state)
		log_fatal ("ICMP protocol used before initialization.");

	memset (&to, 0, sizeof(to));
#ifdef HAVE_SA_LEN
	to.sin_len = sizeof to;
#endif
	to.sin_family = AF_INET;
	to.sin_port = 0; /* unused. */
	memcpy (&to.sin_addr, addr -> iabuf, sizeof to.sin_addr); /* XXX */

	icmp.icmp_type = ICMP_ECHO;
	icmp.icmp_code = 0;
	icmp.icmp_cksum = 0;
	icmp.icmp_seq = 0;
#ifdef PTRSIZE_64BIT
	icmp.icmp_id = (((u_int32_t)(u_int64_t)addr) ^
  			(u_int32_t)(((u_int64_t)addr) >> 32));
#else
	icmp.icmp_id = (u_int32_t)addr;
#endif
	memset (&icmp.icmp_dun, 0, sizeof icmp.icmp_dun);

	icmp.icmp_cksum = wrapsum (checksum ((unsigned char *)&icmp,
					     sizeof icmp, 0));

	/* Send the ICMP packet... */
	status = sendto (icmp_state->socket,
			 (char *)&icmp, sizeof icmp, 0,
			 (struct sockaddr *)&to, sizeof to);
	if (status < 0)
		log_error ("icmp_echorequest %s: %m", inet_ntoa(to.sin_addr));
	
	if (status != sizeof icmp)
		return 0;
	return 1;
}

isc_result_t icmp_echoreply (void *v)
{
	struct icmp *icfrom;
	struct ip *ip;
	struct sockaddr_in from;
	u_int8_t icbuf [1500];
	int status;
	socklen_t sl;
	unsigned hlen, len;
	struct iaddr ia;
	struct icmp_state *state = (struct icmp_state *)v;

	sl = sizeof from;
	status = recvfrom (state -> socket, (char *)icbuf, sizeof icbuf, 0,
			  (struct sockaddr *)&from, &sl);
	if (status < 0) {
		log_error ("icmp_echoreply: %m");
		return ISC_R_UNEXPECTED;
	}

	/* Find the IP header length... */
	ip = (struct ip *)icbuf;
	hlen = IP_HL (ip);

	/* Short packet? */
	if ((unsigned)status < hlen + (sizeof *icfrom)) {
		return ISC_R_SUCCESS;
	}

	len = status - hlen;
	icfrom = (struct icmp *)(icbuf + hlen);

	/* Silently discard ICMP packets that aren't echoreplies. */
	if (icfrom -> icmp_type != ICMP_ECHOREPLY) {
		return ISC_R_SUCCESS;
	}

	/* If we were given a second-stage handler, call it. */
	if (state -> icmp_handler) {
		memcpy (ia.iabuf, &from.sin_addr, sizeof from.sin_addr);
		ia.len = sizeof from.sin_addr;

		(*state -> icmp_handler) (ia, icbuf, len);
	}
	return ISC_R_SUCCESS;
}
