/* v6server.h
 *
 * Definitions for the DHCPv6Server class.
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

#ifndef DHCPP_V6SERVER_H
#define DHCPP_V6SERVER_H

#include "dhc++/v6listener.h"

class DHCPv6Server: public DHCPv6Listener
{
public:
  DHCPv6Server(struct interface_info *ip, duid_t *duid);

protected:
  void information_request(struct sockaddr_in6 *from,
			   unsigned char *contents, ssize_t length);
  void solicit(struct sockaddr_in6 *from,
	       unsigned char *contents, ssize_t length);
  void request(struct sockaddr_in6 *from,
	       unsigned char *contents, ssize_t length);
  void renew(struct sockaddr_in6 *from,
	     unsigned char *contents, ssize_t length);
  void rebind(struct sockaddr_in6 *from,
	      unsigned char *contents, ssize_t length);
  void confirm(struct sockaddr_in6 *from,
	       unsigned char *contents, ssize_t length);
private:
  static struct dhcpv6_client_context *client_contexts;
  struct interface_info *interface;
  duid_t *server_duid;

  void confreq(struct sockaddr_in6 *from,
	       unsigned char *inpacket,
	       ssize_t len, const char *name);
};

#endif

/* Local Variables:  */
/* mode:c++ */
/* c-file-style:"gnu" */
/* end: */
