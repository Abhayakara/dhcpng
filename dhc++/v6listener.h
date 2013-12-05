/* v6listener.h
 *
 * Definitions for the DHCPv6Listener class.
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

#ifndef DHCPP_V6LISTENER_H
#define DHCPP_V6LISTENER_H

class DHCPv6Listener
{
public:
  virtual ~DHCPv6Listener();
  isc_result_t got_packet(dhcpv6_response *response, struct sockaddr_in6 *from,
			  const unsigned char *contents, ssize_t length);
  virtual bool mine(struct dhcpv6_response *rsp);

protected:
  virtual void information_request(dhcpv6_response *response,
				   struct sockaddr_in6 *from,
				   const unsigned char *packet, unsigned length);
  virtual void solicit(dhcpv6_response *response, struct sockaddr_in6 *from,
		       const unsigned char *contents, unsigned length);
  virtual void advertise(dhcpv6_response *response, struct sockaddr_in6 *from,
			 const unsigned char *packet, unsigned length);
  virtual void request(dhcpv6_response *response, struct sockaddr_in6 *from,
		       const unsigned char *packet, unsigned length);
  virtual void renew(dhcpv6_response *response, struct sockaddr_in6 *from,
		     const unsigned char *packet, unsigned length);
  virtual void rebind(dhcpv6_response *response, struct sockaddr_in6 *from,
		      const unsigned char *packet, unsigned length);
  virtual void release(dhcpv6_response *response, struct sockaddr_in6 *from,
		       const unsigned char *packet, unsigned length);
  virtual void decline(dhcpv6_response *response, struct sockaddr_in6 *from,
		       const unsigned char *packet, unsigned length);
  virtual void confirm(dhcpv6_response *response, struct sockaddr_in6 *from,
		       const unsigned char *packet, unsigned length);
  virtual void reply(dhcpv6_response *response, struct sockaddr_in6 *from,
		     const unsigned char *data, unsigned length);
  virtual void relay_forward(dhcpv6_response *response, struct sockaddr_in6 *from,
			     const unsigned char *data, unsigned length);
  virtual void relay_reply(dhcpv6_response *response, struct sockaddr_in6 *from,
			   const unsigned char *data, unsigned length);
  virtual void reconfigure(dhcpv6_response *response, struct sockaddr_in6 *from,
			   const unsigned char *data, unsigned length);
};


#endif

