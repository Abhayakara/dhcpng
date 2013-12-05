/* v4listener.h
 *
 * Definitions for the DHCPv4Listener class.
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

#ifndef DHCPP_V4LISTENER_H
#define DHCPP_V4LISTENER_H

class DHCPv4Listener
{
public:
  virtual ~DHCPv4Listener();
  isc_result_t got_packet(struct interface_info *interface,
			  struct sockaddr_in *from,
			  unsigned char *contents,
			  ssize_t length);

protected:
  virtual void dhcp(struct packet *packet);
  virtual void bootp(struct packet *packet);
  virtual void bootrequest(struct packet *packet);
  virtual void bootreply(struct packet *packet);
  virtual void discover(struct packet *packet);
  virtual void offer(struct packet *packet);
  virtual void request(struct packet *packet);
  virtual void decline(struct packet *packet);
  virtual void ack(struct packet *packet);
  virtual void nak(struct packet *packet);
  virtual void release(struct packet *packet);
  virtual void inform(struct packet *packet);
};


#endif

