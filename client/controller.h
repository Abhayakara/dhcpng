/* controller.h
 *
 * Definitions for the DHCPClientController class.
 */

/* Copyright (c) 2006 Nominum, Inc.   All rights reserved.
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

#ifndef DHCPP_CONTROLLER_H
#define DHCPP_CONTROLLER_H

class DHCPClientController
{
public:
  DHCPClientController();
  virtual ~DHCPClientController();

  void start(struct client_config *config, const char *reason);
  virtual void initialize(void) = 0;
  void send_lease(const char *pfx,
		  struct client_lease *lease, struct option_state *options);
  void send_ia_addr(const char *type, struct ia_addr *address);
  void send_ia(struct ia *ia);
  virtual void finish(EventReceiver *receiver,
		      int failState, int succeedState) = 0;
  virtual void add_item(const char *name, const char *fmt, ...) = 0;
  void send_options(struct option_state *options);

protected:
  virtual void option_internal(struct option_cache *oc,
			       struct option_state *options,
			       struct option_space *u);
  static void option(struct option_cache *oc, struct option_state *options,
		     struct option_space *, void *me);
  virtual void compose_ia_prefix(struct ia *ia);
  virtual int option_name_clean(char *buf, size_t buflen,
				struct option *option) = 0;

  struct client_config *config;
  char *prefix;
};

#endif

/* Local Variables:  */
/* mode:c++ */
/* c-file-style:"gnu" */
/* end: */
