/* script.h
 *
 * The code in this file provides an interface between the DHCP client and
 * a script (shell, perl, whatever you like) that controls the network
 * interface or interfaces that the client manages.   The script is asked
 * to do things like set up an interface to be configured, and later to
 * configure an IP address on it, set up resolver information, and like that.
 */

/*
 * Copyright (c) 2006 Nominum, Inc.   All rights reserved.
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

#ifndef DHCPP_CLIENT_SCRIPT_H
#define DHCPP_CLIENT_SCRIPT_H

#include "controller.h"

class Script: public DHCPClientController
{
public:
  Script(const char *name);
  void initialize(void);
  void add_item(const char *name, const char *fmt, ...);
  void finish(EventReceiver *receiver, int failState, int succeedState);
protected:
  
private:
  void addenv(char *str);
  int option_name_clean(char *buf, size_t buflen, struct option *option);

  char *scriptName;
  int envCount;
  int envMax;
  char **envp;
};
#endif

/* Local Variables:  */
/* mode:c++ */
/* c-file-style:"gnu" */
/* end: */
