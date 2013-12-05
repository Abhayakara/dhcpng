/* dbus.h
 *
 * The code in this file provides an interface between the DHCP client and
 * the D-BUS, which is a freedesktop.org thing.   The idea is that something
 * like Network Manager ought to manage the network interfaces, and the DHCP
 * client should just do the protocol to get the information Network Manager
 * needs to manage them.
 *
 * Right now this is all just stubbed out, so there's not much to see here,
 * but in order for the client to actually be useful there needs to be an
 * actual implementation in here.
 */

/*
 * Copyright (c) 2005-2006 Nominum, Inc.   All rights reserved.
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

#ifndef DHCPP_CLIENT_DBUS_H
#define DHCPP_CLIENT_DBUS_H

#if defined(HAVE_DBUS)
# include "controller.h"
# define DBUS_API_SUBJECT_TO_CHANGE twit-o-rama
# include <dbus/dbus.h>

class DBus: public DHCPClientController
{
public:
  DBus(const char *name);
  ~DBus();
  void initialize(void);
  void add_item(const char *name, const char *fmt, ...);
  void finish(EventReceiver *receiver, int failState, int succeedState);
  int readfd();
  isc_result_t reader();
  isc_result_t reaper();
protected:
  
private:
  int option_name_clean(char *buf, size_t buflen, struct option *option);
  int dbus_connection_setup();
  void dbus_connection_start();
  DBusError dbus_err;
  DBusConnection *dbus;
  char *dbus_path_name;
  int dbus_fd;
};
#endif
#endif

/* Local Variables:  */
/* mode:c++ */
/* c-file-style:"gnu" */
/* end: */
