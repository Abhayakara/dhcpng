/* dbus.cpp
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
 * Copyright (c) 2002-2006 Nominum, Inc.   All rights reserved.
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
  "$Id: dbus.cpp,v 1.7 2008/03/06 06:56:35 mellon Exp $ Copyright (c) 2002-2005 Nominum, Inc.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

#if defined(HAVE_DBUS)
#include "version.h"
#include "client/v4client.h"
#include "client/v6client.h"
#include "dhc++/eventreceiver.h"
#include "client/dbus.h"

static char qq[] = { 0 };

static int dbus_readfd(void *v)
{
  DBus *dbus = (DBus *)v;
  return dbus->readfd();
}

static int dbus_writefd(void *v)
{
  return -1;
}

static isc_result_t dbus_reader(void *v)
{
  DBus *dbus = (DBus *)v;
  return dbus->reader();
}

static isc_result_t dbus_reaper(void *v)
{
  DBus *dbus = (DBus *)v;
  return dbus->reaper();
}

DBus::DBus(const char *name)
{
  const char *dbus_path_format = "com.nominum.dhcp.%s.client";
  char *buf;

  /* Set up the dbus path name. */
  buf = (char *)safemalloc(strlen(dbus_path_format) + strlen(name) + 1);
  sprintf(buf, dbus_path_format, name);
  dbus_path_name = buf;
  
  /* Connect to the dbus. */
  dbus_error_init(&dbus_err);
  dbus_connection_start();
}

DBus::~DBus()
{
  if (dbus)
    {
      unregister_io_object(this);
      dbus_connection_close(dbus);
    }
  free(dbus_path_name);
}

/* Worker that actually sets up dbus connection and registers signals. */

int DBus::dbus_connection_setup()
{
  int rv;

  dbus = dbus_bus_get(DBUS_BUS_SYSTEM, &dbus_err);
  if (dbus_error_is_set(&dbus_err))
    {
      log_error("Unable to connect to dbus: %s", dbus_err.message);
      return 0;
    }

  /* The dbus example code I have tests for dbus == NULL here, but
   * presumably that's already been taken care of by the log_fatal().
   * Watch out for a core dump here.
   */
  
  /* Note that this code blocks, which is kind of bad.   But it only happens
   * on startup, so it's sort of okay.
   */
  rv = dbus_bus_request_name(dbus, dbus_path_name,
		  	     DBUS_NAME_FLAG_REPLACE_EXISTING, &dbus_err);
  if (dbus_error_is_set(&dbus_err))
    {
      log_error("Unable to take dbus system bus name %s: %s",
		dbus_path_name, dbus_err.message);
      return 0;
    }
  if (rv != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER)
    {
      log_error("DBus system bus name %s: not primary.", dbus_path_name);
      return 0;
    }

  if (!dbus_connection_get_unix_fd(dbus, &dbus_fd))
    {
      log_error("dbus_connection_get_unix_fd returned false.");
      return 0;
    }

  register_io_object(this, dbus_readfd, dbus_writefd, dbus_reader,
		     0, dbus_reaper);
  return 1;
}

/* Called on startup to connect to dbus.   If connection to dbus
 * fails, try again later.
 */
void DBus::dbus_connection_start()
{
  if (dbus_connection_setup())
    return;
  /* XXX set up a timeout to retry the connection startup in ~30 seconds. */
}

/* Called by io handler code to find descriptor for dbus. */
int DBus::readfd()
{
  return dbus_fd;
}

/* Called whenever the dbus descriptor is readable. */
isc_result_t DBus::reader()
{
  DBusMessage *msg;

  /* Read what's on the bus. */
  dbus_connection_read_write(dbus, 0);

  /* The tutorial suggests that dbus_connection_read_write() will only read a
   * single message, but I'm a bit skeptical, so let's read whatever's there
   * just in case; otherwise we may wind up receiving a message really late
   * or not at all.
   */
  while (1)
    {
      msg = dbus_connection_pop_message(dbus);
      if (!msg)
	return ISC_R_SUCCESS;
      log_info("got a dbus message.\n");
      dbus_message_unref(msg);
    }
}

/* Called if the io handler detects that the dbus connection is lost. */

isc_result_t DBus::reaper()
{
  dbus_connection_close(dbus);
  dbus = 0;

  /* XXX set up a timeout to retry the connection after ~30 seconds. */
  return ISC_R_SUCCESS;
}

void DBus::initialize(void)
{
}

void DBus::finish(EventReceiver *receiver, int failState, int succeedState)
{
  if (receiver)
    receiver->event("exit", succeedState, 0);

  /* XXX Send a message to the d-bus. */
  log_info("Done sending message to d-bus.");
}

void DBus::add_item(const char *name, const char *fmt, ...)
{
  char spbuf [1024];
  char *s;
  unsigned len;
  char *str;
  va_list list;

  va_start (list, fmt);
  len = vsnprintf (spbuf, sizeof spbuf, fmt, list);
  va_end (list);

  str = (char *)safemalloc(strlen(prefix) + strlen(name) + len +
			    1 /* = */ + 1 /* / */ + 1 /* / */ + 1 /* NUL */);
  s = str;
  if (prefix[0])
    {
      strcpy(s, prefix);
      s += strlen(s);
      *s++ = '/';
    }
  strcpy(s, name);
  s += strlen(s);
  *s++ = '=';
  if (len >= sizeof spbuf)
    {
      va_start(list, fmt);
      vsnprintf(s, len + 1, fmt, list);
      va_end(list);
    }
  else
    strcpy(s, spbuf);
  log_info("Client environment: %s", str);
  free(str);
}

int DBus::option_name_clean(char *buf, size_t buflen, struct option *option)
{
  char *s;

  if (buflen < strlen(option->name) + strlen(option->option_space->name) + 2)
    return 0;

  strcpy(buf, option->option_space->name);
  s = buf + strlen(buf);
  *s++ = '/';
  strcpy(s, option->name);
  return 1;
}
#endif /* HAVE_DBUS */

/* Local Variables:  */
/* mode:c++ */
/* c-file-style:"gnu" */
/* end: */
