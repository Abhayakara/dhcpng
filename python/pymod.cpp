/* Copyright (c) 2007 Nominum, Inc.   All rights reserved.
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

#ifndef lint
static char ocopyright[] __attribute__((unused)) =
"$Id: pymod.cpp,v 1.9 2012/04/01 21:26:34 mellon Exp $ Copyright (c) 2005-2006 Nominum, Inc.  All rights reserved.\n";
#endif /* not lint */

#include "Python.h"

#include "dhcpd.h"
#include "version.h"
#include "client/v4client.h"
#include "client/v6client.h"
#include "client/controller.h"
#include "client/client.h"

#include "python/proto.h"

static PyObject *discover_interfaces(PyObject *self, PyObject *args)
{
  PyObject *ifs = PyList_New(0);
  struct interface_info *ip;
  for (ip = interfaces; ip; ip = ip->next)
    {
      PyObject *ifname = PyString_FromString(ip->name);
      PyList_Append(ifs, ifname);
    }
  return ifs;
}

static PyObject *v4netsetup(PyObject *self, PyObject *args)
{
  dhcpv4_socket_setup();

  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *v6netsetup(PyObject *self, PyObject *args)
{
  int server_port;
  int listen_port;

  if (!PyArg_ParseTuple(args, "II", &listen_port, &server_port))
    return NULL;

  remote_port_dhcpv6 = htons(server_port);
  listen_port_dhcpv6 = htons(listen_port);
  dhcpv6_socket_setup();

  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *do_dispatch(PyObject *self, PyObject *args)
{
  dispatch();
  Py_INCREF(Py_None);
  return Py_None;
}

/* The reason this is complicated is that the caller passes three sets
 * of some kind of iterable object.  Each element of these objects is a
 * descriptor.   We have to turn those into fd_sets and figure out
 * the maximum descriptor value.  Then we have to convert the timeout
 * into a timeval, and call the dispatch_select function, which
 * dispatches DHCP events until the caller's timeout expires or one of
 * the caller's descriptors is ready.   Then we have to go through the
 * three fd_sets we made and construct arrays containing all the file
 * descriptors whose bit is set in the corresponding fd_set, and return
 * those as a tuple.
 */
static PyObject *do_dispatch_select(PyObject *self, PyObject *args)
{
  PyObject *desc[3], *timeout;
  fd_set sets[3];
  int i, j, max = 0, nfds;
  isc_result_t result;
  double td;
  struct timeval tv, *tvp;
  PyObject *rv;

  /* Any iterable is valid for the descriptors, and any simple number is
   * valid for the timeout.
   */
  if (!PyArg_ParseTuple(args, "OOOO", &desc[0], &desc[1], &desc[2], &timeout))
    return NULL;

  for (i = 0; i < 3; i++)
    {
      PyObject *iterator, *item;

      FD_ZERO(&sets[i]);
      iterator = PyObject_GetIter(desc[i]);
      if (iterator == NULL)
	return NULL;
      while ((item = PyIter_Next(iterator)))
	{
	  long fd;
	  if (PyInt_Check(item))
	    fd = PyInt_AS_LONG(item);
	  else if (PyLong_Check(item))
	    fd = PyLong_AsLong(item);
	  else
	    {
	      Py_DECREF(iterator);
	      Py_DECREF(item);
	      return PyErr_Format(PyExc_TypeError,
				  "non-integer descriptor in %s set",
				  i ? i == 1 ? "write" : "exception" : "read");
	    }
	  Py_DECREF(item);

	  if (fd < 0)
	    {
	      Py_DECREF(iterator);
	      return PyErr_Format(PyExc_TypeError,
				  "negative descriptor in %s set",
				  i ? i == 1 ? "write" : "exception" : "read");
	    }
	  FD_SET(fd, &sets[i]);

	  if (fd > max)
	    max = fd;	
	}
      Py_DECREF(iterator);
    }  

  /* Convert the timeout to a timeval. */
  if (PyFloat_Check(timeout))
    {
      td = PyFloat_AS_DOUBLE(timeout);
      tv.tv_sec = td;
      tv.tv_usec = (td - floor(td)) * 1000000;
      tvp = &tv;
    }
  else if (PyInt_Check(timeout))
    {
      tv.tv_sec = PyInt_AS_LONG(timeout);
      tv.tv_usec = 0;
      tvp = &tv;
    }
  else if (PyLong_Check(timeout))
    {
      tv.tv_sec = PyLong_AsLong(timeout);
      tv.tv_usec = 0;
      tvp = &tv;
    }
  else if (timeout == Py_None)
    {
      tvp = 0;
    }
  else
    {
      PyErr_SetString(PyExc_TypeError, "non-numeric timeout");
      return NULL;
    }

  result = dispatch_select(&sets[0], &sets[1], &sets[2], max, tvp, &nfds);
  if (result != ISC_R_SUCCESS)
    return PyErr_Format(PyExc_RuntimeError, "dispatch_select: %s",
			isc_result_totext(result));

  for (i = 0; i < 3; i++)
    {
      desc[i] = PyList_New(0);
      if (desc[i] == NULL) /* XXX this threw an exception, right? */
	{
	  for (j = 0; j < i; j++)
	    Py_DECREF(desc[j]);
	  return NULL;
	}
    }

  /* Make three lists of descriptors that are ready, one for read, one for
   * write, one for exception.
   */
  for (i = 0; i <= max; i++)
    {
      PyObject *num;
      for (j = 0; j < 3; j++)
	{
	  /* If we find that the descriptor i is set in set[j], then
	   * we need to add an element to the end of the list.   Since
	   * it might be ready in more than one set, we keep the reference
	   * to the Py_Integer we create and use the same one in each
	   * descriptor set.
	   */
	  if (FD_ISSET(i, &sets[j]))
	    {
	      num = PyInt_FromLong(i);
	      if (num == NULL)
		{
		  for (i = 0; i < 3; i++)
		    Py_DECREF(desc[i]);
		  return NULL;
		}
	      PyList_Append(desc[j], num);
	    }
	}
    }

  rv = PyTuple_New(3);
  if (rv == NULL)
    {
      for (i = 0; i < 3; i++)
	Py_DECREF(desc[i]);
      return NULL;
    }
  for (i = 0; i < 3; i++)
    PyTuple_SET_ITEM(rv, i, desc[i]); /* steals reference. */
  return rv;
}

static PyMethodDef dhcpmethods[] = {
	{ "discover_interfaces", discover_interfaces, METH_NOARGS },
	{ "v4netsetup", v4netsetup, METH_NOARGS },
	{ "v6netsetup", v6netsetup, METH_VARARGS },
	{ "dispatch", do_dispatch, METH_VARARGS },
	{ "dispatch_select", do_dispatch_select, METH_VARARGS },
	{ NULL, NULL, 0 } };
	

/* Globals for the DHCP agents. */

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

u_int16_t local_port_dhcpv6 = 0;
u_int16_t remote_port_dhcpv6 = 0;
u_int16_t listen_port_dhcpv6 = 0;

/* Called by python when the DHCP module is loaded.   Do all the basic stuff
 * we need to do, and then actually initialize the module.
 */

extern "C" {
  void initdhcp()
  {
    PyObject *module;

    /* Discover all the network interfaces. */
    discover_interfaces();
  
    struct servent *ent;
    ent = getservbyname("dhcpc", "udp");
    if (ent)
      local_port = ent->s_port;
    else
      local_port = htons(68);
    listen_port = local_port;
  
    ent = getservbyname("dhcpc6", "udp");
    if (ent)
      local_port_dhcpv6 = ent->s_port;
    else
      local_port_dhcpv6 = htons(546);
    listen_port_dhcpv6 = local_port_dhcpv6;
    endservent();

    /* local_port is the dhcp client port; remote_port is the dhcp server
     * port.
     */
    remote_port_dhcpv6 = htons(ntohs(local_port_dhcpv6) + 1);
    remote_port = htons(ntohs(local_port) - 1);

    /* Get the current time... */
    fetch_time();

    sockaddr_broadcast.sin_family = AF_INET;
    sockaddr_broadcast.sin_port = remote_port;
    sockaddr_broadcast.sin_addr.s_addr = INADDR_BROADCAST;

    /* We normally send all packets to the all_agents_and_servers
     * multicast address.   However, for debugging, we may want to
     * unicast to a specific IPv6 address.   We may also unicast
     * to the server if it requested us to do so, but that's handled
     * elsewhere.
     */
    sockaddr_in6_all_agents_and_servers.sin6_family = AF_INET6;
    sockaddr_in6_all_agents_and_servers.sin6_port = remote_port;
    inet_pton(AF_INET6, "FF02::1:2",
	      &sockaddr_in6_all_agents_and_servers.sin6_addr);

    /* Set this up as an iaddr as well as a sockaddr_in6. */
    iaddr_all_agents_and_servers.len = 16;
    memcpy(iaddr_all_agents_and_servers.iabuf,
	   &sockaddr_in6_all_agents_and_servers.sin6_addr, 16);
	
    inaddr_any.s_addr = INADDR_ANY;
	
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

    /* Make up a seed for the random number generator from current
       time plus the sum of the last four bytes of each
       interface's hardware address interpreted as an integer.
       No entropy, but we're booting, so we're not likely to
       find anything better, and the main thing is to keep our
       numbers separate from other clients that may also be booting. */
    int seed = 0;
    struct interface_info *ip;

    for (ip = interfaces; ip; ip = ip->next)
      {
	int junk;
	memcpy(&junk,
	       &ip->lladdr.hbuf[ip->lladdr.hlen - sizeof seed], sizeof seed);
	seed += junk;
      }
    srandom(seed + cur_time);

    module = Py_InitModule3("dhcp", dhcpmethods, "DHCP client module (XXX)");

    /* Initialize the interface object. */
    interface_object_init(module);
    /* And the v4 client object. */
    v4client_object_init(module);
    /* And the v6 client object. */
    v6client_object_init(module);
  }
}

/* Local Variables:  */
/* mode:C++ */
/* c-file-style:"gnu" */
/* end: */
