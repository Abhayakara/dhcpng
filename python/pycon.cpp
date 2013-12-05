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
"$Id: pycon.cpp,v 1.7 2010/01/14 20:35:08 mellon Exp $ Copyright (c) 2005-2006 Nominum, Inc.  All rights reserved.\n";
#endif /* not lint */

#include "Python.h"

#include "dhcpd.h"
#include "version.h"

#include "structmember.h"

#include "python/pycon.h"
#include "client/v4client.h"
#include "client/v6client.h"
#include "client/client.h"

#include "python/proto.h"

PyCon::PyCon(PyObject *pyobj)
{
  Py_INCREF(pyobj);
  pycon = pyobj;
}

void PyCon::initialize(void)
{
  PyObject *ret;

  ret = PyObject_CallMethod(pycon, "start", "");
}

void PyCon::finish(EventReceiver *receiver, int failState, int succeedState)
{
  PyObject *ret;

  /* Call the finish method. */
  ret = PyObject_CallMethod(pycon, "finish", "");
  if (receiver)
    {
      if (ret == NULL || ret == Py_False)
	receiver->event("exit", failState, 0);
      else
	receiver->event("exit", succeedState, 0);
    }
}

/* Send the contents of an individual option to the controller. */
void PyCon::option_internal(struct option_cache *oc,
			    struct option_state *options,
			    struct option_space *u)
{
  char name[256];
  PyObject *option, *optname, *optdata;;

  /* Certain DHCPV6 options shouldn't get dumped. */
  if (oc->option->option_space == &dhcpv6_option_space &&
      (oc->option->code == DHCPV6_DUID ||
       oc->option->code == DHCPV6_IA_NA ||
       oc->option->code == DHCPV6_IA_TA ||
       oc->option->code == DHCPV6_IA_ADDRESS ||
       oc->option->code == DHCPV6_AUTHENTICATION ||
       oc->option->code == DHCPV6_VENDOR_SPECIFIC_INFORMATION ||
       oc->option->code == DHCPV6_IA_PD))
    return;

  option = PyTuple_New(2);
  option_name_clean(name, sizeof name, oc->option);
  optname = PyString_FromStringAndSize(name, strlen(name));
  /* We can't do anything here if the allocations failed. */
  if (option == NULL || optname == NULL)
    return;
  PyTuple_SET_ITEM(option, 0, optname);
  optdata = pythonify_option(oc->option, &oc->data);
  if (optdata == NULL)
    return;
  PyTuple_SET_ITEM(option, 1, optdata);
  PyObject_CallMethod(pycon, "add_item", "ssO", prefix, "option", option);
  Py_DECREF(option);
}

void PyCon::add_item(const char *name, const char *fmt, ...)
{
  char spbuf [1024];
  unsigned len;
  va_list list;
  PyObject *ret;

  /* This is ugly, but the other easy alternative is to duplicate
   * most of the controller object code here - not so helpful.
   */
  if (!strcmp(fmt, "%s"))
    {
      va_start(list, fmt);
      ret = PyString_FromString(va_arg(list, char *));
      va_end(list);
    }
  else if (!strcmp(fmt, "%ld"))
    {
      va_start(list, fmt);
      ret = PyLong_FromLong(va_arg(list, long));
      va_end(list);
    }
  else if (!strcmp(fmt, "%lu"))
    {
      va_start(list, fmt);
      ret = PyLong_FromUnsignedLong(va_arg(list, unsigned long));
      va_end(list);
    }
  else
    {
      /* XXX Really we want to create a data structure with the values, rather
       * XXX than printing it into a string.
       */
      va_start(list, fmt);
      len = vsnprintf(spbuf, sizeof spbuf, fmt, list);
      va_end(list);
      ret = PyString_FromString(spbuf);
    }
  ret = PyObject_CallMethod(pycon, "add_item", "ssO", prefix, name, ret);
}


int PyCon::option_name_clean(char *buf, size_t buflen, struct option *option)
{
  unsigned i, j;
  const char *s;

  j = 0;
  if (option->option_space != &dhcp_option_space)
    {
      s = option->option_space->name;
      i = 0;
    }
  else
    { 
      s = option->name;
      i = 1;
    }

  do
    {
      while (*s)
	{
	  if (j + 1 == buflen)
	    return 0;
	  buf[j++] = *s++;
	}
      if (!i)
	{
	  s = option->name;
	  if (j + 1 == buflen)
	    return 0;
	  buf[j++] = '.';
	}
      ++i;
    } while (i != 2);

  buf[j] = 0;
  return 1;
}

/* Local Variables:  */
/* mode:C++ */
/* c-file-style:"gnu" */
/* end: */
