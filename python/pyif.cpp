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
"$Id: pyif.cpp,v 1.3 2010/01/14 20:35:35 mellon Exp $ Copyright (c) 2005-2006 Nominum, Inc.  All rights reserved.\n";
#endif /* not lint */

#include "Python.h"

#include "dhcpd.h"
#include "version.h"
#include "client/v4client.h"
#include "client/v6client.h"
#include "client/controller.h"
#include "client/client.h"

#include "structmember.h"

#include "python/proto.h"

/* The python interface object. */
typedef struct {
    PyObject_HEAD
    /* Type-specific fields go here. */
    char *name;
} ifobj;

/* Static prototypes. */
static int ifinit(ifobj *self, PyObject *args, PyObject *kwds);
static PyObject *ifnew(PyTypeObject *type, PyObject *args, PyObject *kwds);
static void ifdealloc(ifobj *self);
static struct interface_info *getif(char *name);
static PyObject *getv4addrs(ifobj *self, void *closure);
static PyObject *getv6addrs(ifobj *self, void *closure);
static PyObject *getlladdr(ifobj *self, void *closure);
static PyObject *getlltype(ifobj *self, void *closure);

/* Python object static members. */
static PyMemberDef ifmembers[] = {
  { "name", T_STRING, offsetof(ifobj, name), 0, "interface name" },
  { NULL } };

/* Non-static getters and setters for python object. */
static PyGetSetDef ifgsetters[] = {
    {"v4addrs",
     (getter)getv4addrs, NULL,
     "list of IPv4 addresses configured on the interface", NULL},
    {"v6addrs",
     (getter)getv6addrs, NULL,
     "list of IPv6 addresses configured on the interface", NULL},
    {"lladdr",
     (getter)getlladdr, NULL,
     "link-layer address of interface", NULL},
    {"lltype",
     (getter)getlltype, NULL,
     "link-layer type of interface", NULL},
    {NULL} };

/* Methods python object. */
static PyMethodDef ifmethods[] = {
    {NULL}
};

/* The object type definition. */
static PyTypeObject iftype = {
    PyObject_HEAD_INIT(NULL)
    0,					/*ob_size*/
    "dhcp.Interface",			/*tp_name*/
    sizeof(ifobj),			/*tp_basicsize*/
    0,					/*tp_itemsize*/
    (destructor)ifdealloc,		/*tp_dealloc*/
    0,					/*tp_print*/
    0,					/*tp_getattr*/
    0,					/*tp_setattr*/
    0,					/*tp_compare*/
    0,					/*tp_repr*/
    0,					/*tp_as_number*/
    0,					/*tp_as_sequence*/
    0,					/*tp_as_mapping*/
    0,					/*tp_hash */
    0,					/*tp_call*/
    0,					/*tp_str*/
    0,					/*tp_getattro*/
    0,					/*tp_setattro*/
    0,					/*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,	/*tp_flags*/
    "Interface object",			/* tp_doc */
    0,					/* tp_traverse */
    0,					/* tp_clear */
    0,					/* tp_richcompare */
    0,					/* tp_weaklistoffset */
    0,					/* tp_iter */
    0,					/* tp_iternext */
    ifmethods,				/* tp_methods */
    ifmembers,				/* tp_members */
    ifgsetters,				/* tp_getset */
    0,					/* tp_base */
    0,					/* tp_dict */
    0,					/* tp_descr_get */
    0,					/* tp_descr_set */
    0,					/* tp_dictoffset */
    (initproc)ifinit,			/* tp_init */
    0,					/* tp_alloc */
    ifnew,				/* tp_new */
};

void
interface_object_init(PyObject *module)
{
  iftype.tp_new = PyType_GenericNew;
  if (PyType_Ready(&iftype) < 0)
    return;
  Py_INCREF(&iftype);

  PyModule_AddObject(module, "Interface", (PyObject *)&iftype);
}

static void
ifdealloc(ifobj *self)
{
  if (self->name)
    free(self->name);
  self->ob_type->tp_free((PyObject *)self);
}

static PyObject *
ifnew(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  ifobj *self;

  self = (ifobj *)type->tp_alloc(type, 0);
  self->name = (char *)0;
  return (PyObject *)self;
}

static int
ifinit(ifobj *self, PyObject *args, PyObject *kwds)
{
  struct interface_info *ip;
  char *name;

  if (!PyArg_ParseTuple(args, "s", &name))
    return -1;

  ip = getif(name);
  if (!ip)
    {
      PyErr_SetString(PyExc_LookupError, "specified interface does not exist");
      return -1;
    }

  self->name = (char *)malloc(strlen(name) + 1);
  if (self->name == NULL)
    return -1;
  strcpy(self->name, name);
  return 0;
}

static struct interface_info *
getif(char *name)
{
  struct interface_info *ip;
  
  for (ip = interfaces; ip; ip = ip->next)
    {
      if (!strcmp(ip->name, name))
	return ip;
    }
  return (struct interface_info *)0;
}

static PyObject *
getv4addrs(ifobj *self, void *closure)
{
  PyObject *addrs;
  struct interface_info *ip;
  int i;

  /* Get the interface_info struct associated with this ifobj. */
  if (!self->name)
    {
      PyErr_SetString(PyExc_AssertionError,
		      "specified interface object has no name");
      return NULL;
    }
  ip = getif(self->name);

  /* Make a list of the addresses.   If there are no addresses,
   * we return an empty list, not Py_None.
   */
  addrs = PyList_New(0);
  for (i = 0; i < ip->ipv4_addr_count; i++)
    {
      char nbuf[13];
      const char *rv = inet_ntop(AF_INET,
				 (void *)&ip->ipv4s[i], nbuf, sizeof nbuf);
      if (rv == NULL)
	{
	  PyErr_SetString(PyExc_AssertionError,
			  "inet_ntop had no space for ipv4 address");
	  return NULL;
	}

      PyObject *addr = PyString_FromString(rv);
      PyList_Append(addrs, addr);
    }
  return addrs;
}

static PyObject *
getv6addrs(ifobj *self, void *closure)
{
  PyObject *addrs;
  struct interface_info *ip;
  int i;

  /* Get the interface_info struct associated with this ifobj. */
  if (!self->name)
    {
      PyErr_SetString(PyExc_AssertionError,
		      "specified interface object has no name");
      return NULL;
    }
  ip = getif(self->name);

  /* Make a list of the addresses.   If there are no addresses,
   * we return an empty list, not Py_None.
   */
  addrs = PyList_New(0);
  for (i = 0; i < ip->ipv6_addr_count; i++)
    {
      char nbuf[256];
      const char *rv = inet_ntop(AF_INET6,
				 (void *)&ip->ipv6s[i], nbuf, sizeof nbuf);
      if (rv == NULL)
	{
	  PyErr_SetString(PyExc_AssertionError,
			  "inet_ntop had no space for ipv6 address");
	  return NULL;
	}

      PyObject *addr = PyString_FromString(rv);
      PyList_Append(addrs, addr);
    }
  return addrs;
}

static PyObject *
getlladdr(ifobj *self, void *closure)
{
  PyObject *lladdr;
  struct interface_info *ip;

  /* Get the interface_info struct associated with this ifobj. */
  if (!self->name)
    {
      PyErr_SetString(PyExc_AssertionError,
		      "specified interface object has no name");
      return NULL;
    }
  ip = getif(self->name);
  lladdr = PyString_FromStringAndSize((char *)&ip->lladdr.hbuf[1],
				      ip->lladdr.hlen - 1);
  return lladdr;
}

static PyObject *
getlltype(ifobj *self, void *closure)
{
  PyObject *lltype;
  struct interface_info *ip;

  /* Get the interface_info struct associated with this ifobj. */
  if (!self->name)
    {
      PyErr_SetString(PyExc_AssertionError,
		      "specified interface object has no name");
      return NULL;
    }
  ip = getif(self->name);
  lltype = PyLong_FromLong((long)(ip->lladdr.hbuf[0]));
  return lltype;
}

/* Local Variables:  */
/* mode:C++ */
/* c-file-style:"gnu" */
/* end: */
