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
"$Id: pyv6client.cpp,v 1.7 2012/03/30 23:10:25 mellon Exp $ Copyright (c) 2005-2006 Nominum, Inc.  All rights reserved.\n";
#endif /* not lint */

#include "Python.h"

#include "dhcpd.h"
#include "version.h"
#include "client/v6client.h"
#include "client/client.h"

#include "structmember.h"

#include "python/pycon.h"
#include "python/proto.h"

/* The python interface object. */
typedef struct {
  PyObject_HEAD
  /* Type-specific fields go here. */

  /* One client or the other; not both. */
  DHCPv6Client *client;
  PyCon *controller;
  struct interface_info *ifp;
} v6client;

/* Static prototypes. */
static int v6init(v6client *self, PyObject *args, PyObject *kwds);
static PyObject *v6new(PyTypeObject *type, PyObject *args, PyObject *kwds);
static void v6dealloc(v6client *self);
static PyObject *state_soliciting(v6client *self);
static PyObject *state_rapid(v6client *self);
static PyObject *state_release(v6client *self);
static PyObject *state_confirm(v6client *self);
static PyObject *state_inform(v6client *self);
static PyObject *state_unmanaged(v6client *self);
static PyObject *set_relay_destination(v6client *self, PyObject *args, PyObject *kwds);

/* Python object static members. */
static PyMemberDef v6members[] = {
  { NULL } };

/* Non-static getters and setters for python object. */
static PyGetSetDef v6gsetters[] = {
    {NULL} };

/* Methods python object. */
static PyMethodDef v6methods[] = {
  {"set_relay_destination", (PyCFunction)set_relay_destination,
   METH_VARARGS,
   "Set the All DHCP Relay Agents and Servers address"},
  {"state_soliciting", (PyCFunction)state_soliciting, METH_NOARGS,
   "start the client protocol in the soliciting state" },
  {"state_release", (PyCFunction)state_release, METH_NOARGS,
   "start the client protocol in the soliciting state" },
  {"state_rapid", (PyCFunction)state_rapid, METH_NOARGS,
   "start the client protocol in the soliciting state" },
  {"state_confirm", (PyCFunction)state_confirm, METH_NOARGS,
   "try to confirm the current lease (or get a new one)" },
  {"state_inform", (PyCFunction)state_inform, METH_NOARGS,
   "Do a DHCP inform request" },
  {"state_unmanaged", (PyCFunction)state_unmanaged, METH_NOARGS,
   "Stop doing DHCP immediately" },
  {NULL}  /* Sentinel */
};

/* The object type definition. */
static PyTypeObject v6type = {
    PyObject_HEAD_INIT(NULL)
    0,					/*ob_size*/
    "dhcp.v6client",			/*tp_name*/
    sizeof(v6client),			/*tp_basicsize*/
    0,					/*tp_itemsize*/
    (destructor)v6dealloc,		/*tp_dealloc*/
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
    "DHCPv6 client object",		/* tp_doc */
    0,					/* tp_traverse */
    0,					/* tp_clear */
    0,					/* tp_richcompare */
    0,					/* tp_weaklistoffset */
    0,					/* tp_iter */
    0,					/* tp_iternext */
    v6methods,				/* tp_methods */
    v6members,				/* tp_members */
    v6gsetters,				/* tp_getset */
    0,					/* tp_base */
    0,					/* tp_dict */
    0,					/* tp_descr_get */
    0,					/* tp_descr_set */
    0,					/* tp_dictoffset */
    (initproc)v6init,			/* tp_init */
    0,					/* tp_alloc */
    v6new,				/* tp_new */
};

void
v6client_object_init(PyObject *module)
{
  v6type.tp_new = PyType_GenericNew;
  if (PyType_Ready(&v6type) < 0)
    return;
  Py_INCREF(&v6type);

  PyModule_AddObject(module, "v6client", (PyObject *)&v6type);
}

static void
v6dealloc(v6client *self)
{
  /* XXX free up controller and client object! */
  self->ob_type->tp_free((PyObject *)self);
}

static PyObject *
v6new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  v6client *self;

  self = (v6client *)type->tp_alloc(type, 0);
  self->client = 0;
  self->controller = 0;
  self->ifp = 0;
  return (PyObject *)self;
}

static int
v6init(v6client *self, PyObject *args, PyObject *kwds)
{
  struct interface_info *ip;
  char *ifname;
  PyObject *pycon = NULL;
  u_int8_t *duid = NULL;
  int duid_len;

  if (!PyArg_ParseTuple(args, "sOs#", &ifname, &pycon, &duid, &duid_len))
    return -1;

  /* Figure out which interface we're on. */
  for (ip = interfaces; ip; ip = ip->next)
    {
      if (!strcmp(ip->name, ifname))
	break;
    }
  if (!ip)
    {
      PyErr_SetString(PyExc_LookupError, "specified interface does not exist");
      return -1;
    }
  self->ifp = ip;

  /* Generate a controller object, connected to the written-in-python
   * controller object we've been passed.
   */
  self->controller = new PyCon(pycon);

  /* Now generate a client object. */
  self->client = new DHCPv6Client(ip, self->controller, duid, duid_len);
  if (ip->num_v6listeners == ip->max_v6listeners)
    {
      if (ip->max_v6listeners == 0)
	ip->max_v6listeners = 20;
      DHCPv6Listener **foo = (DHCPv6Listener **)safemalloc(ip->max_v6listeners * sizeof (DHCPv6Listener *));
      if (ip->num_v6listeners)
	memcpy(foo, ip->v6listeners, ip->num_v6listeners);
      memset(&foo[ip->num_v6listeners], 0, (ip->max_v6listeners - ip->num_v6listeners) * sizeof (DHCPv6Listener *));
      if (ip->v6listeners)
	free(ip->v6listeners);
      ip->v6listeners = foo;
    }
  ip->v6listeners[ip->num_v6listeners++] = self->client;
  return 0;
}

static PyObject *
set_relay_destination(v6client *self, PyObject *args, PyObject *kwds)
{
  char *dest;
  if (self->client == 0)
    {
      PyErr_SetString(PyExc_LookupError, "no DHCP client");
      return NULL;
    }
  if (!PyArg_ParseTuple(args, "s", &dest))
    return NULL;
  if (!self->client->set_relay_destination(dest))
    {
      PyErr_SetString(PyExc_LookupError, "Invalid IPv6 Address");
      return NULL;
    }
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *
state_soliciting(v6client *self)
{
  self->client->state_soliciting();
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *
state_rapid(v6client *self)
{
  self->client->state_rapid();
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *
state_confirm(v6client *self)
{
  self->client->state_confirm();
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *
state_inform(v6client *self)
{
  self->client->state_inform();
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *
state_release(v6client *self)
{
  self->client->state_release();
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *
state_unmanaged(v6client *self)
{
  self->client->state_unmanaged();
  Py_INCREF(Py_None);
  return Py_None;
}

/* Local Variables:  */
/* mode:C++ */
/* c-file-style:"gnu" */
/* end: */
