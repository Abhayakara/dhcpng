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
"$Id: pyv4client.cpp,v 1.3 2012/03/23 13:27:18 mellon Exp $ Copyright (c) 2005-2006 Nominum, Inc.  All rights reserved.\n";
#endif /* not lint */

#include "Python.h"

#include "dhcpd.h"
#include "version.h"
#include "client/v4client.h"
#include "client/client.h"

#include "structmember.h"

#include "python/pycon.h"
#include "python/proto.h"

/* The python interface object. */
typedef struct {
  PyObject_HEAD
  /* Type-specific fields go here. */

  /* One client or the other; not both. */
  DHCPv4Client *client;
  PyCon *controller;
  struct interface_info *ifp;
} v4client;

/* Static prototypes. */
static int v4init(v4client *self, PyObject *args, PyObject *kwds);
static PyObject *v4new(PyTypeObject *type, PyObject *args, PyObject *kwds);
static void v4dealloc(v4client *self);
static PyObject *state_startup(v4client *self);
static PyObject *state_init_reboot(v4client *self);
static PyObject *state_confirm(v4client *self);
static PyObject *state_init(v4client *self);
static PyObject *state_inform(v4client *self);
static PyObject *state_unmanaged(v4client *self);

/* Python object static members. */
static PyMemberDef v4members[] = {
  { NULL } };

/* Non-static getters and setters for python object. */
static PyGetSetDef v4gsetters[] = {
    {NULL} };

/* Methods python object. */
static PyMethodDef v4methods[] = {
  {"state_startup", (PyCFunction)state_startup, METH_NOARGS,
   "start the client protocol" },
  {"state_init_reboot", (PyCFunction)state_init_reboot, METH_NOARGS,
   "start the client protocol in the INIT-REBOOT state" },
  {"state_confirm", (PyCFunction)state_confirm, METH_NOARGS,
   "try to confirm the current lease (or get a new one)" },
  {"state_init", (PyCFunction)state_init, METH_NOARGS,
   "we have no valid lease, so go try to get one" },
  {"state_inform", (PyCFunction)state_inform, METH_NOARGS,
   "Do a DHCPINFORM" },
  {"state_unmanaged", (PyCFunction)state_unmanaged, METH_NOARGS,
   "Stop doing DHCP immediately" },
  {NULL}  /* Sentinel */
};

/* The object type definition. */
static PyTypeObject v4type = {
    PyObject_HEAD_INIT(NULL)
    0,					/*ob_size*/
    "dhcp.v4client",			/*tp_name*/
    sizeof(v4client),			/*tp_basicsize*/
    0,					/*tp_itemsize*/
    (destructor)v4dealloc,		/*tp_dealloc*/
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
    "DHCPv4 client object",		/* tp_doc */
    0,					/* tp_traverse */
    0,					/* tp_clear */
    0,					/* tp_richcompare */
    0,					/* tp_weaklistoffset */
    0,					/* tp_iter */
    0,					/* tp_iternext */
    v4methods,				/* tp_methods */
    v4members,				/* tp_members */
    v4gsetters,				/* tp_getset */
    0,					/* tp_base */
    0,					/* tp_dict */
    0,					/* tp_descr_get */
    0,					/* tp_descr_set */
    0,					/* tp_dictoffset */
    (initproc)v4init,			/* tp_init */
    0,					/* tp_alloc */
    v4new,				/* tp_new */
};

void
v4client_object_init(PyObject *module)
{
  v4type.tp_new = PyType_GenericNew;
  if (PyType_Ready(&v4type) < 0)
    return;
  Py_INCREF(&v4type);

  PyModule_AddObject(module, "v4client", (PyObject *)&v4type);
}

static void
v4dealloc(v4client *self)
{
  /* XXX free up controller and client object! */
  self->ob_type->tp_free((PyObject *)self);
}

static PyObject *
v4new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  v4client *self;

  self = (v4client *)type->tp_alloc(type, 0);
  self->client = 0;
  self->controller = 0;
  self->ifp = 0;
  return (PyObject *)self;
}

static int
v4init(v4client *self, PyObject *args, PyObject *kwds)
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
  self->client = new DHCPv4Client(ip, self->controller, duid, duid_len);
  ip->v4listener = self->client;

  return 0;
}

static PyObject *
state_startup(v4client *self)
{
  self->client->state_startup();
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *
state_init_reboot(v4client *self)
{
  self->client->state_init_reboot();
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *
state_confirm(v4client *self)
{
  self->client->state_confirm();
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *
state_init(v4client *self)
{
  self->client->state_init();
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *
state_inform(v4client *self)
{
  self->client->state_inform();
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *
state_unmanaged(v4client *self)
{
  self->client->state_unmanaged();
  Py_INCREF(Py_None);
  return Py_None;
}

/* Local Variables:  */
/* mode:C++ */
/* c-file-style:"gnu" */
/* end: */
