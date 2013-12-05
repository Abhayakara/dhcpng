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
"$Id: pyoptions.cpp,v 1.6 2010/01/14 20:37:04 mellon Exp $ Copyright (c) 2007 Nominum, Inc.  All rights reserved.\n";
#endif /* not lint */

#include "Python.h"

#include "dhcpd.h"
#include "version.h"

#include "structmember.h"

#include "python/proto.h"

static PyObject *
pythonify_optformat(const char *name,
		    char *fmt, char *end, struct data_string *data);

/* Given raw option data, produce a python object that represents that
 * data.
 */

PyObject *pythonify_option(struct option *option,
			   struct data_string *data)
{
  unsigned l;
  struct data_string dp = *data;
  PyObject *ret;

  l = strlen(option->format);

  /* Zero or more items, followed by a sequence of zero or more items. */
  if (l && option->format[l - 1] == 'a') 
    {
      PyObject *thingies = NULL;

      /* One or more items, followed by a sequence of zero or more items. */
      if (l > 2)
	thingies = pythonify_optformat(option->name, option->format,
				       &option->format[l - 2], &dp);
      PyObject *array = PyList_New(0);
      while (dp.len)
	{
	  PyObject *elt =
	    pythonify_optformat(option->name, &option->format[l - 2],
				&option->format[l - 1], &dp);
	  PyList_Append(array, elt);
	}
      if (thingies != NULL)
	{
	  /* If ret is a list, it means that there were multiple thingies
	   * in the format before the array, so the array is just another
	   * thingie, which we add to the end of the existing array.
	   */
	  if (PyList_CheckExact(thingies))
	    {
	      PyList_Append(thingies, array);
	      ret = thingies;
	    }

	  /* If ret is not a list, that means that there was only one thingie
	   * in the format before the array, but the actual result is an array
	   * with that thingie and the array we just parsed, so we need to
	   * make an array and put the thingie and the array into the new array.
	   */
	  else
	    {
	      ret = PyList_New(0);
	      PyList_Append(ret, thingies);
	      PyList_Append(ret, array);
	    }
	}
      /* If thingies is null, it means that there were zero items preceding
       * the array; in this case, we return the array - we do not put it
       * inside of another array.
       */
      else
	ret = array;
      return array;
    }

  /* An array of sequences of one or more items. */
  else if (l && option->format[l - 1] == 'A')
    {
      ret = PyList_New(0);

      while (dp.len)
	{
	  PyObject *elt =
	    pythonify_optformat(option->name,
				option->format, &option->format[l - 1], &dp);
	  PyList_Append(ret, elt);
	}
      return ret;
    }
  
  /* One or more items. */
  else
    {
      ret = pythonify_optformat(option->name,
				option->format, &option->format[l], &dp);
      return ret;
    }
}

static PyObject *
pythonify_optformat(const char *name,
		    char *fmt, char *end, struct data_string *dp)
{
  struct in_addr foo;
  unsigned long tval;
  PyObject *ret = NULL;
  PyObject *elt = NULL;
  int index = 0;
  char *fp = fmt;
  unsigned i;

  /* Loop through the option format buffer, consuming data from the option
   * data buffer and converting it to python objects.
   */
  while (fp != end)
    {
      unsigned consumed = 0;

      /* Last item is optional. */
      if (fp[1] == 'o' && dp->len == 0)
	goto out;

      /* Parse the data. */
      switch (*fp)
	{
	case 'E':
	  /* Encapsulations have to come at the end of the buffer.   We do
	   * not pythonify the options in an encapsulation.
	   */
	  fp = end;
	  elt = NULL;
	  consumed = dp->len;
	  break;

	case 'F':
	  fp++;
	  elt = Py_True;
	  Py_INCREF(elt);
	  consumed = 0;
	  break;

	case 'e':
	  fp++;
	  elt = NULL;
	  consumed = 0;
	  break;

	case 'X':
	  for (i = 0; i < dp->len; i++)
	    {
	      if (!isascii(dp->data[i]) || !isprint(dp->data[i]))
		break;
	    }

	  /* If it contains some non-printable characters, return as
	   * a byte array, not a string.
	   */
	  if (i != dp->len)
	    {
	      fp++;
	      elt = PyByteArray_FromStringAndSize((const char *)dp->data,
						  (int)dp->len);
	      consumed = dp->len;
	      break;
	    }
	  /* Fall through, treat it like a text string. */

	case 't':
	  if (fp[1])
	    goto extra_codes;
	  fp++;

	  elt = PyString_FromStringAndSize((const char *)dp->data,
					   (int)dp->len);
	  consumed = dp->len;
	  break;

	case 'd':
	  fp++;
	  /* Cycle through the labels.   If we fall out of this loop and dp[0]
	   * isn't zero, the data is bad.
	   */
	  data_string fqdnbuf;
	  memset(&fqdnbuf, 0, sizeof fqdnbuf);
	  fqdnbuf.buffer = buffer_allocate(200);
	  fqdnbuf.data = fqdnbuf.buffer->data;

	  /* Current pointer into DNS data. */
	  i = 0;

	  /* Cycle through the DNS data until we run out of labels or data. */
	  while (dp->data[i] && i < dp->len)
	    {
	      /* Get the label length or pointer. */
	      unsigned l = dp->data[i];

	      if (l < 0 || l > 63)
		{
		  log_error("unsupported DNS label length: %d", l);
		  /* XXX raise exception */
		  goto out;
		}

	      /* Normal label. */
	      else if (l < 64)
		{
		  if (i + l > dp->len)
		    {
		      log_error("malformed DNS option data at %d: %s", i,
				print_hex_1(dp->len, dp->data, 60));
		      /* XXX raise exception */
		      goto out;
		    }
		  while (l)
		    {
		      ++i;
		      data_string_putc(&fqdnbuf, dp->data[i]);
		      --l;
		    }
		  data_string_putc(&fqdnbuf, '.');
		  i++;
		}
	    }

	  /* If this was a fully-qualified domain name, walk over the terminal
	   * label.
	   */
	  if (i < dp->len)
	    ++i;

	  consumed = i;
	  elt = PyString_FromStringAndSize((const char *)fqdnbuf.data,
					   (int)fqdnbuf.len);
	  data_string_forget(&fqdnbuf);
	  break;

	  /* No data associated with this format. */
	case 'o':
	  fp++;
	  if (fp[1])
	    {
	    extra_codes:
	      log_error("%s: extra codes in format: %s", name, fmt);
	      /* XXX throw exception */
	      goto out;
	    }	      
	  elt = NULL;
	  break;

	case 'I':
	  fp++;
	  consumed = 4;
	  if (dp->len < consumed)
	    {
	    twolittl:
	      log_error("%s: short option data, format %c: %s",
			name, *fp, (dp->len
				    ? "<none>"
				    : print_hex_1(dp->len, dp->data, 60)));
	      /* XXX throw exception */
	      goto out;
	    }
	  foo.s_addr = htonl(getULong(dp->data));
	  elt = PyString_FromString(inet_ntoa(foo));
	  break;

	case '6':
	  fp++;
	  consumed = 16;
	  if (dp->len < consumed)
	    goto twolittl;
	  char v6addr[46];
	  inet_ntop(AF_INET6, (const char *)dp->data, v6addr, sizeof v6addr);
	  elt = PyString_FromString(v6addr);
	  break;

	case 'l':
	  fp++;
	  consumed = 4;
	  if (dp->len < consumed)
	    goto twolittl;
	  elt = PyLong_FromLong((long)getLong(dp->data));
	  break;

	case 'T':
	  fp++;
	  consumed = 4;
	  if (dp->len < consumed)
	    goto twolittl;
	  tval = getULong(dp->data);
	  if (tval == UINT_MAX)
	    {
	      elt = PyString_FromString("infinite");
	      break;
	    }
	  /* fall through */

	case 'L':
	  fp++;
	  consumed = 4;
	  if (dp->len < consumed)
	    goto twolittl;
	  elt = PyLong_FromUnsignedLong(getULong(dp->data));
	  break;

	case 's':
	  fp++;
	  consumed = 2;
	  if (dp->len < consumed)
	    goto twolittl;
	  elt = PyLong_FromLong((long)getShort(dp->data));
	  break;

	case 'S':
	  fp++;
	  consumed = 2;
	  if (dp->len < consumed)
	    goto twolittl;
	  elt = PyLong_FromLong((long)getUShort(dp->data));
	  break;

	case 'b':
	  fp++;
	  consumed = 1;
	  if (dp->len < consumed)
	    goto twolittl;
	  elt = PyLong_FromLong((long)*((const char *)dp->data));
	  break;

	case 'x':
	case 'B':
	  fp++;
	  consumed = 1;
	  if (dp->len < consumed)
	    goto twolittl;
	  elt = PyLong_FromLong((long)dp->data[0]);
	  break;

	case 'f':
	  fp++;
	  consumed = 1;
	  if (dp->len < consumed)
	    goto twolittl;
	  if (dp->data[0])
	    elt = Py_True;
	  else
	    elt = Py_False;
	  Py_INCREF(elt);
	  break;

	default:
	  log_error ("%s: garbage in format string: %s", name, fp);
	  /* Throw an exception! */
	  goto out;
	}
      dp->data += consumed;
      dp->len -= consumed;

      /* If we got an element, put it into the return value.   If this is
       * the first element, the return value is the element, just in case
       * it's also the last element.   If it's the second element, our
       * assumption that there was only one element was wrong, so we have
       * to stuff both the first and second elements into an array.   If
       * it's later than the second element, we already have an array to
       * stuff it into.
       */
      if (elt)
	{
	  if (index == 0)
	    {
	      ret = elt;
	    }
	  else if (index == 1)
	    {
	      PyObject *array = PyList_New(0);
	      if (array)
		{
		  PyList_Append(array, ret);
		  PyList_Append(array, elt);
		  ret = array;
		}
	    }
	  else
	    {
	      PyList_Append(ret, elt);
	    }
	  index++;
	}
    }
 out:
  return ret;
}

#ifdef NOTYET
/* Given a python dictionary containing options, produce an option_state_t
 * containing those options.   Example:
 *
 * { "fqdn": "uma", "user-class": ["joe"] }
 *
 * default_space is the default option space from which to match option
 * names, probably always either dhcp_option_space or dhcpv6_option_space.
 */

struct option_state *
option_state_from_python(PyObject *dict, struct option_space *default_space)
{
  Py_ssize_t pos = 0;
  PyObject *key;
  PyObject *value;
  unsigned i;

  struct option_state *os = new_option_state();
  
  if (!PyDict_Check(dict))
    {
      PyErr_SetString(PyExc_TypeError,
		      "options must be passed as a dictionary.");
      return 0;
    }

  while (PyDict_Next(dict, &pos, &key, &value))
    {
      if (!PyString_Check(key))
	{
	  PyErr_SetString(PyExc_TypeError, "option name must be a string.");
	  return 0;
	}
      char *name;
      Py_ssize_t len;

      /* XXX I think this would throw an exception, so we don't need to.
       * XXX check docs (writing this on the plane).
       */
      if (!PyString_AsStringAndSize(key, &name, &len))
	return 0;

      /* XXX support other option spaces. */
      for (i = 0; i < default_space->max_option; i++)
	{
	  int optlen = strlen(default_space->optvec[i]->name);
	  if (optlen == len &&
	      !memcmp(default_space->optvec[i]->name, name, len))
	    break;
	}

      /* If we didn't find it, throw an exception. */
      if (i == dhcpv6_option_space.max_option)
	{
	  char buf[256];
	  snprintf(buf, sizeof buf, "unknown option: %.*s",
		   (int)(len > 128 ? 128 : len), name);
	  PyErr_SetString(PyExc_KeyError, buf);
	  return 0;
	}

      /* We did find it. */
      struct option_cache *oc =
	option_from_python(default_space->optvec[i], value);

      /* If we didn't successfully parse it, the error string has already
       * been set, so just return.
       */
      if (!oc)
	return 0;
      save_option(&dhcpv6_option_space, os, oc);
    }

    return os;
}

/* Convert a python object into a wire-format option, using the option
 * format string.
 */

static struct option_cache *
option_from_python(struct option *option, PyObject *data)
{
  unsigned l;
  struct data_string dp = *data;
  PyObject *ret;
  char buf[256];
  const char *errstring;

  l = strlen(option->format);

  /* In the case of the 'a' format, we're parsing zero or more singleton
   * object formats, followed by a single object format repeated zero or
   * more times.   So we actually split this up into two operations: parsing
   * the preceding singleton object or objects, and parsing the array of
   * a single object type.
   */
  if (l && option->format[l - 1] == 'a') 
    {
      PyObject *thingies = NULL;
      PyObject *singleton = NULL;
      int available;

      /* First of all, the object we were passed had better be an array. */
      if (!PyList_Check(data))
	{
	  errstring = "option %s requires an array";
	optname_error:
	  snprintf(buf, sizeof buf, errstring, option->name);
	  PyErr_SetString(PyExc_AssertionError, buf);
	  return 0;
	}

      /* This is a bad format string - we need an object format for the array
       * of objects we're parsing.
       */
      if (l == 1)
	{
	  errstring = "internal error: solitary a format for option %s";
	  goto optname_error;
	}

      /* In this case we're simply parsing out of the array we've
       * (we hope!) been passed - there are no singleton objects.
       */
      if (l == 2)
	{
	  thingies = data;
	  available = 0;
	}

      /* In this case, we were passed one or more objects, the last of
       * which is the single object format array.   So first we parse
       * the singleton or singletons, and then we parse the array.
       */
      else
	{
	  /* If there's one singleton object, we extract it from the
	   * array.
	   */
	  if (l == 3)
	    {
	      if (PyList_Size(data) != 2)
		{
		  errstring =
		    "option %s requires exactly two elements in outer list.";
		  goto optname_error;
		}

	      singleton = PyList_GetItem(data, 0);
	      thingies = PyList_GetItem(data, 1);
	      /* We shouldn't be able to get an exception here, but why
	       * tempt fate?
	       */
	      if (!singleton || !thingies)
		return 0;

	      available = 1;
	    }
	  /* There's more than one singleton object, so we parse the singletons
	   * from the array we've been passed.
	   */
	  else
	    {
	      singleton = data;
	      Py_ssize_t len = PyList_Size(data);
	      if (len < 2)
		{
		  errstring =
		    "option %s requires more than two elements in outer list.";
		  goto optname_error;
		}
	      /* The array to parse should be the last element on the list.
	       */
	      thingies = PyList_GetItem(data, len - 1);

	      available = len - 1;
	    }
	  if (!PyList_Check(thingies))
	    {
	      errstring = ("option %s requires a list as the "
			   "final element in the outer list.");
	      goto optname_error;
	    }
	}
	  
      if (singleton)
	{
	  /* Parse the singletons, if that throws an exception pass it
	   * along.
	   */
	  if (!optformat_from_python(oc, option->format,
				     &option->format[l - 2],
				     singleton, available))
	    return 0;
	}

      /* Now convert the array. */
      available = PyList_Size(thingies);
      for (i = 0; i < available; i++)
	{
	  PyObject *thing = PyArray_GetItem(thingies, i);
	  if (!optformat_from_python(oc, &option->format[l - 2],
				     &option->format[l - 1], thing, 1))
	    return 0;
	}
    }

  /* An array of sequences of one or more items. */
  else if (l && option->format[l - 1] == 'A')
    {
      if (!PyList_Check(data))
	{
	  errstring = "option %s requires an array of items.";
	  goto optname_error;
	}
      count = PyList_Size(data);
      for (i = 0; i < count; i++)
	{
	  PyObject *chunk = PyArray_GetItem(data, i);
	  if (PyList_Check(chunk))
	    available = PyList_Size(chunk);
	  else
	    available = 1;

	  /* Try to parse this chunk. */
	  if (!optformat_from_python(oc, &option->format,
				     &option->format[l - 1], chunk, available))
	    return 0;
	}
    }
  
  /* One or more singletons. */
  else
    {
      if (PyList_Check(data))
	available = PyList_Size(chunk);
      else
	available = 1;
      if (!optformat_from_python(oc, &option->format,
				 &option->format[l], data, available))
	return 0;
    }
  return oc;
}
#endif

/* Local Variables:  */
/* mode:C++ */
/* c-file-style:"gnu" */
/* end: */
