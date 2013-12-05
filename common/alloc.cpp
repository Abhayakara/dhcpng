/* alloc.cpp
 *
 * Memory allocation...
 */

/* Copyright (c) 2005, 2006 Nominum, Inc.   All rights reserved.
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
"$Id: alloc.cpp,v 1.3 2006/05/12 21:51:35 mellon Exp $ Copyright (c) 2005-2006 Nominum, Inc.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

void *safemalloc(size_t len)
{
  char *s = (char *)malloc(len);
  if (!s)
    log_fatal("out of memory");
  memset(s, 0, len);
  return s;
}

struct buffer *buffer_allocate (unsigned len)
{
  struct buffer *bp;

  bp = (struct buffer *)safemalloc(len + sizeof *bp);
  bp->size = len;
  return bp;
}

/* Make a copy of the data in data_string, upping the buffer reference
   count if there's a buffer. */

void data_string_copy (struct data_string *dest, struct data_string *src)
{
  dest->buffer = src->buffer;
  dest->data = src->data;
  dest->terminated = src->terminated;
  dest->len = src->len;
}

/* Release the reference count to a data string's buffer (if any) and
   zero out the other information, yielding the null data string. */

void data_string_forget (struct data_string *data)
{
  memset(data, 0, sizeof *data);
}

/* Make a copy of the data in data_string, upping the buffer reference
   count if there's a buffer. */

void data_string_truncate(struct data_string *dp, unsigned len)
{
  if (len < dp->len)
    {
      dp->terminated = 0;
      dp->len = len;
    }
}

struct dns_host_entry *dns_host_entry_allocate(const char *hostname)
{
  struct dns_host_entry *bp;

  bp = (struct dns_host_entry *)safemalloc(strlen (hostname) + sizeof *bp);
  memset (bp, 0, sizeof *bp);
  strcpy (bp -> hostname, hostname);
  return bp;
}

struct option_state *new_option_state()
{
  struct option_state *nv;
  int size = sizeof *nv + option_space_count * sizeof (void *);
  
  nv = (struct option_state *)safemalloc(size);
  memset(nv, 0, size);
  nv->option_space_count = option_space_count;

  return nv;
}

struct option_cache *make_const_option_cache(struct buffer **buffer,
					     u_int8_t *data,
					     unsigned len,
					     struct option *option)
{
  struct buffer *bp;
  struct option_cache *oc;

  if (buffer)
    {
      bp = *buffer;
      *buffer = 0;
    }
  else
    {
      bp = buffer_allocate(len);
    }

  oc = (struct option_cache *)safemalloc(sizeof *oc);
  oc->data.len = len;
  oc->data.buffer = bp;
  oc->data.data = &bp->data [0];
  oc->data.terminated = 0;
  if (data)
    memcpy (&bp->data [0], data, len);
  oc->option = option;
  return oc;
}

pair cons(caddr_t car, pair cdr)
{
  pair foo = (pair)safemalloc(sizeof *foo);
  foo->car = car;
  foo->cdr = cdr;
  return foo;
}

/* Local Variables:  */
/* mode:C++ */
/* c-file-style:"gnu" */
/* end: */
