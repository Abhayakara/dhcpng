/* hash.cpp
 *
 * Routines for manipulating hash tables...
 */

/* Copyright (c) 2005, 2006 Nominum, Inc.   All rights reserved.
 *
 * Copyright (c) 1995-2001 Internet Software Consortium.
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
static char copyright[] __attribute__((unused)) =
  "$Id: hash.cpp,v 1.2 2006/05/12 21:51:35 mellon Exp $ Copyright (c) 2005-2006 Nominum, Inc.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"
#include <ctype.h>

static int do_hash (const unsigned char *, unsigned, unsigned);
static int do_case_hash (const unsigned char *, unsigned, unsigned);

int new_hash_table (struct hash_table **tp, int count)
{
  struct hash_table *rval;

  rval = (struct hash_table *)
    safemalloc(sizeof (struct hash_table) - (DEFAULT_HASH_SIZE *
					     sizeof (struct hash_bucket *)) +
	       count * sizeof (struct hash_bucket *));
  if (!rval)
    return 0;
  rval->hash_count = count;
  *tp = rval;
  return 1;
}

struct hash_bucket *free_hash_buckets;

struct hash_bucket *new_hash_bucket()
{
  struct hash_bucket *rval;
  int i = 0;
  if (!free_hash_buckets)
    {
      rval = (struct hash_bucket *)safemalloc(127 *
					      sizeof (struct hash_bucket));
      for (; i < 127; i++)
	{
	  rval->next = free_hash_buckets;
	  free_hash_buckets = rval;
	  rval++;
	}
    }
  rval = free_hash_buckets;
  free_hash_buckets = rval->next;
  return rval;
}

void free_hash_bucket (struct hash_bucket *ptr)
{
  ptr->next = free_hash_buckets;
  free_hash_buckets = ptr;
}

int new_hash (struct hash_table **rp,
	      int casep)
{
  if (!new_hash_table (rp, DEFAULT_HASH_SIZE))
    return 0;
  memset (&(*rp)->buckets [0], 0,
	  DEFAULT_HASH_SIZE * sizeof (struct hash_bucket *));
  if (casep)
    {
      (*rp)->cmp = casecmp;
      (*rp)->do_hash = do_case_hash;
    }
  else
    {
      (*rp)->cmp = (hash_comparator_t)memcmp;
      (*rp)->do_hash = do_hash;
    }
  return 1;
}

static int do_case_hash (const unsigned char *name,
			 unsigned len,
			 unsigned size)
{
  register int accum = 0;
  register const unsigned char *s = (const unsigned char *)name;
  int i = len;
  register unsigned c;

  while (i--)
    {
      /* Make the hash case-insensitive. */
      c = *s++;
      if (isascii (c) && isupper (c))
	c = tolower (c);

      /* Add the character in... */
      accum = (accum << 1) + c;

      /* Add carry back in... */
      while (accum > 65535)
	{
	  accum = (accum & 65535) + (accum >> 16);
	}
    }
  return accum % size;
}

static int do_hash (const unsigned char *name,
		    unsigned len,
		    unsigned size)
{
  register int accum = 0;
  register const unsigned char *s = (const unsigned char *)name;
  int i = len;

  while (i--)
    {
      /* Add the character in... */
      accum = (accum << 1) + *s++;

      /* Add carry back in... */
      while (accum > 65535)
	{
	  accum = (accum & 65535) + (accum >> 16);
	}
    }
  return accum % size;
}

void add_hash (struct hash_table *table, 
	       const unsigned char *name,
	       unsigned len,
	       hashed_object_t *pointer)
{
  int hashno;
  struct hash_bucket *bp;

  if (!table)
    return;

  if (!len)
    len = strlen((const char *)name);

  hashno = (*table->do_hash)(name, len, table->hash_count);
  bp = new_hash_bucket();

  if (!bp)
    {
      log_error ("Can't add %s to hash table.", name);
      return;
    }
  bp->name = name;
  bp->value = pointer;
  bp->next = table->buckets [hashno];
  bp->len = len;
  table->buckets [hashno] = bp;
}

void delete_hash_entry (struct hash_table *table,
			const unsigned char *name,
			unsigned len)
{
  int hashno;
  struct hash_bucket *bp, *pbp = (struct hash_bucket *)0;

  if (!table)
    return;

  if (!len)
    len = strlen ((const char *)name);

  hashno = (*table->do_hash) (name, len, table->hash_count);

  /* Go through the list looking for an entry that matches;
     if we find it, delete it. */
  for (bp = table->buckets [hashno]; bp; bp = bp->next)
    {
      if ((!bp->len &&
	   !strcmp ((const char *)bp->name, (const char *)name)) ||
	  (bp->len == len &&
	   !(*table->cmp) (bp->name, name, len)))
	{
	  if (pbp)
	    {
	      pbp->next = bp->next;
	    } else {
	    table->buckets [hashno] = bp->next;
	  }
	  free_hash_bucket (bp);
	  break;
	}
      pbp = bp;	/* jwg, 9/6/96 - nice catch! */
    }
}

int hash_lookup(hashed_object_t **vp,
		struct hash_table *table,
		const unsigned char *name,
		unsigned len)
{
  int hashno;
  struct hash_bucket *bp;

  if (!table)
    return 0;
  if (!len)
    len = strlen((const char *)name);

  hashno = (*table->do_hash) (name, len, table->hash_count);

  for (bp = table->buckets [hashno]; bp; bp = bp->next)
    {
      if (len == bp->len && !(*table->cmp)(bp->name, name, len))
	{
	  *vp = bp->value;
	  return 1;
	}
    }
  return 0;
}

int hash_foreach(struct hash_table *table, hash_foreach_func func)
{
  unsigned i;
  struct hash_bucket *bp, *next;
  int count = 0;

  if (!table)
    return 0;

  for (i = 0; i < table->hash_count; i++)
    {
      bp = table->buckets [i];
      while (bp)
	{
	  next = bp->next;
	  (*func) (bp->name, bp->len, bp->value);
	  bp = next;
	  count++;
	}
    }
  return count;
}

int casecmp (const void *v1, const void *v2, unsigned long len)
{
  unsigned i;
  const char *s = (const char *)v1;
  const char *t = (const char *)v2;
	
  for (i = 0; i < len; i++)
    {
      int c1, c2;
      if (isascii (s [i]) && isupper (s [i]))
	c1 = tolower (s [i]);
      else
	c1 = s [i];
		
      if (isascii (t [i]) && isupper (t [i]))
	c2 = tolower (t [i]);
      else
	c2 = t [i];
		
      if (c1 < c2)
	return -1;
      if (c1 > c2)
	return 1;
    }
  return 0;
}

/* Local Variables:  */
/* mode:C++ */
/* c-file-style:"gnu" */
/* end: */
