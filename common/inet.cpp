/* inet.c
 *
 * Subroutines to manipulate internet addresses in a safely portable
 * way...
 */

/* Copyright (c) 2002-2006 Nominum, Inc.   All rights reserved.
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
static char copyright[] __attribute__((unused)) =
  "$Id: inet.cpp,v 1.2 2006/05/12 21:51:35 mellon Exp $ Copyright (c) 2005-2006 Nominum, Inc.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

/* Return just the network number of an internet address... */

struct iaddr subnet_number (struct iaddr addr,
			    struct iaddr mask)
{
  unsigned i;
  struct iaddr rv;

  rv.len = 0;

  /* Both addresses must have the same length... */
  if (addr.len != mask.len)
    return rv;

  rv.len = addr.len;
  for (i = 0; i < rv.len; i++)
    rv.iabuf [i] = addr.iabuf [i] & mask.iabuf [i];
  return rv;
}

/* Combine a network number and a integer to produce an internet address.
   This won't work for subnets with more than 32 bits of host address, but
   maybe this isn't a problem. */

struct iaddr ip_addr (struct iaddr subnet,
		      struct iaddr mask,
		      u_int32_t host_address)
{
  int i, j, k;
  u_int32_t swaddr;
  struct iaddr rv;
  unsigned char habuf [sizeof swaddr];

  swaddr = htonl (host_address);
  memcpy (habuf, &swaddr, sizeof swaddr);

  /* Combine the subnet address and the host address.   If
     the host address is bigger than can fit in the subnet,
     return a zero-length iaddr structure. */
  rv = subnet;
  j = rv.len - sizeof habuf;
  for (i = sizeof habuf - 1; i >= 0; i--)
    {
      if (mask.iabuf [i + j])
	{
	  if (habuf [i] > (mask.iabuf [i + j] ^ 0xFF))
	    {
	      rv.len = 0;
	      return rv;
	    }
	  for (k = i - 1; k >= 0; k--)
	    {
	      if (habuf [k])
		{
		  rv.len = 0;
		  return rv;
		}
	    }
	  rv.iabuf [i + j] |= habuf [i];
	  break;
	} else
	rv.iabuf [i + j] = habuf [i];
    }
		
  return rv;
}

/* Given a subnet number and netmask, return the address on that subnet
   for which the host portion of the address is all ones (the standard
   broadcast address). */

struct iaddr broadcast_addr (struct iaddr subnet,
			     struct iaddr mask)
{
  unsigned i;
  struct iaddr rv;

  if (subnet.len != mask.len)
    {
      rv.len = 0;
      return rv;
    }

  for (i = 0; i < subnet.len; i++)
    {
      rv.iabuf [i] = subnet.iabuf [i] | (~mask.iabuf [i] & 255);
    }
  rv.len = subnet.len;

  return rv;
}

u_int32_t host_addr (struct iaddr addr,
		     struct iaddr mask)
{
  unsigned i;
  u_int32_t swaddr;
  struct iaddr rv;

  rv.len = 0;

  /* Mask out the network bits... */
  rv.len = addr.len;
  for (i = 0; i < rv.len; i++)
    rv.iabuf [i] = addr.iabuf [i] & ~mask.iabuf [i];

  /* Copy out up to 32 bits... */
  memcpy (&swaddr, &rv.iabuf [rv.len - sizeof swaddr], sizeof swaddr);

  /* Swap it and return it. */
  return ntohl (swaddr);
}

int addr_eq (struct iaddr addr1,
	     struct iaddr addr2)
{
  if (addr1.len != addr2.len)
    return 0;
  return memcmp (addr1.iabuf, addr2.iabuf, addr1.len) == 0;
}

char *piaddr (struct iaddr addr)
{
  static char pbuf [4 * 16];
  char *s = pbuf;
  unsigned i;

  if (addr.len == 0)
    {
      strcpy (s, "<null address>");
    }
  for (i = 0; i < addr.len; i++)
    {
      sprintf (s, "%s%d", i ? "." : "", addr.iabuf [i]);
      s += strlen (s);
    }
  return pbuf;
}

char *piaddr1(struct iaddr addr)
{
  static char pbuf [4 * 16];
  char *s = pbuf;
  unsigned i;

  if (addr.len == 0)
    {
      strcpy (s, "<null address>");
    }
  for (i = 0; i < addr.len; i++)
    {
      sprintf (s, "%s%d", i ? "." : "", addr.iabuf [i]);
      s += strlen (s);
    }
  return pbuf;
}

char *piaddrmask(struct iaddr addr,
		 struct iaddr mask)
{
  char *s, *t;
  int i, mw;
  unsigned len;

  for (i = 0; i < 32; i++)
    {
      if (!mask.iabuf [3 - i / 8])
	i += 7;
      else if (mask.iabuf [3 - i / 8] & (1 << (i % 8)))
	break;
    }
  mw = 32 - i;
  len = mw > 9 ? 2 : 1;
  len += 4;	/* three dots and a slash. */
  for (i = 0; i < (mw / 8) + 1; i++)
    {
      if (addr.iabuf [i] > 99)
	len += 3;
      else if (addr.iabuf [i] > 9)
	len += 2;
      else
	len++;
    }
  s = (char *)safemalloc(len + 1);
  if (!s)
    return s;
  t = s;
  sprintf (t, "%d", addr.iabuf [0]);
  t += strlen (t);
  for (i = 1; i < (mw / 8) + 1; i++)
    {
      sprintf (t, ".%d", addr.iabuf [i]);
      t += strlen (t);
    }
  *t++ = '/';
  sprintf (t, "%d", mw);
  return s;
}

/* Local Variables:  */
/* mode:C++ */
/* c-file-style:"gnu" */
/* end: */
