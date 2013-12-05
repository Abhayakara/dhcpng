/* convert.cpp
 *
 * Safe copying of option values into and out of the option buffer, which
 * can't be assumed to be aligned.
 */

/* Copyright (c) 2005, 2006 Nominum, Inc.   All rights reserved.
 *
 * Copyright (c) 1996-1999 Internet Software Consortium.
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
  "$Id: convert.cpp,v 1.3 2007/09/14 23:03:54 mellon Exp $ Copyright (c) 1996-1999 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

u_int32_t getULong (const unsigned char *buf)
{
  u_int32_t ibuf;

  memcpy (&ibuf, buf, sizeof (u_int32_t));
  return ntohl (ibuf);
}

int32_t getLong (const unsigned char *buf)
{
  int32_t ibuf;

  memcpy (&ibuf, buf, sizeof (int32_t));
  return ntohl (ibuf);
}

u_int32_t getUShort (const unsigned char *buf)
{
  unsigned short ibuf;

  memcpy (&ibuf, buf, sizeof (u_int16_t));
  return ntohs (ibuf);
}

int32_t getShort (const unsigned char *buf)
{
  short ibuf;

  memcpy (&ibuf, buf, sizeof (int16_t));
  return ntohs (ibuf);
}

void putULong (unsigned char *obuf, u_int32_t val)
{
  u_int32_t tmp = htonl (val);
  memcpy (obuf, &tmp, sizeof tmp);
}

void putLong (unsigned char *obuf, int32_t val)
{
  int32_t tmp = htonl (val);
  memcpy (obuf, &tmp, sizeof tmp);
}

void putUShort (unsigned char *obuf, u_int32_t val)
{
  u_int16_t tmp = htons (val);
  memcpy (obuf, &tmp, sizeof tmp);
}

void putShort (unsigned char *obuf, int32_t val)
{
  int16_t tmp = htons (val);
  memcpy (obuf, &tmp, sizeof tmp);
}

void putUChar (unsigned char *obuf, u_int32_t val)
{
  *obuf = val;
}

u_int32_t getUChar (const unsigned char *obuf)
{
  return obuf [0];
}

int converted_length (const unsigned char *buf,
		      unsigned int base,
		      unsigned int width)
{
  u_int32_t number = 0;
  u_int32_t column;
  int power = 1;
  u_int32_t newcolumn = base;

  if (base > 16)
    return 0;

  if (width == 1)
    number = getUChar (buf);
  else if (width == 2)
    number = getUShort (buf);
  else if (width == 4)
    number = getULong (buf);

  do {
    column = newcolumn;

    if (number < column)
      return power;
    power++;
    newcolumn = column * base;
    /* If we wrap around, it must be the next power of two up. */
  } while (newcolumn > column);

  return power;
}

int binary_to_ascii (unsigned char *outbuf,
		     const unsigned char *inbuf,
		     unsigned int base,
		     unsigned int width)
{
  u_int32_t number = 0;
  static char h2a [] = "0123456789abcdef";
  int power = converted_length (inbuf, base, width);
  int i;

  if (base > 16)
    return 0;

  if (width == 1)
    number = getUChar (inbuf);
  else if (width == 2)
    number = getUShort (inbuf);
  else if (width == 4)
    number = getULong (inbuf);

  for (i = power - 1 ; i >= 0; i--)
    {
      outbuf [i] = h2a [number % base];
      number /= base;
    }

  return power;
}

/* Local Variables:  */
/* mode:C++ */
/* c-file-style:"gnu" */
/* end: */
