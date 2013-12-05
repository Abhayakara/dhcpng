/* print.cpp
 *
 * Turn data structures into printable text.
 */

/* Copyright (c) 2005, 2006 Nominum, Inc.   All rights reserved.
 *
 * Copyright (c) 1995-2003 Internet Software Consortium.
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
  "$Id: print.cpp,v 1.4 2009/09/19 21:53:27 mellon Exp $ Copyright (c) 2005-2006 Nominum, Inc.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

char *quotify_string (const char *s)
{
  unsigned len = 0;
  const char *sp;
  char *buf, *nsp;

  for (sp = s; sp && *sp; sp++)
    {
      if (*sp == ' ')
	len++;
      else if (!isascii (*sp) || !isprint (*sp))
	len += 4;
      else if (*sp == '"' || *sp == '\\')
	len += 2;
      else
	len++;
    }

  buf = (char *)safemalloc(len + 1);
  nsp = buf;
  for (sp = s; sp && *sp; sp++)
    {
      if (*sp == ' ')
	*nsp++ = ' ';
      else if (!isascii (*sp) || !isprint (*sp))
	{
	  sprintf (nsp, "\\%03o",
		   *(const unsigned char *)sp);
	  nsp += 4;
	} else if (*sp == '"' || *sp == '\\')
	{
	  *nsp++ = '\\';
	  *nsp++ = *sp;
	} else
	*nsp++ = *sp;
    }
  *nsp++ = 0;
  return buf;
}

char *quotify_buf (const unsigned char *s, unsigned len)
{
  unsigned nulen = 0;
  char *buf, *nsp;
  unsigned i;

  for (i = 0; i < len; i++)
    {
      if (s [i] == ' ')
	nulen++;
      else if (!isascii (s [i]) || !isprint (s [i]))
	nulen += 4;
      else if (s [i] == '"' || s [i] == '\\')
	nulen += 2;
      else
	nulen++;
    }

  buf = (char *)safemalloc(nulen + 1);
  if (buf)
    {
      nsp = buf;
      for (i = 0; i < len; i++)
	{
	  if (s [i] == ' ')
	    *nsp++ = ' ';
	  else if (!isascii (s [i]) || !isprint (s [i]))
	    {
	      sprintf (nsp, "\\%03o", s [i]);
	      nsp += 4;
	    }
	  else if (s [i] == '"' || s [i] == '\\')
	    {
	      *nsp++ = '\\';
	      *nsp++ = s [i];
	    }
	  else
	    *nsp++ = s [i];
	}
      *nsp++ = 0;
    }
  return buf;
}

char *print_base64 (const unsigned char *buf, unsigned len)
{
  char *s, *b;
  unsigned bl;
  unsigned i;
  unsigned val, extra;
  static char to64 [] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  bl = ((len * 4 + 2) / 3) + 1;
  b = (char *)safemalloc(bl + 1);
  if (!b)
    return (char *)0;
	
  i = 0;
  s = b;
  while (i != len)
    {
      val = buf [i++];
      extra = val & 3;
      val = val >> 2;
      *s++ = to64 [val];
      if (i == len)
	{
	  *s++ = to64 [extra << 4];
	  *s++ = '=';
	  break;
	}
      val = (extra << 8) + buf [i++];
      extra = val & 15;
      val = val >> 4;
      *s++ = to64 [val];
      if (i == len)
	{
	  *s++ = to64 [extra << 2];
	  *s++ = '=';
	  break;
	}
      val = (extra << 8) + buf [i++];
      extra = val & 0x3f;
      val = val >> 6;
      *s++ = to64 [val];
      *s++ = to64 [extra];
    }
  if (!len)
    *s++ = '=';
  *s++ = 0;
  if (s > b + bl + 1)
    abort ();
  return b;
}

char *print_hw_addr (int htype,
		     int hlen,
		     unsigned char *data)
{
  static char habuf [49];
  char *s;
  int i;

  if (hlen <= 0)
    habuf [0] = 0;
  else
    {
      s = habuf;
      for (i = 0; i < hlen; i++)
	{
	  sprintf (s, "%02x", data [i]);
	  s += strlen (s);
	  *s++ = ':';
	}
      *--s = 0;
    }
  return habuf;
}

#if defined (DEBUG_PACKET)
void dump_packet_option (struct option_cache *oc,
			 struct option_state *options,
			 struct universe *u, void *foo)
{
  const char *name, *dot;
  struct data_string ds;
  memset (&ds, 0, sizeof ds);

  if (u != &dhcp_universe)
    {
      name = u->name;
      dot = ".";
    }
  else
    {
      name = "";
      dot = "";
    }
  log_debug("  option %s%s%s %s;\n",
	    name, dot, oc->option->name,
	    pretty_print_option(oc->option,
				oc->data.data, oc->data.len, 1, 1));
}

void dump_packet (tp)
  struct packet *tp;
{
  struct dhcp_packet *tdp = tp->raw;

  log_debug ("packet length %d", tp->packet_length);
  log_debug ("op = %d  htype = %d  hlen = %d  hops = %d",
	     tdp->op, tdp->htype, tdp->hlen, tdp->hops);
  log_debug ("xid = %x  secs = %ld  flags = %x",
	     tdp->xid, (unsigned long)tdp->secs, tdp->flags);
  log_debug ("ciaddr = %s", inet_ntoa (tdp->ciaddr));
  log_debug ("yiaddr = %s", inet_ntoa (tdp->yiaddr));
  log_debug ("siaddr = %s", inet_ntoa (tdp->siaddr));
  log_debug ("giaddr = %s", inet_ntoa (tdp->giaddr));
  log_debug ("chaddr = %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",
	     ((unsigned char *)(tdp->chaddr)) [0],
	     ((unsigned char *)(tdp->chaddr)) [1],
	     ((unsigned char *)(tdp->chaddr)) [2],
	     ((unsigned char *)(tdp->chaddr)) [3],
	     ((unsigned char *)(tdp->chaddr)) [4],
	     ((unsigned char *)(tdp->chaddr)) [5]);
  log_debug ("filename = %s", tdp->file);
  log_debug ("server_name = %s", tdp->sname);
  if (tp->options_valid)
    {
      int i;

      for (i = 0; i < tp->options->universe_count; i++)
	{
	  if (tp->options->universes [i])
	    {
	      option_space_foreach (tp, (struct lease *)0,
				    (struct client_state *)0,
				    (struct option_state *)0,
				    tp->options,
				    &global_scope,
				    universes [i], 0,
				    dump_packet_option);
	    }
	}
    }
  log_debug ("%s", "");
}
#endif

void dump_raw (const unsigned char *buf,
	       unsigned len)
{
  unsigned i;
  char lbuf [80];
  int lbix = 0;

  /*
    1         2         3         4         5         6         7
    01234567890123456789012345678901234567890123456789012345678901234567890123
    280: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   .................  
  */

  memset(lbuf, ' ', 79);
  lbuf [79] = 0;

  for (i = 0; i < len; i++)
    {
      if ((i & 15) == 0)
	{
	  if (lbix)
	    {
	      lbuf[53]=' ';
	      lbuf[54]=' ';
	      lbuf[55]=' ';
	      lbuf[73]='\0';
	      log_info ("%s", lbuf);
	    }
	  memset(lbuf, ' ', 79);
	  lbuf [79] = 0;
	  sprintf (lbuf, "%03x:", i);
	  lbix = 4;
	}
      else if ((i & 7) == 0)
	lbuf [lbix++] = ' ';

      if (isprint(buf[i]))
	{
	  lbuf[56+(i%16)]=buf[i];
	}
      else
	{
	  lbuf[56+(i%16)]='.';
	}

      sprintf(&lbuf [lbix], " %02x", buf [i]);
      lbix += 3;
      lbuf[lbix]=' ';

    }
  lbuf[53]=' ';
  lbuf[54]=' ';
  lbuf[55]=' ';
  lbuf[73]='\0';
  log_info ("%s", lbuf);
}

#define HBLEN 60

#define DECLARE_HEX_PRINTER(x)						\
char *print_hex##x (unsigned len,					\
		    const u_int8_t *data,				\
		    unsigned limit)					\
{									\
  static char hex_buf##x [HBLEN + 1];					\
  unsigned i;								\
  									\
  if (limit > HBLEN)							\
    limit = HBLEN;							\
  									\
  for (i = 0; i < (limit - 2) && i < len; i++)				\
    {									\
      if (!isascii (data [i]) || !isprint (data [i]))			\
	{								\
	  for (i = 0; i < limit / 3 && i < len; i++)			\
	    {								\
	      sprintf (&hex_buf##x [i * 3],				\
		       "%02x:", data [i]);				\
	    }								\
	  hex_buf##x [i * 3 - 1] = 0;					\
	  return hex_buf##x;						\
	}								\
    }									\
  hex_buf##x [0] = '"';							\
  i = len;								\
  if (i > limit - 2)							\
    i = limit - 2;							\
  memcpy (&hex_buf##x [1], data, i);					\
  hex_buf##x [i + 1] = '"';						\
  hex_buf##x [i + 2] = 0;						\
  return hex_buf##x;							\
}

DECLARE_HEX_PRINTER (_1)
DECLARE_HEX_PRINTER (_2)
DECLARE_HEX_PRINTER (_3)

#define DQLEN	80

char *print_dotted_quads (unsigned len,
			  const u_int8_t *data)
{
  static char dq_buf [DQLEN + 1];
  unsigned i;
  char *s, *last;

  s = &dq_buf [0];
  last = s;
	
  i = 0;

  do {
    sprintf (s, "%d.%d.%d.%d, ",
	     data [i], data [i + 1], data [i + 2], data [i + 3]);
    s += strlen(s);
    i += 4;
  } while ((s - &dq_buf [0] > DQLEN - 21) && i + 3 < len);
  if (i == len)
    s [-2] = 0;
  else
    strcpy (s, "...");
  return dq_buf;
}

char *print_dec_1 (unsigned long val)
{
  static char vbuf [32];
  sprintf (vbuf, "%lu", val);
  return vbuf;
}

char *print_dec_2 (unsigned long val)
{
  static char vbuf [32];
  sprintf (vbuf, "%lu", val);
  return vbuf;
}

int token_print_indent_concat (FILE *file, int col,  int indent,
			       const char *prefix, 
			       const char *suffix, ...)
{
  va_list list;
  unsigned len;
  char *s, *t, *u;

  va_start (list, suffix);
  s = va_arg (list, char *);
  len = 0;
  while (s)
    {
      len += strlen (s);
      s = va_arg (list, char *);
    }
  va_end (list);

  t = (char *)safemalloc(len + 1);
  if (!t)
    log_fatal ("token_print_indent: no memory for copy buffer");

  va_start (list, suffix);
  s = va_arg (list, char *);
  u = t;
  while (s)
    {
      len = strlen (s);
      strcpy (u, s);
      u += len;
    }
  va_end (list);
	
  len = token_print_indent (file, col, indent,
			    prefix, suffix, t);
  return col;
}

int token_indent_data_string (FILE *file, int col, int indent,
			      const char *prefix, const char *suffix,
			      struct data_string *data)
{
  unsigned i;
  char obuf [3];

  /* See if this is just ASCII. */
  for (i = 0; i < data->len; i++)
    if (!isascii (data->data [i]) ||
	!isprint (data->data [i]))
      break;

  /* If we have a purely ASCII string, output it as text. */
  if (i == data->len)
    {
      char *buf = (char *)safemalloc(data->len + 3);
      buf [0] = '"';
      memcpy (buf + 1, data->data, data->len);
      buf [data->len + 1] = '"';
      buf [data->len + 2] = 0;
      i = token_print_indent (file, col, indent,
			      prefix, suffix, buf);
      return i;
    }

  for (i = 0; i < data->len; i++)
    {
      sprintf (obuf, "%2.2x", data->data [i]);
      col = token_print_indent (file, col, indent,
				i == 0 ? prefix : "",
				(i + 1 == data->len
				 ? suffix
				 : ""), obuf);
      if (i + 1 != data->len)
	col = token_print_indent (file, col, indent,
				  prefix, suffix, ":");
    }
  return col;
}

int token_print_indent (FILE *file, int col, int indent,
			const char *prefix,
			const char *suffix, const char *buf)
{
  int len = strlen (buf) + strlen (prefix);
  if (col + len > 79)
    {
      if (indent + len < 79)
	{
	  indent_spaces (file, indent);
	  col = indent;
	}
      else
	{
	  indent_spaces (file, col);
	  col = len > 79 ? 0 : 79 - len - 1;
	}
    }
  else if (prefix && *prefix)
    {
      fputs (prefix, file);
      col += strlen (prefix);
    }
  fputs (buf, file);
  col += len;
  if (suffix && *suffix)
    {
      if (col + strlen (suffix) > 79)
	{
	  indent_spaces (file, indent);
	  col = indent;
	}
      else
	{
	  fputs (suffix, file);
	  col += strlen (suffix);
	}
    }
  return col;
}

void indent_spaces (FILE *file, int indent)
{
  int i;
  fputc ('\n', file);
  for (i = 0; i < indent; i++)
    fputc (' ', file);
}

/* Local Variables:  */
/* mode:C++ */
/* c-file-style:"gnu" */
/* end: */
