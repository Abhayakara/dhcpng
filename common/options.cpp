/* options.cpp
 *
 * DHCP options parsing and reassembly.
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
  "$Id: options.cpp,v 1.7 2007/09/14 23:06:44 mellon Exp $ Copyright (c) 2005-2006 Nominum, Inc.  All rights reserved.\n";
#endif /* not lint */

#define DHCP_OPTION_DATA
#include "dhcpd.h"
#include "client/v4client.h"

struct option *vendor_cfg_option;

/* Parse all available options out of the specified packet. */

int parse_options (struct packet *packet)
{
  struct option_cache *op = (struct option_cache *)0;

  /* Allocate a new option state. */
  packet->options = new_option_state();

  /* If we don't see the magic cookie, there's nothing to parse. */
  if (memcmp (packet->raw->options, DHCP_OPTIONS_COOKIE, 4))
    {
      packet->options_valid = 0;
      return 1;
    }

  /* Go through the options field, up to the end of the packet
     or the End field. */
  if (!parse_option_buffer(packet->options,
			   &packet->raw->options [4],
			   (packet->packet_length - DHCP_FIXED_NON_UDP - 4),
			   &dhcp_option_space))
    return 0;

  /* If we parsed a DHCP Option Overload option, parse more
     options out of the buffer(s) containing them. */
  if (packet->options_valid &&
      (op = lookup_option(&dhcp_option_space, packet->options,
			  DHO_DHCP_OPTION_OVERLOAD)))
    {
      if (op->data.data [0] & 1)
	{
	  if (!parse_option_buffer(packet->options,
				   (unsigned char *)packet->raw->file,
				   sizeof packet->raw->file,
				   &dhcp_option_space))
	    return 0;
	}
      if (op->data.data [0] & 2)
	{
	  if (!parse_option_buffer(packet->options,
				   (unsigned char *)packet->raw->sname,
				   sizeof packet->raw->sname,
				   &dhcp_option_space))
	    return 0;
	}
    }
  packet->options_valid = 1;
  return 1;
}

/* Parse options out of the specified buffer, storing addresses of option
   values in packet->options and setting packet->options_valid if no
   errors are encountered. */

int parse_option_buffer (struct option_state *options,
			 const unsigned char *buffer,
			 unsigned length,
			 struct option_space *option_space)
{
  unsigned len, offset;
  unsigned code;
  struct option_cache *op = (struct option_cache *)0;
  struct buffer *bp = (struct buffer *)0;
  struct option *opt = (struct option *)0;

  bp = buffer_allocate(length);
  memcpy (bp->data, buffer, length);
	
  for (offset = 0; buffer [offset] != DHO_END && offset < length; )
    {
      code = buffer [offset];
      /* Pad options don't have a length - just skip them. */
      if (code == DHO_PAD)
	{
	  ++offset;
	  continue;
	}

      /* Don't look for length if the buffer isn't that big. */
      if (offset + 2 > length)
	{
	  len = 65536;
	  goto bogus;
	}

      /* All other fields (except end, see above) have a
	 one-byte length. */
      len = buffer [offset + 1];

      /* If the length is outrageous, the options are bad. */
      if (offset + len + 2 > length)
	{
	bogus:
	  log_error ("parse_option_buffer: option %s.%s (%d) "
		     "larger than buffer.",
		     option_space->name, opt->name, len);
	  return 0;
	}

      /* If the option contains an encapsulation, parse it.   If
	 the parse fails, or the option isn't an encapsulation (by
	 far the most common case), or the option isn't entirely
	 an encapsulation, keep the raw data as well. */
      opt = find_option(option_space, code);
      if (opt &&
	  !((opt->format [0] == 'e' || opt->format [0] == 'E') &&
	    parse_encapsulated_suboptions(options, opt,
					  buffer + offset + 2, len,
					  option_space, (const char *)0)))
	{
	  op = lookup_option(option_space, options, code);
	  if (op)
	    {
	      struct data_string nouveau;
	      memset (&nouveau, 0, sizeof nouveau);
	      nouveau.buffer = buffer_allocate(op->data.len + len);
	      memcpy (nouveau.buffer->data, op->data.data,
		      op->data.len);
	      memcpy (&nouveau.buffer->data [op->data.len],
		      &bp->data [offset + 2], len);
	      nouveau.len = op->data.len + len;
	      nouveau.data = nouveau.buffer->data;
	      data_string_forget (&op->data);
	      data_string_copy (&op->data, &nouveau);
	      data_string_forget (&nouveau);
	    }
	  else
	    {
	      save_option_buffer (option_space, options, bp,
				  &bp->data [offset + 2], len, opt, 1);
	    }
	}
      offset += len + 2;
    }
  return 1;
}

/* If an option in an option buffer turns out to be an encapsulation,
   figure out what to do.   If we don't know how to de-encapsulate it,
   or it's not well-formed, return zero; otherwise, return 1, indicating
   that we succeeded in de-encapsulating it. */

struct option_space *find_option_option_space (struct option *eopt,
					       const char *uname)
{
  int i;
  char *s;
  struct option_space *option_space = (struct option_space *)0;

  /* Look for the E option in the option format. */
  s = strchr (eopt->format, 'E');
  if (!s)
    {
      log_error ("internal encapsulation format error 1.");
      return 0;
    }

  if (strlen(s) && uname)
    {
      for (i = 0; i < option_space_count; i++)
	{
	  if (!strcmp (option_spaces [i]->name, uname))
	    {
	      option_space = option_spaces [i];
	      break;
	    }
	}
    }
  else if (strlen(s))
    {
      for (i = 0; i < option_space_count; i++)
	{
	  if (!strcmp(option_spaces[i]->name, s))
	    {
	      option_space = option_spaces [i];
	      break;
	    }
	}
    }
  return option_space;
}

/* If an option in an option buffer turns out to be an encapsulation,
   figure out what to do.   If we don't know how to de-encapsulate it,
   or it's not well-formed, return zero; otherwise, return 1, indicating
   that we succeeded in de-encapsulating it. */

int parse_encapsulated_suboptions (struct option_state *options,
				   struct option *eopt,
				   const unsigned char *buffer,
				   unsigned len, struct option_space *eu,
				   const char *uname)
{
  int i;
  struct option_space *option_space =
    find_option_option_space(eopt, uname);

  /* If we didn't find the option_space, we can't do anything with it
     right now (e.g., we can't decode vendor options until we've
     decoded the packet and executed the scopes that it matches). */
  if (!option_space)
    return 0;
		
  /* Decode the option space. */
  i = decode_option_space(options, buffer, len, option_space);

  /* If there is stuff before the suboptions, we have to keep it. */
  if (eopt->format [0] != 'E')
    return 0;
  /* Otherwise, return the status of the decode function. */
  return i;
}

int
decode_option_space(struct option_state *options, const unsigned char *buffer,
		    unsigned len, struct option_space *option_space)
{
  /* If we don't have a decoding function for it, we can't decode
     it. */
  if (!option_space->decode)
    return 0;

  return (*option_space->decode) (options, buffer, len, option_space);
}

int fqdn_option_space_decode(struct option_state *options,
			     const unsigned char *buffer,
			     unsigned length, struct option_space *u)
{
  struct buffer *bp = (struct buffer *)0;

  /* XXX: Note that all the calls to find_option below assume that it
     XXX: returns nonzero.   This is a safe assumption because we are
     XXX: only looking up predefined options. */

  /* FQDN options have to be at least four bytes long. */
  if (length < 3)
    return 0;

  /* Save the contents of the option in a buffer. */
  bp = buffer_allocate(length + 4);
  memcpy (&bp->data [3], buffer + 1, length - 1);

  if (buffer [0] & 4)	/* encoded */
    bp->data [0] = 1;
  else
    bp->data [0] = 0;
  save_option_buffer (&fqdn_option_space, options, bp,
		      &bp->data [0], 1,
		      find_option(&fqdn_option_space, FQDN_ENCODED), 0);
	
  if (buffer [0] & 1)	/* server-update */
    bp->data [2] = 1;
  else
    bp->data [2] = 0;
  if (buffer [0] & 2)	/* no-client-update */
    bp->data [1] = 1;
  else
    bp->data [1] = 0;

  /* XXX Ideally we should store the name in DNS format, so if the
     XXX label isn't in DNS format, we convert it to DNS format,
     XXX rather than converting labels specified in DNS format to
     XXX the plain ASCII representation.   But that's hard, so
     XXX not now. */

  /* Not encoded using DNS format? */
  if (!bp->data [0])
    {
      unsigned i;

      /* Some broken clients NUL-terminate this option. */
      if (buffer [length - 1] == 0)
	{
	  --length;
	  bp->data [1] = 1;
	}

      /* Determine the length of the hostname component of the
	 name.  If the name contains no '.' character, it
	 represents a non-qualified label. */
      for (i = 3; i < length && buffer [i] != '.'; i++);
      i -= 3;

      /* Note: If the client sends a FQDN, the first '.' will
	 be used as a NUL terminator for the hostname. */
      if (i)
	{
	  save_option_buffer (&fqdn_option_space, options, bp,
			      &bp->data[5], i,
			      find_option(&fqdn_option_space,
					  FQDN_HOSTNAME), 0);
	}

      /* Note: If the client sends a single label, the
	 FQDN_DOMAINNAME option won't be set. */
      if (length > 4 + i)
	{
	  save_option_buffer(&fqdn_option_space, options, bp,
			     &bp->data[6 + i], length - 4 - i,
			     find_option(&fqdn_option_space,
					 FQDN_DOMAINNAME), 1);
	}

      /* Also save the whole name. */
      if (length > 3)
	{
	  save_option_buffer (&fqdn_option_space, options, bp,
			      &bp->data [5], length - 3,
			      find_option(&fqdn_option_space,
					  FQDN_FQDN), 1);
	}
    }
  else
    {
      unsigned len;
      unsigned total_len = 0;
      unsigned first_len = 0;
      int terminated = 0;
      unsigned char *s;

      s = &bp->data[5];

      while (s < &bp->data[0] + length + 2)
	{
	  len = *s;
	  if (len > 63)
	    {
	      log_info ("fancy bits in fqdn option");
	      return 0;
	    }	
	  if (len == 0)
	    {
	      terminated = 1;
	      break;
	    }
	  if (s + len > &bp->data [0] + length + 3)
	    {
	      log_info ("fqdn tag longer than buffer");
	      return 0;
	    }

	  if (first_len == 0)
	    {
	      first_len = len;
	    }

	  *s = '.';
	  s += len + 1;
	  total_len += len + 1;
	}

      /* We wind up with a length that's one too many because
	 we shouldn't increment for the last label, but there's
	 no way to tell we're at the last label until we exit
	 the loop.   :'*/
      if (total_len > 0)
	total_len--;

      if (!terminated)
	{
	  first_len = total_len;
	}

      if (first_len > 0)
	{
	  save_option_buffer(&fqdn_option_space, options, bp,
			     &bp->data[6], first_len,
			     find_option(&fqdn_option_space,
					 FQDN_HOSTNAME), 0);
	}
      if (total_len > 0 && first_len != total_len)
	{
	  save_option_buffer(&fqdn_option_space, options, bp,
			     &bp->data[6 + first_len],
			     total_len - first_len,
			     find_option(&fqdn_option_space,
					 FQDN_DOMAINNAME), 1);
	}
      if (total_len > 0)
	{
	  save_option_buffer (&fqdn_option_space, options, bp,
			      &bp->data [6], total_len,
			      find_option(&fqdn_option_space,
					  FQDN_FQDN), 1);
	}
    }

  save_option_buffer(&fqdn_option_space, options, bp,
		     &bp->data [1], 1,
		     find_option(&fqdn_option_space,
				 FQDN_NO_CLIENT_UPDATE), 0);
  save_option_buffer(&fqdn_option_space, options, bp,
		     &bp->data [2], 1,
		     find_option(&fqdn_option_space,
				 FQDN_SERVER_UPDATE), 0);
  save_option_buffer(&fqdn_option_space, options, bp,
		     &bp->data [3], 1,
		     find_option(&fqdn_option_space, FQDN_RCODE1), 0);
  save_option_buffer(&fqdn_option_space, options, bp,
		     &bp->data [4], 1,
		     find_option(&fqdn_option_space, FQDN_RCODE2), 0);
  return 1;
}

/* Parse options out of the specified buffer, storing addresses of option
   values in packet->options and setting packet->options_valid if no
   errors are encountered.   The option buffer contains options represented
   as a two-byte code followed by a two-byte length. */

int parse_twobyte_option_buffer (struct option_state *options,
				 const unsigned char *buffer,
				 unsigned length,
				 struct option_space *option_space)
{
  unsigned len, offset;
  unsigned code;
  struct buffer *bp = (struct buffer *)0;
  struct option *opt = (struct option *)0;

  bp = buffer_allocate(length);
  memcpy (bp->data, buffer, length);
	
  for (offset = 0; offset < length; )
    {
      code = getUShort(&buffer[offset]);

      /* Don't look for length if the buffer isn't that big. */
      if (offset + 2 > length)
	{
	  len = 65536;
	  goto bogus;
	}

      /* Get the option definition. */
      opt = find_option(option_space, code);

      /* All other fields (except end, see above) have a
	 one-byte length. */
      len = getUShort(&buffer[offset + 2]);

      /* If the length is outrageous, the options are bad. */
      if (offset + len + 2 > length)
	{
	bogus:
	  log_error ("parse_twobyte_option_buffer: "
		     "option %s.%s (%d) larger than buffer.",
		     option_space->name,
		     opt ? opt->name : "unknown", len);
	  return 0;
	}

      /* I've cut out the code to parse encapsulations here
       * because it can only work in cases where the encapsulation
       * starts at the beginning of the option, and in general IPv6
       * encapsulations need to be handled differently anyway.
       */
#if 0
      /* If the option contains an encapsulation, parse it.   If
	 the parse fails, or the option isn't an encapsulation (by
	 far the most common case), or the option isn't entirely
	 an encapsulation, keep the raw data as well. */
      if (opt &&
	  !((opt->format [0] == 'e' || opt->format [0] == 'E') &&
	    (parse_encapsulated_suboptions
	     (options, opt, buffer + offset + 4, len,
	      option_space, (const char *)0))))
	{
	  struct option_cache *op = lookup_option(option_space,
						  options, code);
	  if (op)
	    {
	      struct data_string nouveau;
	      memset (&nouveau, 0, sizeof nouveau);
	      nouveau.buffer = buffer_allocate(op->data.len + len);
	      memcpy (nouveau.buffer->data, op->data.data,
		      op->data.len);
	      memcpy (&nouveau.buffer->data [op->data.len],
		      &bp->data [offset + 2], len);
	      nouveau.len = op->data.len + len;
	      nouveau.data = nouveau.buffer->data;
	      data_string_forget (&op->data);
	      data_string_copy (&op->data, &nouveau);
	      data_string_forget (&nouveau);
	    }
	}
#endif

      save_option_buffer (option_space, options, bp,
			  &bp->data[offset + 4], len, opt, 1);
      offset += len + 4;
    }
  return 1;
}



/* cons options into a big buffer, and then split them out into the
   three seperate buffers if needed.  This allows us to cons up a set
   of vendor options using the same routine. */

int cons_options (struct dhcp_packet *outpacket,
		  int mms,
		  struct option_state *options,
		  int overload,	/* Overload flags that may be set. */
		  int terminate,
		  int bootpp,
		  struct data_string *prl,
		  const char *vuname)
{
#define PRIORITY_COUNT 300
  unsigned priority_list [PRIORITY_COUNT];
  unsigned priority_len;
  unsigned char buffer [4096];	/* Really big buffer... */
  unsigned main_buffer_size;
  unsigned mainbufix, agentix;
  unsigned option_size;
  unsigned length;
  unsigned i;
  struct option_cache *op;
  struct data_string ds;
  pair pp, *hash;
  int need_endopt = 0;
  int ocount = 0;
  unsigned ofbuf1, ofbuf2;

  memset (&ds, 0, sizeof ds);

  /* If the client has provided a maximum DHCP message size,
     use that; otherwise, if it's BOOTP, only 64 bytes; otherwise
     use up to the minimum IP MTU size (576 bytes). */
  /* XXX if a BOOTP client specifies a max message size, we will
     honor it. */

  if (mms)
    {
      main_buffer_size = mms - DHCP_FIXED_LEN;

      /* Enforce a minimum packet size... */
      if (main_buffer_size < (576 - DHCP_FIXED_LEN))
	main_buffer_size = 576 - DHCP_FIXED_LEN;
    }
  else if (bootpp)
    {
      main_buffer_size = 64;
    }
  else
    main_buffer_size = 576 - DHCP_FIXED_LEN;

  /* Set a hard limit at the size of the output buffer. */
  if (main_buffer_size > sizeof buffer)
    main_buffer_size = sizeof buffer;

  /* Preload the option priority list with mandatory options. */
  priority_len = 0;
  priority_list [priority_len++] = DHO_DHCP_MESSAGE_TYPE;
  priority_list [priority_len++] = DHO_DHCP_SERVER_IDENTIFIER;
  priority_list [priority_len++] = DHO_DHCP_LEASE_TIME;
  priority_list [priority_len++] = DHO_DHCP_MESSAGE;
  priority_list [priority_len++] = DHO_DHCP_REQUESTED_ADDRESS;
  priority_list [priority_len++] = DHO_DHCP_RENEWAL_TIME;
  priority_list [priority_len++] = DHO_DHCP_REBINDING_TIME;
  priority_list [priority_len++] = DHO_FQDN;

  if (prl && prl->len > 0)
    {
      if ((op = lookup_option (&dhcp_option_space, options,
			       DHO_SUBNET_SELECTION)))
	{
	  if (priority_len < PRIORITY_COUNT)
	    priority_list [priority_len++] =
	      DHO_SUBNET_SELECTION;
	}
			    
      data_string_truncate (prl, (PRIORITY_COUNT - priority_len));

      for (i = 0; i < prl->len; i++)
	{
	  /* Prevent client from changing order of delivery
	     of relay agent information option. */
	  if (prl->data [i] != DHO_DHCP_AGENT_OPTIONS)
	    priority_list [priority_len++] =
	      prl->data [i];
	}
    }
  else
    {
      /* First, hardcode some more options that ought to be
	 sent first... */
      priority_list [priority_len++] = DHO_SUBNET_MASK;
      priority_list [priority_len++] = DHO_ROUTERS;
      priority_list [priority_len++] = DHO_DOMAIN_NAME_SERVERS;
      priority_list [priority_len++] = DHO_HOST_NAME;

      /* Append a list of the standard DHCP options from the
	 standard DHCP option space.  Actually, if a site
	 option space hasn't been specified, we wind up
	 treating the dhcp option space as the site option
	 space, and the first for loop is skipped, because
	 it's slightly more general to do it this way,
	 taking the 1Q99 DHCP futures work into account. */
      if (options->site_code_min)
	{
	  for (i = 0; i < OPTION_HASH_SIZE; i++)
	    {
	      hash = (pair *)(options->option_spaces[dhcp_option_space.index]);
	      if (hash)
		{
		  for (pp = hash [i]; pp; pp = pp->cdr)
		    {
		      op = (struct option_cache *)(pp->car);
		      if (op->option->code < options->site_code_min &&
			  priority_len < PRIORITY_COUNT &&
			  (op->option->code != DHO_DHCP_AGENT_OPTIONS))
			priority_list [priority_len++] =
			  op->option->code;
		    }
		}
	    }
	}

      /* Now cycle through the site option space, or if there
	 is no site option space, we'll be cycling through the
	 dhcp option space. */
      for (i = 0; i < OPTION_HASH_SIZE; i++)
	{
	  hash = (pair *)(options->option_spaces
			  [options->site_option_space]);
	  if (hash)
	    {
	      for (pp = hash [i]; pp; pp = pp->cdr)
		{
		  op = (struct option_cache *)(pp->car);
		  if (op->option->code >=
		      options->site_code_min &&
		      priority_len < PRIORITY_COUNT &&
		      (op->option->code !=
		       DHO_DHCP_AGENT_OPTIONS))
		    priority_list [priority_len++] =
		      op->option->code;
		}
	    }
	}

      /* Now go through all the option spaces for which options
	 were set and see if there are encapsulations for
	 them; if there are, put the encapsulation options
	 on the priority list as well. */
      for (i = 0; i < options->option_space_count; i++)
	{
	  if (options->option_spaces [i] &&
	      option_spaces[i]->enc_opt &&
	      priority_len < PRIORITY_COUNT &&
	      (option_spaces[i]->enc_opt->option_space == &dhcp_option_space))
	    {
	      if (option_spaces [i]->enc_opt->code !=
		  DHO_DHCP_AGENT_OPTIONS)
		priority_list [priority_len++] =
		  option_spaces [i]->enc_opt->code;
	    }
	}

      /* The vendor option space can't stand on its own, so always
	 add it to the list. */
      if (priority_len < PRIORITY_COUNT)
	priority_list [priority_len++] =
	  DHO_VENDOR_ENCAPSULATED_OPTIONS;
    }

  /* Figure out the overload buffer offset(s). */
  if (overload)
    {
      ofbuf1 = main_buffer_size - 4;
      if (overload == 3)
	ofbuf2 = main_buffer_size - 4 + DHCP_FILE_LEN;
      else
	ofbuf2 = 0;
    }
  else
    ofbuf1 = ofbuf2 = 0;

  /* Copy the options into the big buffer... */
  option_size = store_options (&ocount, buffer,
			       (main_buffer_size - 4 +
				((overload & 1) ? DHCP_FILE_LEN : 0) +
				((overload & 2) ? DHCP_SNAME_LEN : 0)),
			       options, priority_list, priority_len,
			       ofbuf1, ofbuf2, terminate, vuname);
  /* If store_options failed. */
  if (option_size == 0)
    return 0;
  if (overload)
    {
      if (ocount == 1 && (overload & 1))
	overload = 1;
      else if (ocount == 1 && (overload & 2))
	overload = 2;
      else if (ocount == 2)
	overload = 3;
      else
	overload = 0;
    }

  /* Put the cookie up front... */
  memcpy (outpacket->options, DHCP_OPTIONS_COOKIE, 4);
  mainbufix = 4;

  /* If we're going to have to overload, store the overload
     option at the beginning.  If we can, though, just store the
     whole thing in the packet's option buffer and leave it at
     that. */
  memcpy (&outpacket->options [mainbufix],
	  buffer, option_size);
  mainbufix += option_size;
  if (overload)
    {
      outpacket->options [mainbufix++] = DHO_DHCP_OPTION_OVERLOAD;
      outpacket->options [mainbufix++] = 1;
      outpacket->options [mainbufix++] = overload;
      outpacket->options [mainbufix++] = DHO_END;

      if (overload & 1)
	{
	  memcpy (outpacket->file,
		  &buffer [ofbuf1], DHCP_FILE_LEN);
	}
      if (overload & 2)
	{
	  if (ofbuf2)
	    {
	      memcpy (outpacket->sname, &buffer [ofbuf2],
		      DHCP_SNAME_LEN);
	    }
	  else
	    {
	      memcpy (outpacket->sname, &buffer [ofbuf1],
		      DHCP_SNAME_LEN);
	    }
	}
    }
  agentix = mainbufix;
  if (mainbufix < main_buffer_size)
    need_endopt = 1;
  length = DHCP_FIXED_NON_UDP + mainbufix;

  /* Now hack in the agent options if there are any. */
  priority_list [0] = DHO_DHCP_AGENT_OPTIONS;
  priority_len = 1;
  agentix +=
    store_options (0, &outpacket->options [agentix],
		   1500 - DHCP_FIXED_LEN - agentix,
		   options, priority_list, priority_len,
		   0, 0, 0, (char *)0);

  /* Tack a DHO_END option onto the packet if we need to. */
  if (agentix < 1500 - DHCP_FIXED_LEN && need_endopt)
    outpacket->options [agentix++] = DHO_END;

  /* Figure out the length. */
  length = DHCP_FIXED_NON_UDP + agentix;
  return length;
}

/* Store all the requested options into the requested buffer. */

int store_options (int *ocount,
		   unsigned char *buffer,
		   unsigned buflen,
		   struct option_state *options,
		   unsigned *priority_list,
		   unsigned priority_len,
		   unsigned first_cutoff,
		   unsigned second_cutoff,
		   int terminate,
		   const char *vuname)
{
  unsigned bufix = 0;
  unsigned i;
  unsigned ix;
  int tto;
  struct data_string od;
  struct option_cache *oc;
  unsigned code;

  memset (&od, 0, sizeof od);

  /* Eliminate duplicate options in the parameter request list.
     There's got to be some clever knuthian way to do this:
     Eliminate all but the first occurance of a value in an array
     of values without otherwise disturbing the order of the array. */
  for (i = 0; i < priority_len - 1; i++)
    {
      tto = 0;
      for (ix = i + 1; ix < priority_len + tto; ix++)
	{
	  if (tto)
	    priority_list [ix - tto] =
	      priority_list [ix];
	  if (priority_list [i] == priority_list [ix])
	    {
	      tto++;
	      priority_len--;
	    }
	}
    }

  /* Copy out the options in the order that they appear in the
     priority list... */
  for (i = 0; i < priority_len; i++)
    {
      /* Number of bytes left to store (some may already
	 have been stored by a previous pass). */
      unsigned length;
      int optstart;
      struct option_space *u;
      int have_encapsulation = 0;
      struct data_string encapsulation;
      struct option *opt;

      memset (&encapsulation, 0, sizeof encapsulation);

      /* Code for next option to try to store. */
      code = priority_list [i];
	    
      /* Look up the option in the site option space if the code
	 is above the cutoff, otherwise in the DHCP option space. */
      if (code >= options->site_code_min)
	u = option_spaces [options->site_option_space];
      else
	u = &dhcp_option_space;

      opt = find_option(u, code);
      oc = lookup_option (u, options, code);

      /* It's an encapsulation, try to find the option_space
	 to be encapsulated first, except that if it's a straight
	 encapsulation and the user has provided a value for the
	 encapsulation option, use the user-provided value. */
      if (opt &&
	  ((opt->format [0] == 'E' && !oc) || opt->format [0] == 'e'))
	{
	  static char *s;
	  struct option_cache *tmp;
	  struct data_string name;

	  s = strchr(opt->format, 'E');
	  if (s)
	    {
	      memset(&name, 0, sizeof name);

	      /* A zero-length option_space name means the vendor
		 option space, if one is defined. */
	      if (!s[1])
		{
		  if (vendor_cfg_option)
		    {
		      tmp = lookup_option(vendor_cfg_option->option_space,
					  options,
					  vendor_cfg_option->code);
		      if (tmp)
			data_string_copy(&name, &tmp->data);
		    }
		  else if (vuname)
		    {
		      name.data = (const unsigned char *)vuname;
		      name.len = strlen(s);
		    }
		}
	      else
		{
		  name.data = (unsigned char *)s + 1;
		  name.len = strlen(s);
		}
			
	      /* If we found a option space, and there are options
	       * configured for that option space, try to encapsulate
	       * it.
	       */
	      if (name.len)
		{
		  have_encapsulation = option_space_encapsulate(&encapsulation,
								options, &name);
		  data_string_forget(&name);
		}
	    }
	}

      /* In order to avoid memory leaks, we have to get to here
	 with any option cache that we allocated in tmp not being
	 referenced by tmp, and whatever option cache is referenced
	 by oc being an actual reference.   lookup_option doesn't
	 generate a reference (this needs to be fixed), so the
	 preceding goop ensures that if we *didn't* generate a new
	 option cache, oc still winds up holding an actual reference. */

      /* If no data is available for this option, skip it. */
      if (!oc && !have_encapsulation)
	continue;
	    
      /* Find the value of the option... */
      if (oc)
	data_string_copy(&od, &oc->data);

      /* We should now have a constant length for the option. */
      length = od.len;
      if (have_encapsulation)
	{
	  length += encapsulation.len;
	  if (!od.len)
	    {
	      data_string_copy (&od, &encapsulation);
	      data_string_forget (&encapsulation);
	    }
	  else
	    {
	      struct buffer *bp = buffer_allocate(length);
	      memcpy (&bp->data [0], od.data, od.len);
	      memcpy (&bp->data [od.len], encapsulation.data,
		      encapsulation.len);
	      data_string_forget (&od);
	      data_string_forget (&encapsulation);
	      od.data = &bp->data [0];
	      od.buffer = bp;
	      od.len = length;
	      od.terminated = 0;
	    }
	}

      /* Do we add a NUL? */
      if (terminate)
	{
	  struct option *opt = find_option(&dhcp_option_space, code);
	  if (opt->format [0] == 't')
	    {
	      length++;
	      tto = 1;
	    }
	  else
	    {
	      tto = 0;
	    }
	}
      else
	{
	  tto = 0;
	}

      /* Try to store the option. */
	    
      /* If the option's length is more than 255, we must store it
	 in multiple hunks.   Store 255-byte hunks first.  However,
	 in any case, if the option data will cross a buffer
	 boundary, split it across that boundary. */

      ix = 0;
      optstart = bufix;
      while (length)
	{
	  unsigned char incr = length > 255 ? 255 : length;
		    
	  /* If this option is going to overflow the buffer,
	     skip it. */
	  if (bufix + 2 + incr > buflen)
	    {
	      bufix = optstart;
	      break;
	    }
		    
	  /* Everything looks good - copy it in! */
	  buffer [bufix] = code;
	  buffer [bufix + 1] = incr;
	  if (tto && incr == length)
	    {
	      memcpy (buffer + bufix + 2,
		      od.data + ix, (unsigned)(incr - 1));
	      buffer [bufix + 2 + incr - 1] = 0;
	    }
	  else
	    {
	      memcpy (buffer + bufix + 2,
		      od.data + ix, (unsigned)incr);
	    }
	  length -= incr;
	  ix += incr;
	  bufix += 2 + incr;
	}
      data_string_forget (&od);
    }

  /* Do we need to do overloading? */
  if (first_cutoff && bufix > first_cutoff)
    {
      int second_bufsize, third_bufsize;
      unsigned firstix = 0;
      unsigned j;
      unsigned len = 0;
      unsigned char *ovbuf;

      if (ocount)
	*ocount = 1;
      if (second_cutoff)
	{
	  second_bufsize = second_cutoff - first_cutoff;
	  third_bufsize = buflen - second_cutoff;
	}
      else
	{
	  second_bufsize = buflen - first_cutoff;
	  third_bufsize = 0;
	}
      ovbuf = (unsigned char *)safemalloc(bufix);

      /* First move any options that can only fit into the first
	 buffer into the first buffer. */
      for (i = 0; i < bufix; )
	{
	  len = buffer [i + 1] + 2;
	  if (i + len > first_cutoff
	      && buffer [i + 1] > second_bufsize
	      && buffer [i + 1] > third_bufsize
	      && buffer [i + 1] < first_cutoff - 4 - firstix)
	    {
	      memcpy (ovbuf, &buffer [i], len);
	      memmove (&buffer [firstix + len],
		       &buffer [firstix], i - firstix);
	      memcpy (&buffer [firstix], ovbuf, len);
	      firstix += len;
	    }
	  i += len;
	}

      /* Find the first cutoff point. */
      for (i = 0; i < bufix; )
	{
	  len = buffer [i + 1] + 2;
	  if (i + len + 4 > first_cutoff)
	    break;
	  i += len;
	}
      /* Copy down any options that can fill out this buffer. */
      for (j = i + len; j < bufix; )
	{
	  len = buffer [j + 1] + 2;
	  if (i + len + 4 < first_cutoff)
	    {
	      memcpy (ovbuf, &buffer [j], len);
	      memmove (&buffer [i + len], &buffer [i], j - i);
	      memcpy (&buffer [i], ovbuf, len);
	      i += len;
	    }
	  j += len;
	}

      /* Stuff in the overload. */
      memcpy (ovbuf, &buffer [i], bufix - i);
      memset (&buffer [i], 0, first_cutoff - i);
      memcpy (&buffer [first_cutoff], ovbuf, bufix - i);
      ix = i;
      bufix += (first_cutoff - i);
      i += (first_cutoff - i);

      /* See if there's life after the second cutoff. */
      if (second_cutoff)
	{
	  for (j = i + buffer [i + 1] + 2; j < bufix; )
	    {
	      len = buffer [j + 1] + 2;
	      if (j + len + 1 + (first_cutoff - i) > second_cutoff)
		{
		  memcpy (ovbuf, &buffer [j], bufix - j);
		  buffer [j] = DHO_END;
		  if (second_cutoff - j > 1)
		    memset (&buffer [j + 1],
			    0, second_cutoff - j - 1);
		  memcpy (&buffer [second_cutoff], ovbuf, bufix - j);
		  bufix += (second_cutoff - j);
		  buffer [bufix++] = DHO_END;
		  if (ocount)
		    *ocount |= 2;
		  break;
		}
	      j += len;
	    }
	}
    }
  else
    return bufix;

  return ix;
}

/* Format the specified option so that a human can easily read it. */

const char *pretty_print_option(struct option *option,
				const unsigned char *data,
				unsigned len,
				int emit_quotes)
{
  struct data_string optbuf;
  struct enumeration *enumbuf[32];
  unsigned i, j, k, l, m;
  const unsigned char *dp = data;
  struct in_addr foo;
  unsigned long tval;
  int arrayp = 0;
  int array_first = 1;

  memset (enumbuf, 0, sizeof enumbuf);

  memset(&optbuf, 0, sizeof optbuf);
  optbuf.buffer = buffer_allocate(200);
  optbuf.data = optbuf.buffer->data;
	
  l = strlen(option->format);
  if (l && option->format[l - 1] == 'a')
    arrayp = 'a';
  else if (l && option->format[l - 1] == 'A')
    {
      arrayp = 'A';
      data_string_putc(&optbuf, '(');
    }

  /* Loop through the option format buffer, consuming data from the option
   * data buffer and pretty printing it to the output buffer.
   */
  for (i = 0; option->format[i]; i++, l++)
    {
    another:
      /* Array containing elements each of which contains one or more
       * subelements.
       */
      if (i == 0 && arrayp == 'A')
	{
	  if ((unsigned)(dp - data) == len)
	    {
	      data_string_putc(&optbuf, ')');
	      goto out;
	    }
	  data_string_putc(&optbuf, '(');
	}

      /* Array whose elements are atomic. */
      else if (arrayp == 'a' && option->format[i + 1] == 'a')
	{
	  if ((unsigned)(dp - data) == len)
	    {
	      data_string_putc(&optbuf, ')');
	      goto out;
	    }
	  if (array_first)
	    {
	      array_first = 0;
	      data_string_putc(&optbuf, '(');
	    }
	}

      /* Last item is optional. */
      else if (option->format[i + 1] == 'o' && (unsigned)(dp - data) == len)
	goto out;

      else if (dp != data + len)
	data_string_putc(&optbuf, ' ');

      switch (option->format[i])
	{
	case 'a':
	case 'A':
	  if (option->format[i + 1])
	    {
	    extra_codes:
	      log_error ("%s: Extra codes in format string: %s",
			 option->name, option->format);
	      goto out;
	      break;
	    }
	  if (i == 0)
	    {
	      log_error("%s: small array option format with no format code "
			"preceding it: %s",
			option->name, option->format);
	      goto out;
	    }
	  if (option->format[i] == 'a')
	    i--;
	  else
	    {
	      i = 0;
	      data_string_putc(&optbuf, ')');
	    }
	  goto another;

	case 'E':
	  /* Encapsulations have to come at the end of the buffer.   We do
	   * not print the options in an encapsulation.
	   */
	  if (option->format[i + 1])
	    data_string_printf(&optbuf, "\"*encapsulation <%s>*\"",
			       &option->format[i + 1]);
	  else
	    data_string_printf(&optbuf, "\"*vendor encapsulation*\"");
	  i += strlen(&option->format[i]);
	  break;

	case 'X':
	  if (option->format[i + 1])
	    goto extra_codes;

	  for (k = 0; dp + k < data + len; k++)
	    {
	      if (!isascii(data[k]) || !isprint(data[k]))
		break;
	    }

	  /* If we found no bogus characters, or the bogus character we found
	   * is a trailing NUL, it's okay to print this option as text.
	   */
	  if (k == len || (k + 1 == len && data[k] == 0))
	    goto textString;
	  else
	    {
	      for (j = 0; dp + j < data + len; j++)
		data_string_printf(&optbuf, "%s%x", j == 0 ? "" : ":", dp[j]);
	      dp += j;
	    }
	  break;

	case 'd':
	  /* Cycle through the labels.   If we fall out of this loop and dp[0]
	   * isn't zero, the data is bad.
	   */

	  /* Current pointer into DNS data. */
	  j = 0;

	  /* Cycle through the DNS data until we run out of labels or data. */
	  while (dp[j] && dp + j < data + len)
	    {
	      /* Get the label length or pointer. */
	      l = dp[j];

	      if (l < 0 || l > 63)
		{
		  log_error("unsupported DNS label length: %d", l);
		  goto out;
		}

	      /* Normal label. */
	      else if (l < 64)
		{
		  if (dp + j + l > data + len)
		    {
		      log_error("malformed DNS option data at %d: %s", j,
				print_hex_1(len - (dp - data),
					    dp, 60));
		      goto out;
		    }
		  for (m = 0; m < l; m++)
		    data_string_putc(&optbuf, dp[m + j + 1]);
		  data_string_putc(&optbuf, '.');
		  j += l + 1;
		}
	    }

	  /* Advance over the data and the terminating token. */
	  if (dp + j < data + len)
	    dp += j + 1;

	  /* This wasn't a fully-qualified domain name, so there's no
	   * terminal label to walk over.
	   */
	  else
	    dp += j;
	  break;

	textString:
	case 't':
	  if (option->format[i + 1])
	    goto extra_codes;

	  if (emit_quotes)
	    data_string_putc(&optbuf, '"');
	  for (; dp < data + len; dp++)
	    {
	      if (!isascii (*dp) || !isprint (*dp))
		{
		  /* Skip trailing NUL. */
		  if (dp + 1 != data + len || *dp != 0)
		    {
		      data_string_printf(&optbuf, "\\%03o", *dp);
		    }
		}
	      else if (*dp == '"' || *dp == '\'' ||
		       *dp == '$' || *dp == '`' || *dp == '\\')
		{
		  data_string_putc(&optbuf, '\\');
		  data_string_putc(&optbuf, *dp);
		}
	      else
		data_string_putc(&optbuf, *dp);
	    }
	  if (emit_quotes)
	    data_string_putc(&optbuf, '"');
	  break;

	  /* No data associated with this format. */
	case 'o':
	  if (option->format[i + 1])
	    goto extra_codes;
	  break;

	case 'I':
	  if (dp + 4 > data + len)
	    {
	    twolittl:
	      log_error("short option data, format %c: %s",
			option->format[i],
			(dp > data + len
			 ? "<none>"
			 : print_hex_1(len - (dp - data), dp, 60)));
	      goto out;
	    }
	  foo.s_addr = htonl(getULong(dp));
	  data_string_strcat(&optbuf, inet_ntoa(foo));
	  dp += 4;
	  break;
	case '6':
	  if (dp + 16 > data + len)
	    goto twolittl;
	  data_string_need(&optbuf, 46);
	  inet_ntop(AF_INET6, (const char *)dp,
		    (char *)optbuf.buffer->data + optbuf.len,
		    optbuf.buffer->size - optbuf.len);
	  optbuf.len += strlen((char *)optbuf.buffer->data + optbuf.len);
	  dp += 16;
	  break;
	case 'l':
	  if (dp + 4 > data + len)
	    goto twolittl;
	  data_string_printf(&optbuf, "%ld", (long)getLong(dp));
	  dp += 4;
	  break;
	case 'T':
	  if (dp + 4 > data + len)
	    goto twolittl;
	  tval = getULong(dp);
	  if (tval == UINT_MAX)
	    data_string_strcat(&optbuf, "infinite");
	  else
	    data_string_printf(&optbuf, "%lu", tval);
	  dp += 4;
	  break;
	case 'L':
	  if (dp + 4 > data + len)
	    goto twolittl;
	  data_string_printf(&optbuf, "%lu", (unsigned long)getULong(dp));
	  dp += 4;
	  break;
	case 's':
	  if (dp + 2 > data + len)
	    goto twolittl;
	  data_string_printf(&optbuf, "%ld", (long)getShort(dp));
	  dp += 2;
	  break;
	case 'S':
	  if (dp + 2 > data + len)
	    goto twolittl;
	  data_string_printf(&optbuf, "%ld", (long)getUShort(dp));
	  dp += 2;
	  break;
	case 'b':
	  if (dp + 1 > data + len)
	    goto twolittl;
	  data_string_printf(&optbuf, "%d", *(const char *)dp++);
	  break;
	case 'B':
	  if (dp + 1 > data + len)
	    goto twolittl;
	  data_string_printf (&optbuf, "%d", *dp++);
	break;
	case 'x':
	  if (dp + 1 > data + len)
	    goto twolittl;
	  data_string_printf (&optbuf, "%x", *dp++);
	  break;
	case 'f':
	  if (dp + 1 > data + len)
	    goto twolittl;
	  data_string_strcat(&optbuf, (*dp++ ? "true" : "false"));
	  break;
	default:
	  log_error ("%s: garbage in format string: %s",
		     option->name,
		     &(option->format [i]));
	  break;
	}
    }
 out:
  return (const char *)optbuf.data;
}

int get_option (struct data_string *result,
		struct option_space *option_space,
		struct option_state *options,
		unsigned code)
{
  struct option_cache *oc;

  if (!option_space->lookup_func)
    return 0;
  oc = ((*option_space->lookup_func) (option_space, options, code));
  if (!oc)
    return 0;
  data_string_copy(result, &oc->data);
  return 1;
}

struct option_cache *lookup_option (struct option_space *option_space,
				    struct option_state *options,
				    unsigned code)
{
  if (!options)
    return (struct option_cache *)0;
  if (option_space->lookup_func)
    return (*option_space->lookup_func)(option_space,
					options, code);
  else
    log_error ("can't look up options in %s space.",
	       option_space->name);
  return (struct option_cache *)0;
}

struct option_cache *lookup_hashed_option (struct option_space *option_space,
					   struct option_state *options,
					   unsigned code)
{
  int hashix;
  pair bptr;
  pair *hash;

  /* Make sure there's a hash table. */
  if (option_space->index >= options->option_space_count ||
      !(options->option_spaces [option_space->index]))
    return (struct option_cache *)0;

  hash = (pair *)options->option_spaces[option_space->index];

  hashix = compute_option_hash(code);
  for (bptr = hash[hashix]; bptr; bptr = bptr->cdr)
    {
      if (((struct option_cache *)(bptr->car))->option->code ==
	  code)
	return (struct option_cache *)(bptr->car);
    }
  return (struct option_cache *)0;
}

void
save_option_buffer (struct option_space *option_space,
		    struct option_state *options,
		    struct buffer *bp,
		    unsigned char *buffer, unsigned length,
		    struct option *option, int tp)
{
  struct buffer *lbp = (struct buffer *)0;
  struct option_cache *op = (struct option_cache *)safemalloc(sizeof *op);
  memset(op, 0, sizeof *op);

  /* If we weren't passed a buffer in which the data are saved and
     refcounted, allocate one now. */
  if (!bp)
    {
      lbp = buffer_allocate(length);
      memcpy (lbp->data, buffer, length + tp);
      bp = lbp;
      buffer = &bp->data [0]; /* Refer to saved buffer. */
    }

  /* Reference buffer copy to option cache. */
  op->data.buffer = bp;
		
  /* Point option cache into buffer. */
  op->data.data = buffer;
  op->data.len = length;
			
  if (tp)
    {
      /* NUL terminate (we can get away with this because we (or
	 the caller!) allocated one more than the buffer size, and
	 because the byte following the end of an option is always
	 the code of the next option, which the caller is getting
	 out of the *original* buffer. */
      buffer [length] = 0;
      op->data.terminated = 1;
    }
  else
    op->data.terminated = 0;
	
  op->option = option;

  /* Now store the option. */
  save_option (option_space, options, op);
}

void save_option (struct option_space *option_space,
		  struct option_state *options, struct option_cache *oc)
{
  if (option_space->save_func)
    (*option_space->save_func) (option_space, options, oc);
  else
    log_error ("can't store options in %s space.",
	       option_space->name);
}

void save_hashed_option (struct option_space *option_space,
			 struct option_state *options,
			 struct option_cache *oc)
{
  int hashix;
  pair bptr;
  pair *hash = (pair *)options->option_spaces [option_space->index];
  struct option_cache *cur;

  /* Compute the hash. */
  hashix = compute_option_hash (oc->option->code);

  /* If there's no hash table, make one. */
  if (!hash)
    {
      hash = (pair *)safemalloc(OPTION_HASH_SIZE * sizeof *hash);
      memset (hash, 0, OPTION_HASH_SIZE * sizeof *hash);
      options->option_spaces [option_space->index] = (VOIDPTR)hash;
    }
  else
    {
      /* Try to find an existing option matching the new one. */
      for (bptr = hash [hashix]; bptr; bptr = bptr->cdr)
	{
	  if (((struct option_cache *)
	       (bptr->car))->option->code ==
	      oc->option->code)
	    break;
	}

      /* If we find one, and we are concatenating, concatenate
       * the old and new options.   If we are not concatenating
       * (i.e., dhcpv6), then just chain the two options together.
       */
      if (bptr)
	{
	  cur = (struct option_cache *)bptr->car;
	  if (option_space->concatenate)
	    {
	      struct buffer *nouveau;

	      nouveau = buffer_allocate(cur->data.len +
					oc->data.len);
	      memcpy(nouveau->data,
		     cur->data.data, cur->data.len);
	      memcpy(&nouveau->data[cur->data.len],
		     oc->data.data, oc->data.len);
	      cur->data.buffer = nouveau;
	      cur->data.data = nouveau->data;
	      cur->data.len = nouveau->size;
	      cur->data.terminated = 0;
	    }
	  else
	    {
	      oc->next = cur;
	      bptr->car = (caddr_t)oc;
	    }
	  return;
	}
    }

  /* Otherwise, just put the new one at the head of the list. */
  bptr = (pair)safemalloc(sizeof *bptr);
  bptr->cdr = hash [hashix];
  bptr->car = (caddr_t)oc;
  hash [hashix] = bptr;
}

void delete_option (struct option_space *option_space,
		    struct option_state *options,
		    unsigned code)
{
  if (option_space->delete_func)
    (*option_space->delete_func) (option_space, options, code);
  else
    log_error ("can't delete options from %s space.",
	       option_space->name);
}

void delete_hashed_option (struct option_space *option_space,
			   struct option_state *options,
			   unsigned code)
{
  int hashix;
  pair bptr, prev = (pair)0;
  pair *hash = (pair *)options->option_spaces [option_space->index];

  /* There may not be any options in this space. */
  if (!hash)
    return;

  /* Try to find an existing option matching the new one. */
  hashix = compute_option_hash (code);
  for (bptr = hash [hashix]; bptr; bptr = bptr->cdr)
    {
      if (((struct option_cache *)(bptr->car))->option->code == code)
	break;
      prev = bptr;
    }
  /* If we found one, wipe it out... */
  if (bptr)
    {
      if (prev)
	prev->cdr = bptr->cdr;
      else
	hash [hashix] = bptr->cdr;
    }
}

void data_string_need(struct data_string *result, int need)
{
  int total_need = result->len + need;

  /* Make sure there's space to store this option. */
  if (!result->buffer || result->buffer->size < total_need)
    {
      struct buffer *nouveau;
      int newlen;

      if (result->buffer)
	newlen = result->buffer->size * 2;
      else
	newlen = 256;
      if (newlen < total_need)
	{
	  newlen = result->buffer->size + total_need + 256;
	}

      nouveau = buffer_allocate(newlen);
      memcpy(nouveau->data, result->data, result->len);
      result->buffer = nouveau;
      result->data = nouveau->data;
    }

}

void data_string_putc(struct data_string *dest, int c)
{
  data_string_need(dest, dest->len + 1);
  dest->buffer->data[dest->len] = c;
  dest->len++;
}

void data_string_strcat(struct data_string *dest, const char *s)
{
  int i = strlen(s);
  data_string_need(dest, dest->len + i);
  strcpy((char *)dest->buffer->data + dest->len, s);
  dest->len += i;
}

void data_string_printf(struct data_string *dest, const char *fmt, ...)
{
  va_list list;
  int i;

  va_start(list, fmt);
  i = vsnprintf((char *)dest->buffer->data + dest->len,
		dest->buffer->size - dest->len, fmt, list);
  va_end(list);

  if (i < 0)
    return;

  if ((unsigned)i > dest->buffer->size - dest->len)
    {
      data_string_need(dest, dest->len + i + 1);
      va_start (list, fmt);
      i = vsnprintf((char *)dest->buffer->data + dest->len,
		    dest->buffer->size - dest->len, fmt, list);
      va_end (list);
    }
}

void store_option(struct data_string *result,
		  struct option_space *option_space,
		  struct option_cache *oc)
{
  int need = 0;
  struct option_cache *chain;

  for (chain = oc; chain; chain = chain->next)
    need += (chain->data.len +
	     option_space->length_size + option_space->tag_size);

  data_string_need(result, need);

  for (chain = oc; chain; chain = chain->next)
    {
      (option_space->store_tag)(&result->buffer->data[result->len],
				chain->option->code);
      result->len += option_space->tag_size;
      (option_space->store_length)(&result->buffer->data[result->len],
				   chain->data.len);
      result->len += option_space->length_size;
      memcpy(&result->buffer->data[result->len],
	     chain->data.data, chain->data.len);
      result->len += chain->data.len;
    }
}
	
int option_space_encapsulate (struct data_string *result,
			      struct option_state *options,
			      struct data_string *name)
{
  struct option_space *u;

  u = (struct option_space *)0;
  option_space_hash_lookup (&u, option_space_hash,
			    (const char *)name->data, name->len);
  if (!u)
    return 0;

  if (u->encapsulate)
    return (*u->encapsulate)(result, options, u);
  log_error ("encapsulation requested for %s with no support.",
	     name->data);
  return 0;
}

int hashed_option_space_encapsulate (struct data_string *result,
				     struct option_state *options,
				     struct option_space *option_space)
{
  pair p, *hash;
  int status;
  int i;

  if (option_space->index >= options->option_space_count)
    return 0;

  hash = (pair *)options->option_spaces [option_space->index];
  if (!hash)
    return 0;

  status = 0;
  for (i = 0; i < OPTION_HASH_SIZE; i++)
    {
      for (p = hash [i]; p; p = p->cdr)
	{
	  store_option (result, option_space,
			(struct option_cache *)p->car);
	  status = 1;
	}
    }
  return status;
}

int nwip_option_space_encapsulate (struct data_string *result,
				   struct option_state *options,
				   struct option_space *option_space)
{
  pair ocp;
  int status;
  struct option_chain_head *head;

  if (option_space->index >= options->option_space_count)
    return 0;
  head = ((struct option_chain_head *)
	  options->option_spaces [nwip_option_space.index]);
  if (!head || !head->first)
    return 0;

  /* Preallocate space at the beginning of the buffer for the stupid
   * nwip-exists-in-option-area or no-nwip-options suboption.
   */
  result->buffer = buffer_allocate(100);
  result->len = 2;
  result->data = &result->buffer->data[0];

  status = 0;
  for (ocp = head->first; ocp; ocp = ocp->cdr)
    {
      store_option (result, option_space,
		    (struct option_cache *)ocp->car);
      status = 1;
    }

  /* If there's no data, the nwip suboption is supposed to contain
     a suboption saying there's no data. */
  if (!status)
    {
      result->buffer->data[0] = 1;
      result->buffer->data[1] = 0;
      status = 1;
    }
  else
    {
      result->buffer->data[0] = 2;
      result->buffer->data[1] = 0;
    }

  return status;
}

int fqdn_option_space_encapsulate (struct data_string *result,
				   struct option_state *options,
				   struct option_space *option_space)
{
  pair ocp;
  struct data_string *results[FQDN_SUBOPTION_COUNT + 1];
  unsigned len;
  struct buffer *bp = (struct buffer *)0;
  struct option_chain_head *head;

  /* If there's no FQDN option_space, don't encapsulate. */
  if (fqdn_option_space.index >= options->option_space_count)
    return 0;
  head = ((struct option_chain_head *)
	  options->option_spaces [fqdn_option_space.index]);
  if (!head || !head->first)
    return 0;

  /* Figure out the values of all the suboptions. */
  memset (results, 0, sizeof results);
  for (ocp = head->first; ocp; ocp = ocp->cdr)
    {
      struct option_cache *oc = (struct option_cache *)(ocp->car);
      if (oc->option->code > FQDN_SUBOPTION_COUNT)
	continue;
      results[oc->option->code] = &oc->data;
    }
  len = 4 + results [FQDN_FQDN]->len;
  /* Save the contents of the option in a buffer. */
  bp = buffer_allocate(len);
  result->buffer = bp;
  result->len = 3;
  result->data = &bp->data[0];

  memset (&bp->data [0], 0, len);
  if (results[FQDN_NO_CLIENT_UPDATE] &&
      results[FQDN_NO_CLIENT_UPDATE]->len &&
      results[FQDN_NO_CLIENT_UPDATE]->data[0])
    bp->data[0] |= 2;
  if (results[FQDN_SERVER_UPDATE] &&
      results[FQDN_SERVER_UPDATE]->len &&
      results[FQDN_SERVER_UPDATE]->data[0])
    bp->data[0] |= 1;
  if (results[FQDN_RCODE1] && results [FQDN_RCODE1]->len)
    bp->data[1] = results[FQDN_RCODE1]->data[0];
  if (results[FQDN_RCODE2] && results[FQDN_RCODE2]->len)
    bp->data[2] = results[FQDN_RCODE2]->data[0];

  if (results[FQDN_ENCODED] &&
      results[FQDN_ENCODED]->len &&
      results[FQDN_ENCODED]->data [0])
    {
      bp->data[0] |= 4;
      if (results[FQDN_FQDN] && results[FQDN_FQDN]->len)
	{
	  result->len +=
	    dns_fqdn_to_wire (&bp->data [3],
			      results[FQDN_FQDN]->data,
			      results[FQDN_FQDN]->len);
	  result->terminated = 0;
	}
    }
  else
    {
      if (results[FQDN_FQDN] && results[FQDN_FQDN]->len)
	{
	  memcpy (&bp->data [3], results[FQDN_FQDN]->data,
		  results[FQDN_FQDN]->len);
	  result->len += results[FQDN_FQDN]->len;
	  result->terminated = 0;
	}
    }
  return 1;
}

int dns_fqdn_to_wire (unsigned char *in,
		      const unsigned char *data, unsigned len)
{
  unsigned i = 0;
  unsigned char *out = in;

  while (i < len)
    {
      unsigned j;
      for (j = i; data[j] != '.' && j < len; j++)
	;
      *out++ = j - i;
      memcpy (out, &data[i], j - i);
      out += j - i;
      i = j;
      if (data[j] == '.')
	i++;
    }
  if (data[len - 1] == '.')
    *out++ = 0;
  return out - in;
}

void option_space_foreach (struct option_state *options,
			   struct option_space *u, void *stuff,
			   void (*func) (struct option_cache *,
					 struct option_state *,
					 struct option_space *, void *))
{
  if (u->foreach)
    (*u->foreach) (options, u, stuff, func);
}

void suboption_foreach (struct option_state *options,
			struct option_space *u, void *stuff,
			void (*func) (struct option_cache *,
				      struct option_state *,
				      struct option_space *, void *),
			struct option_cache *oc,
			const char *vsname)
{
  struct option_space *option_space =
    find_option_option_space (oc->option, vsname);
  if (option_space->foreach)
    (*option_space->foreach) (options, option_space, stuff, func);
}

void hashed_option_space_foreach (struct option_state *options,
				  struct option_space *u, void *stuff,
				  void (*func) (struct option_cache *,
						struct option_state *,
						struct option_space *, void *))
{
  pair *hash;
  int i;
  struct option_cache *oc;

  if (options->option_space_count <= u->index)
    return;

  hash = (pair *)options->option_spaces[u->index];
  if (!hash)
    return;
  for (i = 0; i < OPTION_HASH_SIZE; i++)
    {
      pair p;
      /* XXX save _all_ options! XXX */
      for (p = hash[i]; p; p = p->cdr)
	{
	  oc = (struct option_cache *)p->car;
	  (*func)(oc, options, u, stuff);
	}
    }
}

void save_linked_option (struct option_space *option_space,
			 struct option_state *options,
			 struct option_cache *oc)
{
  pair *tail;
  struct option_chain_head *head;

  if (option_space->index >= options->option_space_count)
    return;
  head = ((struct option_chain_head *)
	  options->option_spaces [option_space->index]);
  if (!head)
    {
      head = (struct option_chain_head *)safemalloc(sizeof *head);
      options->option_spaces[option_space->index] = head;
    }

  /* Find the tail of the list. */
  for (tail = &head->first; *tail; tail = &((*tail)->cdr))
    {
      if (oc->option ==
	  ((struct option_cache *)((*tail)->car))->option)
	{
	  (*tail)->car = (caddr_t)oc;
	  return;
	}
    }

  *tail = cons(0, 0);
  (*tail)->car = (caddr_t)oc;
}

int linked_option_space_encapsulate (struct data_string *result,
				     struct option_state *options,
				     struct option_space *option_space)
{
  int status;
  pair oc;
  struct option_chain_head *head;

  if (option_space->index >= options->option_space_count)
    return 0;
  head = ((struct option_chain_head *)
	  options->option_spaces [option_space->index]);
  if (!head)
    return 0;

  status = 0;
  for (oc = head->first; oc; oc = oc->cdr)
    {
      store_option (result, option_space,
		    (struct option_cache *)(oc->car));
      status = 1;
    }
  return status;
}

void delete_linked_option (struct option_space *option_space,
			   struct option_state *options,
			   unsigned code)
{
  pair *tail, tmp = (pair)0;
  struct option_chain_head *head;

  if (option_space->index >= options->option_space_count)
    return;
  head = ((struct option_chain_head *)
	  options->option_spaces [option_space->index]);
  if (!head)
    return;

  for (tail = &head->first; *tail; tail = &((*tail)->cdr))
    {
      if (code == ((struct option_cache *)(*tail)->car)->option->code)
	{
	  tmp = (*tail)->cdr;
	  (*tail) = tmp;
	  break;
	}
    }
}

struct option_cache *lookup_linked_option (struct option_space *option_space,
					   struct option_state *options,
					   unsigned code)
{
  pair oc;
  struct option_chain_head *head;

  if (option_space->index >= options->option_space_count)
    return 0;
  head = ((struct option_chain_head *)
	  options->option_spaces [option_space->index]);
  if (!head)
    return 0;

  for (oc = head->first; oc; oc = oc->cdr)
    {
      if (code ==
	  ((struct option_cache *)(oc->car))->option->code)
	{
	  return (struct option_cache *)(oc->car);
	}
    }

  return (struct option_cache *)0;
}

void linked_option_space_foreach (struct option_state *options,
				  struct option_space *u, void *stuff,
				  void (*func) (struct option_cache *,
						struct option_state *,
						struct option_space *, void *))
{
  pair car;
  struct option_chain_head *head;

  if (u->index >= options->option_space_count)
    return;
  head = ((struct option_chain_head *)
	  options->option_spaces [u->index]);
  if (!head)
    return;
  for (car = head->first; car; car = car->cdr)
    {
      (*func) ((struct option_cache *)(car->car), options, u, stuff);
    }
}

/* Enumerations can be specified in option formats, so we define the
 * routines that manage them here.
 */

struct enumeration *enumerations;

void add_enumeration (struct enumeration *enumeration)
{
  enumeration->next = enumerations;
  enumerations = enumeration;
}

struct enumeration *find_enumeration (const char *name, int length)
{
  struct enumeration *e;

  for (e = enumerations; e; e = e->next)
    if (strlen(e->name) == (unsigned)length &&
	!memcmp(e->name, name, (unsigned)length))
      return e;
  return (struct enumeration *)0;
}

struct enumeration_value *find_enumeration_value (const char *name,
						  int length,
						  const char *value)
{
  struct enumeration *e;
  int i;

  e = find_enumeration (name, length);
  if (e)
    {
      for (i = 0; e->values [i].name; i++)
	{
	  if (!strcmp (value, e->values [i].name))
	    return &e->values [i];
	}
    }
  return (struct enumeration_value *)0;
}

/* Find the definition of an option with the specified code in the specified
 * option_space.
 */
struct option *
find_option(struct option_space *option_space, unsigned code)
{
  struct option *opt;
  if (code < option_space->max_option && option_space->optvec[code])
    return option_space->optvec[code];

  /* Make a temporary option.   Rely on gc to get rid of it when it's
   * no longer in use.
   */
  opt = (struct option *)safemalloc(sizeof *opt);
  memset(opt, 0, sizeof *opt);
  opt->name = (char *)safemalloc(32);
  snprintf(opt->name, 32, "option-%d", code);
  opt->format = (char *)safemalloc(2);
  opt->format[0] = 'X';
  opt->format[1] = 0;
  opt->option_space = option_space;
  opt->code = code;
  return opt;
}

struct option *
define_option(struct option_space *option_space,
	      unsigned code, const char *format, const char *name)
{
  char nbuf[128];
  unsigned i;
  struct option *option;
  char *np;

  /* Make sure the same name never refers to two different codes. */
  if (name)
    {
      for (i = 0; i < option_space->max_option; i++)
	{
	  if (i != code && option_space->optvec[i] &&
	      !strcmp(option_space->optvec[i]->name, name))
	    {
	      log_error("attempt to define option named %s "
			"with code %d when an option of that"
			" name is already assigned to a "
			"different code %d", name, code,
			option_space->optvec[i]->code);
	      goto noname;
	    }
	}
      np = (char *)safemalloc(strlen(name) + 1);
      strcpy(np, name);

      /* If no name was provided, or if there was a clash, make up a name
       * from the code.   Conceivably this could be a duplicate, but at
       * that point we're clearly experiencing deliberate bad behavior
       * on the part of the user, so they'll just have to deal with the
       * consequences.
       */
    }
  else
    {
    noname:
      sprintf(nbuf, "option_%d", code);
      np = (char *)safemalloc(strlen(nbuf) + 1);
      strcpy(np, nbuf);
    }

  /* See if there's an option definition for this code already, and
   * if so, supersede it.
   */
  if (code < option_space->max_option && option_space->optvec[code])
    {
      option_space->optvec[code]->name = np;
      strcpy(option_space->optvec[code]->name, name);
      option_space->optvec[code]->format =
	(char *)safemalloc(strlen(format) + 1);
      strcpy(option_space->optvec[code]->format, format);
      return option_space->optvec[code];
    }

  /* We're making a new definition; make sure there's space. */
  if (code >= option_space->max_option)
    {
      struct option **newvec = (struct option **)
	safemalloc((code + 10) * sizeof *newvec);
      if (option_space->optvec)
	memcpy(newvec, option_space->optvec,
	       option_space->max_option * sizeof *newvec);
      memset(&newvec[option_space->max_option], 0,
	     (code + 10 - option_space->max_option) * sizeof *newvec);
      option_space->optvec = newvec;
      option_space->max_option = code + 10;
    }

  /* Allocate and fill in the option. */
  option = (struct option *)safemalloc(sizeof *option);
  option->name = np;
  option->format = (char *)safemalloc(strlen(format) + 1);
  strcpy(option->format, format);
  option->code = code;
  option->option_space = option_space;
  option_space->optvec[code] = option;
  return option;
}

/* Local Variables:  */
/* mode:C++ */
/* c-file-style:"gnu" */
/* end: */
