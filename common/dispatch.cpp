/* dispatch.cpp

   Network input dispatcher... */

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
"$Id: dispatch.cpp,v 1.10 2010/01/14 20:28:14 mellon Exp $ Copyright (c) 2006 Nominum, Inc.  All rights reserved.\n";
#endif /* not lint */

#ifndef NO_PYTHON
#include "Python.h"
#endif

#include "dhcpd.h"
#include "dhc++/timeout.h"

typedef struct io_object
{
  struct io_object *next;
  void *thunk;
  int (*readfd)(void *);
  int (*writefd)(void *);
  isc_result_t (*reader)(void *);
  isc_result_t (*writer)(void *);
  isc_result_t (*reaper)(void *);
} io_object_t;

static io_object_t *io_objects;

unsigned long long cur_time;

/* Advance the clock (this has historically been used in simulation, and
 * probably isn't used at all in the current code).
 */
void set_time(unsigned long long t)
{
  /* Do any outstanding timeouts. */
  if (cur_time != t)
    {
      cur_time = t;
      Timeout::next(cur_time);
    }
}

/* Put the current clock time into cur_time. */
void fetch_time()
{
  struct timeval now;
  gettimeofday (&now, (struct timezone *)0);
  cur_time = TIMEV_NANOSECONDS(now);
}

/* Add an I/O object to the list of I/O objects. */
isc_result_t register_io_object(void *v,
				int (*readfd)(void *),
				int (*writefd)(void *),
				isc_result_t (*reader)(void *),
				isc_result_t (*writer)(void *),
				isc_result_t (*reaper)(void *))
{
  io_object_t *obj, *p;

  obj = (io_object_t *)safemalloc(sizeof *obj);

  /* Find the last I/O state, if there are any. */
  for (p = io_objects; p && p->next; p = p->next)
    ;
  if (p)
    p->next = obj;
  else
    io_objects = obj;

  obj->thunk = v;
  obj->readfd = readfd;
  obj->writefd = writefd;
  obj->reader = reader;
  obj->writer = writer;
  obj->reaper = reaper;
  return ISC_R_SUCCESS;
}

/* Take an I/O object off the list of I/O objects. */
isc_result_t unregister_io_object(void *v)
{
  io_object_t *p, *obj, *last;

  /* remove from the list of I/O states */
  obj = (io_object_t *)v;
  last = io_objects;
  for (p = io_objects; p && p->next; p = p ->next)
    {
      if (p == obj)
	{
	  if (p == io_objects)
	    io_objects = io_objects->next;
	  else
	    last->next = p->next;
	  return ISC_R_SUCCESS;
	}
      last = p;
    }
  return ISC_R_NOTFOUND;
}

/* Keep dispatching until something changes. */
isc_result_t dispatch(void)
{
  isc_result_t rv;
  struct timeval to;
  fd_set r, w, x;

  FD_ZERO(&r);
  FD_ZERO(&w);
  FD_ZERO(&x);

  to.tv_sec = 60 * 60 * 24;
  to.tv_usec = 0;
  do {
    rv = dispatch_select(&r, &w, &x, 0, &to, 0);
  } while (rv == ISC_R_SUCCESS);
  return rv;
}

/* Wait for packets to come in using select().   When one does, call
 * receive_packet to receive the packet and possibly strip hardware
 * addressing information from it, and then call through the
 * bootp_packet_handler hook to try to do something with it.
 * If any of the indicated descriptors comes ready or the indicated
 * timeout expires, return.
 *
 * The idea here is that dispatch_select is essentially a replacement
 * for the select() syscall, so that you can run the DHCP client in
 * tandem with someone else's select-based dispatch loop.
 */

isc_result_t dispatch_select(fd_set *ord,
			     fd_set *owt,
			     fd_set *oex,
			     int omax,
			     struct timeval *oto,
			     int *rcount)
{
  int max = 0;
  int count;
  int desc;
  struct timeval to;
  fd_set r, w, x;

  io_object_t *io;
  isc_result_t status;
  unsigned long long when;
  unsigned long long expiry;

  expiry = TIMEV_NANOSECONDS(*oto) + cur_time;
  fetch_time();

  /* Wait for a packet or a timeout... XXX */
  do {

    /* Timeout::next() does two things - first, it runs any timeouts that
     * have a time less than cur_time, and then it returns the time at which
     * the next timeout will occur.   This is relative to the epoch, not to
     * cur_time, so we subtract cur_time to get the number of ticks until
     * the next timeout.
     */
    when = Timeout::next(cur_time);

    /* If the caller's timeout expires before ours does, use it; otherwise,
     * use ours.
     */
    if (when < expiry && when != 0)
      when = when - cur_time;
    else
      {
	/* If the caller's timer has expired, do a poll, and then return. */
	if (expiry < cur_time)
	    when = 0;
	else
	    when = expiry - cur_time;
      }
	
    to.tv_sec = SECONDS(when);
    to.tv_usec = MICROSECONDS(when);

    /* It is possible for the timeout to get set larger than
     * the largest time select() is willing to accept.
     * Restricting the timeout to a maximum of one day should
     * work around this.  -DPN.  (Ref: Bug #416)
     */
    if (to.tv_sec > (60 * 60 * 24))
      to.tv_sec = 60 * 60 * 24;
	
  again:
    /* If we have no I/O state, we can't proceed. */
    if (!(io = io_objects) && omax == 0)
      return ISC_R_NOMORE;

    /* Copy the caller's read and write masks. */
    memcpy(&r, ord, sizeof r);
    memcpy(&w, owt, sizeof w);
    memcpy(&x, oex, sizeof x);
    max = omax;

    /* Set up the read and write masks. */
    for (; io; io = io->next)
      {
	/* Check for a read socket.   If we shouldn't be
	   trying to read for this I/O object, either there
	   won't be a readfd function, or it'll return -1. */
	if (io->readfd && (desc = (*(io->readfd))(io->thunk)) >= 0)
	  {
	    FD_SET (desc, &r);
	    if (desc > max)
	      max = desc;
	  }
		
	/* Same deal for write fdets. */
	if (io->writefd && (desc = (*(io->writefd))(io->thunk)) >= 0)
	  {
	    FD_SET (desc, &w);
	    if (desc > max)
	      max = desc;
	  }
      }

    /* Wait for a packet or a timeout... XXX */
#if 0
#if defined (__linux__)
#define fds_bits __fds_bits
#endif
    log_error ("dispatch: %d %lx %lx", max,
	       (unsigned long)r.fds_bits [0],
	       (unsigned long)w.fds_bits [0]);
#endif
#ifndef NO_PYTHON
    Py_BEGIN_ALLOW_THREADS
#endif
    count = select (max + 1, &r, &w, &x, &to);
#ifndef NO_PYTHON
    Py_END_ALLOW_THREADS
#endif

    /* Get the current time... */
    fetch_time();

    /* We probably have a bad file descriptor.   Figure out which one.
     * When we find it, call the reaper function on it, which will
     * maybe make it go away, and then try again.
     */
    if (count < 0)
      {
	struct timeval t0;
	int got_bogon = 0;
	io = io_objects;
	
	while (io)
	  {
	    fd_set tr, tw, tx;
	    void *thunk = io->thunk;
	    FD_ZERO(&tr);
	    FD_ZERO(&tw);
	    FD_ZERO(&tx);
	    t0.tv_sec = t0.tv_usec = 0;
	    
	    if (io->readfd && (desc = (*(io->readfd))(thunk)) >= 0)
	      {
		FD_SET(desc, &tr);
#if 0
		log_error("read check: %d %lx %lx", max,
			  (unsigned long)r.fds_bits [0],
			  (unsigned long)w.fds_bits [0]);
#endif
#ifndef NO_PYTHON
		Py_BEGIN_ALLOW_THREADS
#endif
		count = select(desc + 1, &tr, &tw, &tx, &t0);
#ifndef NO_PYTHON
		Py_END_ALLOW_THREADS
#endif
		if (count < 0)
		  {
		  bogon:
		    log_error("Bad descriptor %d.", desc);
		    if (io->reaper)
		      (io->reaper)(thunk);
		    unregister_io_object(io->thunk);
		    got_bogon = 1;
		    break;
		  }
	      }
			
	    FD_ZERO(&tr);
	    FD_ZERO(&tw);
	    FD_ZERO(&tx);
	    t0.tv_sec = t0.tv_usec = 0;

	    /* Same deal for write fds. */
	    if (io->writefd &&
		(desc = (*(io->writefd))(io->thunk)) >= 0)
	      {
		FD_SET(desc, &tw);
		count = select(desc + 1, &tr, &tw, &tx, &t0);
		if (count < 0)
		  goto bogon;
	      }
	  }

	/* If we didn't get a bogon, it means that one of the descriptors
	 * the caller passed was bogus.
	 */
	if (!got_bogon)
	  return ISC_R_INVALIDARG;

	/* Now we have to retry the select. */
	goto again;
      }

    for (io = io_objects; io; io = io->next)
      {
	/* Check for a read descriptor, and if there is one,
	 * see if we got input on that socket.
	 */
	if (io->readfd && (desc = (io->readfd)(io->thunk)) >= 0)
	  {
	    if (FD_ISSET(desc, &r))
	      status = (io->reader)(io->thunk);
	    /* XXX what to do with status? */
	    --count;
	    FD_CLR(desc, &r);
	  }
	
	/* Same deal for write descriptors. */
	if (io->writefd &&
	    (desc = (io->writefd)(io->thunk)) >= 0)
	  {
	    if (FD_ISSET(desc, &w))
	      status = (io->writer)(io->thunk);
	    /* XXX what to do with status? */
	    --count;
	    FD_CLR(desc, &r);
	  }
      }
  } while (count > 0 && cur_time < expiry);

  /* Return the new bitmaps. */
  memcpy(ord, &r, sizeof r);
  memcpy(owt, &w, sizeof w);
  memcpy(oex, &x, sizeof x);

  /* If count > 0, one of the caller's descriptors is ready, so return.
   * If cur_time < expiry, the caller's timeout has expired, so return.
   */
  if (rcount)
    *rcount = count;
  return ISC_R_SUCCESS;
}

/* Local Variables:  */
/* mode:c++ */
/* c-file-style:"gnu" */
/* end: */
