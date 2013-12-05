/* timeout.cpp
 *
 * Object for handling timeout events.
 */

/* Copyright (c) 2005-2006 Nominum, Inc.   All rights reserved.
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
"$Id: timeout.cpp,v 1.6 2010/01/14 20:31:51 mellon Exp $ Copyright (c) 2005-2006 Nominum, Inc.  All rights reserved.\n";
#endif /* not lint */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "dhc++/timeout.h"

struct Timeout_timeout {
  struct Timeout_timeout *next;
  struct Timeout_timeout *next_timeout;
  unsigned long long when;
  int selector;
  Timeout *timer;
};

timeout_t *Timeout::timeouts;

/* Initialize the list of timeouts. */
Timeout::Timeout()
{
  timers = 0;
  defer = false;
}

/* Timeouts are allocated, so we need to free them when the timer object
 * is destroyed.
 */
Timeout::~Timeout()
{
  printf("timeout destructor called.\n");
  clearTimeouts();
}

void Timeout::dumpTimeouts(const char *caller)
{
#if 0
  printf("%s:", caller);
  timeout_t *timeout;
  extern unsigned long long cur_time;
#if 0
  for (timeout = timeouts; timeout; timeout = timeout->next_timeout)
    printf(" %d", ((int)((unsigned long long)timeout->timer) & 0xffff));
#else
  for (timeout = timeouts; timeout; timeout = timeout->next_timeout)
    printf(" %lld", (timeout->when - cur_time) / 1000);

#endif
  printf("\n");
#endif
}

/* Trigger a timeout at the specified time.   Other timeouts remain
 * in effect.   Timeout time is in microseconds after the epoch - in
 * otherwords, a struct timespec converted to a long long.   On operating
 * systems that aren't unix-like, you'll have to fake it.   Absolute
 * times don't matter - just that they're all relative to the same
 * epoch.
 */

void Timeout::addTimeout(unsigned long long when, int selector)
{
  timeout_t *timer = new timeout_t;
  memset(timer, 0, sizeof *timer);
  timer->when = when;
  timer->timer = this;
  timer->selector = selector;

#ifdef DEBUG_TIMEOUTS
  dumpTimeouts("addTimeout entry");
  printf("addTimeout(%lld, %p, %d)\n", when, this, selector);
#endif

  /* Put the timer on the list.   If it's the first on the list, set up
   * an actual timeout for it.
   */
  if (!timers)
    {
      timers = timer;
      insertTimeout();
    }
  else if (timers->when > when)
    {
      cancelTimeout();
      timer->next = timers;
      timers = timer;
      insertTimeout();
    }
  else
    {
      timeout_t *tp;
      for (tp = timers; tp->next && tp->next->when < when; tp = tp->next)
	;
      timer->next = tp->next;
      tp->next = timer;
    }

#ifdef DEBUG_TIMEOUTS
  dumpTimeouts("addTimeout exit");
#endif
}

/* If this timer object has any actual timeouts, get them off the global
 * timeout list, and free the memory associated with them.
 */
void Timeout::clearTimeouts()
{
#ifdef DEBUG_TIMEOUTS
  dumpTimeouts("clearTimeouts entry");
#endif
  if (timers)
    {
      timeout_t *tp, *next;

      /* If our first timer is on the global timeout list, take it off.
       * None but the first is ever on the global list.
       */
      cancelTimeout();

      for (tp = timers; tp; tp = next)
	{
	  next = tp->next;
	  delete tp;
	}
      timers = 0;
    }
#ifdef DEBUG_TIMEOUTS
  dumpTimeouts("clearTimeouts exit");
#endif
}

/* Insert the earliest timeout on this timer object into the global timeout
 * list.   We don't insert every timeout because in general it's quite
 * likely that a later timeout will never actually become the first timeout,
 * and so there's no reason to waste time sorting it in until it becomes
 * the first.
 */
void Timeout::insertTimeout()
{
  unsigned long long when;

  if (defer)
    return;
  if (!timers)
    return;
#ifdef DEBUG_TIMEOUTS
  dumpTimeouts("insertTimeout entry");
#endif
  when = timers->when;

  if (!timeouts)
    {
      timeouts = timers;
    }
  else if (timeouts->when > timers->when)
    {
      timers->next_timeout = timeouts;
      timeouts = timers;
    }
  else
    {
      timeout_t *p;
      for (p = timeouts; (p->next_timeout &&
			  p->next_timeout->when < when); p = p->next_timeout)
	;
      timers->next_timeout = p->next_timeout;
      p->next_timeout = timers;
    }
#ifdef DEBUG_TIMEOUTS
  dumpTimeouts("insertTimeout exit");
#endif
}
  
/* Find the first timeout for this timer object on the global list of
 * timeouts, and remove it.   When complete, there will be no timeouts
 * belonging to this timer object on the global list.
 */
void Timeout::cancelTimeout()
{
  timeout_t *tp;

  /* If we are in the middle of processing timeouts, then the timeout
   * for this timer isn't on the list, so we don't need to do any work.
   */
  if (defer)
    return;

  if (!timers)
    return;

  /* If this Timout's timeout is first on the list, just remove it. */
  if (timeouts == timers)
    {
      timeouts = timeouts->next_timeout;
#ifdef DEBUG_TIMEOUTS
      dumpTimeouts("cancelTimeout exit");
#endif
      return;
    }

  /* Scan the list looking for our timeout.   It would be a bit of a
   * non-fatal coding mistake to ever call cancelTimeout() when we
   * *don't* have a timeout on this list, but to mitigate the cost
   * of that, we stop scanning when the timeout on the list that
   * we're looking at is later than the first timeout for this Timeout
   * object.
   */
  for (tp = timeouts; tp->next_timeout; tp = tp->next_timeout)
    {
      if (tp->when > timers->when)
	break;
      if (tp->next_timeout == timers)
	{
	  tp->next_timeout = timers->next_timeout;
	  break;
	}
    }

  /* At this point we've either removed the timeout from the list, or
   * it wasn't on the list in the first place.
   */
#ifdef DEBUG_TIMEOUTS
  dumpTimeouts("cancelTimeout exit");
#endif
}
 
/* Called by the dispatcher to find out how long to wait for the next
 * timeout.   Before returning with that information, process any
 * outstanding timeouts.
 */
unsigned long long Timeout::next(unsigned long long now)
{
#ifdef DEBUG_TIMEOUTS
  dumpTimeouts("next entry");
#endif

  /* Handle all the expired timeouts, in order. */
  while (timeouts && timeouts->when < now)
    {
      timeout_t *tp = timeouts;
      timeouts = timeouts->next_timeout;
      tp->next_timeout = 0;
      tp->timer->startProcessingTimeout(tp, now);
    }

#ifdef DEBUG_TIMEOUTS
  dumpTimeouts("next exit");
#endif

  /* Possibly we have no further timeouts to process. */
  if (timeouts)
    return timeouts->when;
  return 0;
}
  
/* This is called when this particular Timeout object instance has hit
 * a timeout.
 */
void Timeout::startProcessingTimeout(timeout_t *tp, unsigned long long now)
{
  /* tp should always be equal to timers at this point; if it's not, there's
   * some kind of programming error.
   */
  if (tp != timers)
    abort();

  /* Get rid of the timeout that just happened, but let the caller
   * free it.
   */
  timers = timers->next;

  /* We don't want to call insertTimeout twice; it's possible the caller
   * will add some timeouts, and on the other hand it might not, so defer
   * the call to insertTimeout() until after the caller returns.   That way
   * we only actually insert the new timeout once.
   */
  defer = true;

  /* Invoke the virtual function to do the timeout. */
  event("timeout", tp->selector, 0);

  /* Free the memory. */
  delete tp;

  /* If we still have a timeout, insert it. */
  defer = false;
  if (timers)
    insertTimeout();
}

/* Local Variables:  */
/* mode:c++ */
/* c-file-style:"gnu" */
/* end: */
