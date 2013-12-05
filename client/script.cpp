/* script.cpp
 *
 * The code in this file provides an interface between the DHCP client and
 * a script (shell, perl, whatever you like) that controls the network
 * interface or interfaces that the client manages.   The script is asked
 * to do things like set up an interface to be configured, and later to
 * configure an IP address on it, set up resolver information, and like that.
 */

/*
 * Copyright (c) 2002-2005 Nominum, Inc.   All rights reserved.
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
static char ocopyright[] __attribute__((unused)) =
  "$Id: script.cpp,v 1.10 2008/03/07 19:58:23 mellon Exp $ Copyright (c) 2002-2005 Nominum, Inc.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"
#include "version.h"
#include "client/v4client.h"
#include "client/v6client.h"
#include "dhc++/eventreceiver.h"
#include "client/script.h"

Script::Script(const char *name)
{
  scriptName = (char *)safemalloc(strlen(name) + 1);
  strcpy(scriptName, name);

  envCount = 0;
  envp = 0;
  envMax = 0;
}

void Script::initialize(void)
{
  envCount = 0;
  envp = 0;
  envMax = 0;
}

void Script::finish(EventReceiver *receiver, int failState, int succeedState)
{
  char *argv[2];
  int pid, wpid, wstatus;
  char *s;

  /* Set $PATH. */
  s = (char *)safemalloc(sizeof CLIENT_PATH + 1);
  strcpy(s, CLIENT_PATH);
  addenv(s);

  /* Terminate environment string list. */
  addenv(0);

  argv [0] = scriptName;
  argv [1] = (char *)0;

  pid = fork();
  if (pid < 0)
    {
      log_error("fork: %m");
    }
  else if (pid)
    {
    again:
      do {
	wpid = wait(&wstatus);
      } while (wpid != pid && wpid > 0);

      /* We waited, so refresh the time. */
      fetch_time();

      if (wpid < 0)
	{
	  log_error ("wait: %m");
	}
      else
	{
	  char s[128];

	  if (WIFEXITED(wstatus))
	    {
	      if (receiver)
		{
		  if (WEXITSTATUS(wstatus))
		    receiver->event("exit", failState, WEXITSTATUS(wstatus));
		  else
		    receiver->event("exit", succeedState, 0);
		}
	    }
	  else if (WIFSIGNALED(wstatus))
	    {
	      sprintf(s, "signal-%d", WTERMSIG(wstatus));
	      if (receiver)
		receiver->event(s, failState, -1);
	    }
	  else if (WIFSTOPPED(wstatus)
#ifdef WIFCONTINUED
		   || WIFCONTINUED(wstatus)
#endif
		   )
	    goto again;
	  else
	    {
	      log_error("Wait returned status %lx, which makes no sense.",
			(long)wstatus);
	    }
	}
    }
  else
    {
      execve(scriptName, argv, envp);
      log_error("execve (%s, ...): %m", scriptName);
      exit(1);
    }

  envCount = 0;

  log_info("Done running client script.");
}

void Script::add_item(const char *name, const char *fmt, ...)
{
  char spbuf [1024];
  char *s;
  unsigned len;
  char *str;
  va_list list;

  va_start(list, fmt);
  vprintf(fmt, list);
  va_end(list);
  putchar('\n');

  va_start(list, fmt);
  len = vsnprintf(spbuf, sizeof spbuf, fmt, list);
  va_end(list);

  str = (char *)safemalloc(strlen(prefix) + strlen(name) + len +
			    1 /* = */ + 1 /* / */ + 1 /* / */ + 1 /* NUL */);
  s = str;
  if (prefix[0])
    {
      strcpy(s, prefix);
      s += strlen(s);
      *s++ = '_';
    }
  strcpy(s, name);
  s += strlen(s);
  *s++ = '=';
  if (len >= sizeof spbuf)
    {
      va_start(list, fmt);
      vsnprintf(s, len + 1, fmt, list);
      va_end(list);
    }
  else
    strcpy(s, spbuf);
  addenv(str);
}

void Script::addenv(char *str)
{
  if (envCount == envMax)
    {
      char **nevp = (char **)safemalloc((envMax + 10) * sizeof (char *));
      if (envMax)
	{
	  memcpy(nevp, envp, envMax * sizeof (char *));
	  free(envp);
	}
      memset(nevp + envMax, 0, 10 * sizeof (char *));
      envp = nevp;
      envMax += 10;
    }
  envp[envCount++] = str;
}

int Script::option_name_clean(char *buf, size_t buflen, struct option *option)
{
  unsigned i, j;
  const char *s;

  j = 0;
  if (option->option_space != &dhcp_option_space)
    {
      s = option->option_space->name;
      i = 0;
    }
  else
    { 
      s = option->name;
      i = 1;
    }

  do
    {
      while (*s)
	{
	  if (j + 1 == buflen)
	    return 0;
	  if (*s == '-')
	    buf[j++] = '_';
	  else
	    buf[j++] = *s;
	  ++s;
	}
      if (!i)
	{
	  s = option->name;
	  if (j + 1 == buflen)
	    return 0;
	  buf[j++] = '_';
	}
      ++i;
    } while (i != 2);

  buf[j] = 0;
  return 1;
}

/* Local Variables:  */
/* mode:c++ */
/* c-file-style:"gnu" */
/* end: */
