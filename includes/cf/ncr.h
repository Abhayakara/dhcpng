/* sco.h

   System dependencies for NCR MP-RAS...

   Based on the SCO header file. */

/*
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
 * 3. Neither the name of The Internet Software Consortium nor the names
 *    of its contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INTERNET SOFTWARE CONSORTIUM AND
 * CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE INTERNET SOFTWARE CONSORTIUM OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <syslog.h>
#include <sys/types.h>
#include <sys/bitypes.h>

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <setjmp.h>
#include <limits.h>

extern int h_errno;

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_arp.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

/* NCR doesn't have /var/run. */
#ifndef _PATH_DHCPD_CONF
#define _PATH_DHCPD_CONF	"/etc/dhcpd.conf"
#endif
#ifndef _PATH_DHCPD_PID
#define _PATH_DHCPD_PID		"/etc/dhcpd.pid"
#endif
#ifndef _PATH_DHCLIENT_PID
#define _PATH_DHCLIENT_PID  "/etc/dhclient.pid"
#endif
#ifndef _PATH_DHCRELAY_PID
#define _PATH_DHCRELAY_PID  "/etc/dhcrelay.pid"
#endif
#ifndef _PATH_DHCPD_DB
#define _PATH_DHCPD_DB      "/etc/dhcpd.leases"
#endif
#ifndef _PATH_DHCLIENT_DB
#define _PATH_DHCLIENT_DB   "/etc/dhclient.leases"
#endif

/* Varargs stuff: use stdarg.h instead ... */
#include <stdarg.h>
#define VA_DOTDOTDOT ...
#define VA_start(list, last) va_start (list, last)
#define va_dcl

/* By default, use BSD Socket API for receiving and sending packets.
   This actually works pretty well on Solaris, which doesn't censor
   the all-ones broadcast address. */
#if defined (USE_DEFAULT_NETWORK)
# define USE_SOCKETS
#endif

#define EOL	'\n'
#define VOIDPTR	void *

/* socklen_t */
typedef size_t socklen_t;

/*
 * Time stuff...
 *
 * Definitions for an ISC DHCPD system that uses time_t
 * to represent time internally as opposed to, for example,  struct timeval.)
 */

#include <time.h>
#include <sys/time.h>

#define TIME time_t
#define GET_TIME(x)	time ((x))

#ifdef NEED_PRAND_CONF
const char *cmds[] = {
	"/bin/ps -ef 2>&1",
	"/etc/arp -n -a 2>&1",
	"/usr/bin/netstat -an 2>&1",
	"/bin/df  2>&1",
	"/usr/bin/uptime  2>&1",
	"/usr/bin/netstat -s 2>&1",
	"/usr/bin/vmstat  2>&1",
	"/usr/bin/w  2>&1",
	NULL
};

const char *dirs[] = {
	"/tmp",
	"/usr/tmp",
	".",
	"/",
	"/var/spool",
	"/var/adm",
	"/dev",
	NULL
};

const char *files[] = {
	NULL
};
#endif /* NEED_PRAND_CONF */
