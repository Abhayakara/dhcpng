/* linux.h

   System dependencies for Linux.

   Based on a configuration originally supplied by Jonathan Stone. */

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

#include <features.h>
#ifndef __BIT_TYPES_DEFINED__
#define __BIT_TYPES_DEFINED__
#undef __USE_BSD
#ifdef __x86_64__
typedef char int8_t;
typedef short int16_t;
typedef int int32_t;
typedef unsigned char u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned int u_int32_t;
typedef unsigned long u_int64_t;
#else
typedef char int8_t;
typedef short int16_t;
typedef long int32_t;
typedef unsigned char u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned long u_int32_t;
#endif /* __x86_64__ */
#endif /* __BIT_TYPES_DEFINED__ */

typedef u_int8_t u8;
typedef u_int16_t u16;
typedef u_int32_t u32;

#ifdef __x86_64__
#define PTRSIZE_64BIT
#endif

#include <syslog.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <setjmp.h>
#include <limits.h>

#include <net/if.h>
#include <net/route.h>

#if LINUX_MAJOR == 1
# include <linux/if_arp.h>
# include <linux/time.h>		/* also necessary */
#else
# include <net/if_arp.h>
# include <netpacket/packet.h>
#endif

#include <sys/time.h>		/* gettimeofday()*/

/* I'm not at all clear on where this ought to go.   The idea with this
 * version of the client is that it's generally not in charge of maintaining
 * state.   I don't expect to see a lot of dhcp-related files in /var/lib,
 * so it seems like /var/lib/misc is a good place for it.   Nice long name
 * for clarity.   :')
 */

#ifndef _PATH_DHCLIENT_DUID
#define _PATH_DHCLIENT_DUID	"/var/lib/dhcp3/dhcp-client-duid"
#endif

/* Varargs stuff... */
#include <stdarg.h>
#define VA_DOTDOTDOT ...
#define VA_start(list, last) va_start (list, last)
#define va_dcl

#define vsnprintf(buf, size, fmt, list) vsprintf (buf, fmt, list)
#define NO_SNPRINTF

#define VOIDPTR	void *

#define EOL	'\n'

/* Time stuff... */

#include <time.h>

#define TIME time_t
#define GET_TIME(x)	time ((x))

#define ALIAS_NAMES_PERMUTED
#define SKIP_DUMMY_INTERFACES

#define NEED_V4ONLY_SOCKET
#define NEED_LPF
#define NEED_PACKET_DECODING
#define NEED_USERLAND_FILTER
/* At the time of this writing, the Linux headers do not follow RFC3542. */
#ifndef IPV6_RECVPKTINFO
# define IPV6_RECVPKTINFO IPV6_PKTINFO
#endif

#define HAVE_AF_PACKET

#ifdef NEED_PRAND_CONF
#ifndef HAVE_DEV_RANDOM
 # define HAVE_DEV_RANDOM 1
 #endif /* HAVE_DEV_RANDOM */

const char *cmds[] = {
	"/bin/ps -axlw 2>&1",
	"/sbin/arp -an 2>&1",
	"/bin/netstat -an 2>&1",
	"/bin/df  2>&1",
	"/usr/bin/dig com. soa +ti=1 +retry=0 2>&1",
	"/usr/bin/uptime  2>&1",
	"/bin/netstat -s 2>&1",
	"/usr/bin/dig . soa +ti=1 +retry=0 2>&1",
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
	"/dev",
	"/var/spool/mail",
	"/home",
	"/usr/home",
	NULL
};

const char *files[] = {
	"/proc/stat",
	"/proc/rtc",
	"/proc/meminfo",
	"/proc/interrupts",
	"/proc/self/status",
	"/var/log/messages",
	"/var/log/wtmp",
	"/var/log/lastlog",
	NULL
};
#endif /* NEED_PRAND_CONF */
