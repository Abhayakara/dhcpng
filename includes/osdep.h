/* osdep.h

   Operating system dependencies... */

/*
 * Copyright (c) 2002-2006 Nominum, Inc.
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

#if !defined (__ISC_DHCP_OSDEP_H__)
#define __ISC_DHCP_OSDEP_H__

#include "site.h"

/* Porting::

   If you add a new network API, you must add a check for it below: */

#if !defined (USE_SOCKETS) && \
    !defined (USE_SOCKET_SEND) && \
    !defined (USE_SOCKET_RECEIVE) && \
    !defined (USE_RAW_SOCKETS) && \
    !defined (USE_RAW_SEND) && \
    !defined (USE_SOCKET_RECEIVE) && \
    !defined (USE_BPF) && \
    !defined (USE_BPF_SEND) && \
    !defined (USE_BPF_RECEIVE) && \
    !defined (USE_LPF) && \
    !defined (USE_LPF_SEND) && \
    !defined (USE_LPF_RECEIVE) && \
    !defined (USE_NIT) && \
    !defined (USE_NIT_SEND) && \
    !defined (USE_NIT_RECEIVE) && \
    !defined (USR_DLPI_SEND) && \
    !defined (USE_DLPI_RECEIVE)
#  define USE_DEFAULT_NETWORK
#endif

#if !defined (TIME_MAX)
# define TIME_MAX 2147483647
#endif

/* Porting::

   If you add a new system configuration file, include it here: */

#if defined (sun)
# if defined (__svr4__) || defined (__SVR4)
#  include "cf/sunos5-5.h"
# else
#  include "cf/sunos4.h"
# endif
#endif

#ifdef aix
#  include "cf/aix.h"
#endif

#ifdef bsdi
#  include "cf/bsdos.h"
#endif

#ifdef __NetBSD__
#  include "cf/netbsd.h"
#endif

#ifdef __FreeBSD__
#  include "cf/freebsd.h"
#endif

#ifdef OpenBSD
#  include "cf/openbsd.h"
#endif

#if defined (__osf__) && defined (__alpha)
#  include "cf/alphaosf.h"
#endif

#ifdef ultrix
#  include "cf/ultrix.h"
#endif

#ifdef linux
#  include "cf/linux.h"
#endif

#ifdef SCO
#  include "cf/sco.h"
#endif

#if defined (hpux) || defined (__hpux)
#  include "cf/hpux.h"
#endif

#ifdef __QNX__
#  include "cf/qnx.h"
#endif

#ifdef __CYGWIN32__
#  include "cf/cygwin32.h"
#endif

#ifdef __APPLE__
# include "cf/rhapsody.h"
#else
# if defined (NeXT)
#  include "cf/nextstep.h"
# endif
#endif

#ifdef NCR
# include "cf/ncr.h"
#endif

/* If we don't have a DLPI packet filter, we have to filter in userland.
   Probably not worth doing, actually. */
#if defined (USE_DLPI_RECEIVE) && !defined (USE_DLPI_PFMOD)
#  define USERLAND_FILTER
#endif

/* jmp_buf is assumed to be a struct unless otherwise defined in the
   system header. */
#ifndef jbp_decl
# define jbp_decl(x)	jmp_buf *x
#endif
#ifndef jref
# define jref(x)	(&(x))
#endif
#ifndef jdref
# define jdref(x)	(*(x))
#endif
#ifndef jrefproto
# define jrefproto	jmp_buf *
#endif

#ifndef BPF_FORMAT
# define BPF_FORMAT "/dev/bpf%d"
#endif

#if defined (F_SETFD) && !defined (HAVE_SETFD)
# define HAVE_SETFD
#endif

#if defined (IFF_POINTOPOINT) && !defined (HAVE_IFF_POINTOPOINT)
# define HAVE_IFF_POINTOPOINT
#endif

#if defined (AF_LINK) && !defined (HAVE_AF_LINK)
# define HAVE_AF_LINK
#endif

#if defined (ARPHRD_TUNNEL) && !defined (HAVE_ARPHRD_TUNNEL)
# define HAVE_ARPHRD_TUNNEL
#endif

#if defined (ARPHRD_LOOPBACK) && !defined (HAVE_ARPHRD_LOOPBACK)
# define HAVE_ARPHRD_LOOPBACK
#endif

#if defined (ARPHRD_ROSE) && !defined (HAVE_ARPHRD_ROSE)
# define HAVE_ARPHRD_ROSE
#endif

#if defined (ARPHRD_IEEE802) && !defined (HAVE_ARPHRD_IEEE802)
# define HAVE_ARPHRD_IEEE802
#endif

#if defined (ARPHRD_IEEE802_TR) && !defined (HAVE_ARPHRD_IEEE802_TR)
# define HAVE_ARPHRD_IEEE802_TR
#endif

#if defined (ARPHRD_FDDI) && !defined (HAVE_ARPHRD_FDDI)
# define HAVE_ARPHRD_FDDI
#endif

#if defined (ARPHRD_AX25) && !defined (HAVE_ARPHRD_AX25)
# define HAVE_ARPHRD_AX25
#endif

#if defined (ARPHRD_NETROM) && !defined (HAVE_ARPHRD_NETROM)
# define HAVE_ARPHRD_NETROM
#endif

#if defined (ARPHRD_METRICOM) && !defined (HAVE_ARPHRD_METRICOM)
# define HAVE_ARPHRD_METRICOM
#endif

#if defined (SO_BINDTODEVICE) && !defined (HAVE_SO_BINDTODEVICE)
# define HAVE_SO_BINDTODEVICE
#endif

#if defined (AF_LINK) && !defined (HAVE_AF_LINK)
# define HAVE_AF_LINK
#endif

/* Linux needs to define SHUT_* in /usr/include/sys/socket.h someday... */
#if !defined (SHUT_RD)
# define SHUT_RD 0
#endif

#if !defined (SOCKLEN_T)
#define SOCKLEN_T socklen_t
#endif

#endif /* __ISC_DHCP_OSDEP_H__ */
