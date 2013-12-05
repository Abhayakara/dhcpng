/* dhcpv6.h
 * 
 * DHCPv6 protocol structure and constant definitions.
 */

/* Copyright (c) 2005, 2006 Nominum, Inc.   All rights reserved.
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

/* DHCP Unique Identifier - an identifier that is specific to a particular
 * DHCP client.   All integers should be sent in network byte order.
 */

typedef struct duid {
	u_int32_t len;			/* Length of the DUID (not sent!) */
	union {
		u_int16_t type;		/* Type of duid. */
		struct duid_llt {	/* Link-layer address plus time. */
			u_int16_t type;
			u_int16_t hardware_type;
			u_int32_t time;
			unsigned char lladdr[1];
		} llt;
		struct duid_en {	/* Enterprise number plus id. */
			u_int16_t type;
			u_int32_t enterprise_number;
			unsigned char id[1];
		} en;
		struct duid_ll {	/* We have a built-in lladdr. */
			u_int16_t type;
			u_int16_t hardware_type;
			unsigned char lladdr[1];
		} ll;
	} data;
} duid_t;

/* DUID types. */
#define DUID_LLT 	1
#define DUID_EN		2
#define DUID_LL		3

/* Information Refresh Time intervals. */
#define DHCPV6_IRT_DEFAULT	86400
#define DHCPV6_IRT_MINIMUM	600

/* The protocol specification doesn't recommend a maximum for the IRT,
 * but in general information requests are very cheap, so if the maximum
 * that's specified is quite high, it's probably a denial of service attack
 * of some kind, and so we want to disregard it.   Since the protocol doesn't
 * specify a maximum, we don't reject packets with an IRT longer than this,
 * but we also don't honor the IRT in the packet.
 */
#define DHCPV6_IRT_MAXIMUM	86400

/* Client and Server messages. */
typedef struct dhcpv6_cs_message {
	u_int32_t len;			    /* Length of message (not sent!) */
	unsigned char type_xid[4];	   /* Type and xid, mashed together. */
	unsigned char options[1];	       /* Options - variable length. */
} dhcpv6_cs_message_t;

/* Set the transaction ID in a DHCPv6 message. */
#define DHCPV6_MSG_SET_XID(msg, xid) { \
		(msg)->type_xid[1] = ((xid) & 0xFF0000) >> 16;	\
		(msg)->type_xid[2] = ((xid) & 0xFF00) >> 8;	\
		(msg)->type_xid[3] = (xid) & 0xFF);

#define DHCPV6_MSG_SET_TYPE(msg, type) (msg)->type_xid[0] = type

/* DHCPv6 message types. */
#define DHCPV6_SOLICIT			1
#define DHCPV6_ADVERTISE		2
#define DHCPV6_REQUEST			3
#define DHCPV6_CONFIRM			4
#define DHCPV6_RENEW			5
#define DHCPV6_REBIND			6
#define DHCPV6_REPLY			7
#define DHCPV6_RELEASE			8
#define DHCPV6_DECLINE			9
#define DHCPV6_RECONFIGURE		10
#define DHCPV6_INFORMATION_REQUEST	11

/* In RFC3315, the following message types are written as RELAY-FORW
 * and RELAY-REPL.  I don't know why.  RELAY-FORWARD has fewer
 * characters than INFORMATION-REQUEST.  Perhaps there was some kind
 * of atavistic desire for names that would fit in a single 32-bit
 * word.  Anyway, i'm being verbose.   Deal.   :')
 */
#define DHCPV6_RELAY_FORWARD		12
#define DHCPV6_RELAY_REPLY		13

/* Get the transaction ID out of the message. */
#define DHCPV6_MSG_GET_XID(msg) (			 \
		(((unsigned)(msg)->type_xid[1]) << 16) | \
		(((unsigned)(msg)->type_xid[2]) << 8) |	 \
		((unsigned)(msg)->type_xid[3]))

#define DHCPV6_MSG_GET_TYPE(msg, type) ((msg)->type_xid[0])

typedef struct dhcpv6_relay_message {
	unsigned char type;
	unsigned char hop_count;
	unsigned char link_address[16];
	unsigned char peer_address[16];
	char options[1];
} dhcpv6_relay_message_t;

#define DHCPV6_DUID				1
#define DHCPV6_SERVER_IDENTIFIER		2
#define DHCPV6_IA_NA				3
#define DHCPV6_IA_TA				4
#define DHCPV6_IA_ADDRESS			5
#define DHCPV6_REQUESTED_OPTIONS		6
#define DHCPV6_PREFERENCE			7
#define DHCPV6_ELAPSED_TIME			8
#define DHCPV6_RELAY_MESSAGE			9
#define DHCPV6_AUTHENTICATION			10
#define DHCPV6_SERVER_UNICAST_ADDRESS		11
#define DHCPV6_STATUS_CODE			13
#define DHCPV6_RAPID_COMMIT			14
#define DHCPV6_USER_CLASS			15
#define DHCPV6_VENDOR_CLASS			16
#define DHCPV6_VENDOR_SPECIFIC_INFORMATION	17
#define DHCPV6_INTERFACE_IDENTIFIER		18
#define DHCPV6_RECONFIGURE_MESSAGE		19
#define DHCPV6_RECONFIGURE_ACCEPTED		20
#define DHCPV6_SIP_SERVER_NAMES			21
#define DHCPV6_SIP_SERVERS			22
#define DHCPV6_DOMAIN_NAME_SERVERS		23
#define DHCPV6_DOMAIN_SEARCH_LIST		24
#define DHCPV6_IA_PD				25
#define DHCPV6_IA_PREFIX			27
#define DHCPV6_NIS_SERVERS			28
#define DHCPV6_NISPLUS_SERVERS			29
#define DHCPV6_NIS_DOMAINS			30
#define DHCPV6_NISPLUS_DOMAINS			31
#define DHCPV6_INFORMATION_REFRESH_TIME		32
#define DHCPV6_FQDN				39

/* Status codes: */
#define DHCPV6_SUCCESS				0
#define DHCPV6_UNSPECIFIED_FAILURE		1
#define DHCPV6_NO_ADDRS_AVAILABLE		2
#define DHCPV6_BINDING_UNAVAILABLE		3
#define DHCPV6_BINDING_NOT_ON_LINK		4
#define DHCPV6_USE_MULTICAST			5
