/* dhcpd.h

   Definitions for dhcpd... */

/* Copyright (c) 2002-2006 Nominum, Inc.   All rights reserved.
 *
 * Copyright (c) 1996-2001 Internet Software Consortium.
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

#ifndef __CYGWIN32__
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>

#include <netdb.h>
#else
#define fd_set cygwin_fd_set
#include <sys/types.h>
#endif
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <ctype.h>
#include <time.h>

#include "cdefs.h"
#include "osdep.h"

#include "arpa/nameser.h"

#include "hash.h"
typedef struct hash_table option_space_hash_t;
typedef struct hash_table option_hash_t;
typedef struct hash_table dns_zone_hash_t;
typedef struct hash_table auth_hash_t;

#include "dhcp.h"
#include "dhcpv6.h"
#include "inet.h"

#include <isc-dhcp/result.h>

#if !defined (OPTION_HASH_SIZE)
# define OPTION_HASH_SIZE 17
# define OPTION_HASH_PTWO 32	/* Next power of two above option hash. */
# define OPTION_HASH_EXP 5	/* The exponent for that power of two. */
#endif

#define compute_option_hash(x) \
	(((x) & (OPTION_HASH_PTWO - 1)) + \
	 (((x) >> OPTION_HASH_EXP) & \
	  (OPTION_HASH_PTWO - 1))) % OPTION_HASH_SIZE;

enum dhcp_shutdown_state {
	shutdown_listeners,
	shutdown_omapi_connections,
	shutdown_drop_omapi_connections,
	shutdown_dhcp,
	shutdown_done
};

/* A pair of pointers, suitable for making a linked list. */
typedef struct _pair {
	caddr_t car;
	struct _pair *cdr;
} *pair;

struct option_chain_head {
	pair first;
};

struct enumeration_value {
	const char *name;
	u_int8_t value;
};

struct enumeration {
	struct enumeration *next;
	const char *name;
	struct enumeration_value *values;
};	

/* A data buffer with a reference count. */
struct buffer {
	int refcnt;
	int size;
	unsigned char data [1];
};

/* XXX The mechanism by which data strings are returned is currently
   XXX broken: rather than returning an ephemeral pointer, we create
   XXX a reference to the data in the caller's space, which the caller
   XXX then has to dereference - instead, the reference should be
   XXX ephemeral by default and be made a persistent reference explicitly. */
/* XXX on the other hand, it seems to work pretty nicely, so maybe the
   XXX above comment is meshuggenah. */

/* A string of data bytes, possibly accompanied by a larger buffer. */
struct data_string {
	struct buffer *buffer;
	const unsigned char *data;
	unsigned len;	/* Does not include NUL terminator, if any. */
	int terminated;
};

/* DNS host entry structure... */
struct dns_host_entry {
	TIME timeout;
	struct data_string data;
	char hostname [1];
};

/* The option data structure contains the description of an option - that is,
 * its format, its option code, and the option space in which it lives, as
 * well as its name.   Use find_option to get the definition for a particular
 * option by option code.   We normally don't look them up by name, since
 * that's slower, and not any easier.   Use the DHO_* and DHCPV6_* manifest
 * constants from dhcp.h and dhcpv6.h instead of numeric codes - it makes the
 * code easier to read.
 */
struct option {
	char *name;
	char *format;
	struct option_space *option_space;
	unsigned code;
};

/* const_option is identical to option, except that it can be statically
 * initialized because the name and format are const char *.   This is all
 * in aid of allowing us to declare initializers for options in tables.c.
 * You never see a const_option structure outside of tables.c.
 */
struct const_option {
	const char *name;
	const char *format;
	struct option_space *option_space;
	unsigned code;
};

/* Failover FQDN option. */
typedef struct {
	u_int16_t flags;
	unsigned length;
	u_int8_t *data;
} ddns_fqdn_t;

/* Variable-length array of data. */

struct string_list {
	struct string_list *next;
	char string [1];
};

/* A name server, from /etc/resolv.conf. */
struct name_server {
	struct name_server *next;
	struct sockaddr_in addr;
	TIME rcdate;
};

/* A domain search list element. */
struct domain_search_list {
	struct domain_search_list *next;
	char *domain;
	TIME rcdate;
};

typedef struct auth_key {
	char *name;
	char *algorithm;
	struct data_string key;
} auth_key_t;

/* Option tag structures are used to build chains of option tags, for
   when we're sure we're not going to have enough of them to justify
   maintaining an array. */

struct option_tag {
	struct option_tag *next;
	u_int8_t data [1];
};

/* An agent option structure.   We need a special structure for the
   Relay Agent Information option because if more than one appears in
   a message, we have to keep them seperate. */

struct agent_options {
	struct agent_options *next;
	int length;
	struct option_tag *first;
};

/* The option_cache structure stores the contents of an option that has
 * been received on the wire, or the contents of an option that needs to
 * be packed so it can be sent on the wire.
 *
 * The next pointer allows option values to be chained; if more than one
 * of a particular option is to be sent, we make a linked list of these
 * options.
 *
 * On receipt, the setting of the concatenate flag in the option space
 * determines whether we create a linked list when more then one of a
 * particular option appears, or whether we concatenate the contents
 * of the options into a single option_cache structure.  Generally, we
 * concatenate for DHCPv4, and make lists for DHCPv6.
 */
struct option_cache {
	struct option_cache *next;
	struct option *option;
	struct data_string data;
};

/* The option_state structure represents a complete set of options, possibly
 * in more than one option space.  In the world of DHCPv4, this structure is
 * going to contain all of the options in all the option spaces, so even though
 * for example nwip options are encapsulated together in a suboption of the
 * nwip option, they are represented here as options in the nwip option space,
 * not just as a single blob of data.   Of course, you can also get to the
 * single blob of data if you want.
 *
 * In DHCPv6-land, there is really only ever one option space - the DHCPv6
 * option space.   Actually, you could have multiple vendor encapsulations,
 * but right now this isn't supported.   So for now, an option_state struct
 * is always going to contain all the options in the packet.   But it's a
 * bit more complicated than that, because in DHCPv6 we have DHCPv6 options
 * encapsulated inside of DHCPv6 options.   There's no way to make that work
 * with the flat structure we use in DHCPv4, so instead we have option_state
 * structures for each level of encapsulation.   A little less automatic
 * than the way things are done in DHCPv4, unfortunately.
 *
 * To find the value of a particular option in an option_state structure,
 * use lookup_option().   To stash an option in an option_state structure,
 * use store_option().   To get rid of an existing option in an option_state
 * structure, use delete_option().   Use option_space_encapsulate() to convert
 * an option_state structure into a buffer containing wire-format options. 
 * To go the other way, use decode_option_space().
 */
struct option_state {
	unsigned option_space_count;
	int site_option_space;
	unsigned site_code_min;
	VOIDPTR option_spaces [1];
};

/* An option space is the container for an entire collection of option
 * definitions (struct option).   Option codes are unique only within an
 * option space - this allows us, in DHCPv4-land, to use the same wire format
 * and option codes to represent more than one set of options - since
 * option codes are scarce in DHCPv4, this is important.   It's also a handy
 * way to pick apart certain complex options - specifically, the fqdn option.
 */
struct option_space {
	const char *name;
	struct option_cache *(*lookup_func) (struct option_space *,
					     struct option_state *,
					     unsigned);
	void (*save_func) (struct option_space *, struct option_state *,
			   struct option_cache *);
	void (*foreach) (struct option_state *, struct option_space *, void *,
			 void (*) (struct option_cache *,
				   struct option_state *,
				   struct option_space *, void *));
	void (*delete_func) (struct option_space *option_space,
			     struct option_state *, unsigned);
	int (*option_state_dereference) (struct option_space *,
					 struct option_state *,
					 const char *, int);
	int (*decode) (struct option_state *,
		       const unsigned char *, unsigned, struct option_space *);
	int (*encapsulate) (struct data_string *,
			    struct option_state *, struct option_space *);
	void (*store_tag) PROTO ((unsigned char *, u_int32_t));
	void (*store_length) PROTO ((unsigned char *, u_int32_t));
	int tag_size, length_size;
	int concatenate;
	struct option *enc_opt;
	unsigned index;
	unsigned max_option;
	struct option **optvec;
};

/* A DHCPv4 packet and the pointers to its option values. */
struct packet {
	struct dhcp_packet *raw;
	unsigned packet_length;
	int packet_type;
	int options_valid;
	int client_port;
	struct iaddr sender_addr;
	struct interface_info *interface;	/* Interface on which packet
						   was received. */

	/* Information for relay agent options (see
	   draft-ietf-dhc-agent-options-xx.txt). */
	u_int8_t *circuit_id;		/* Circuit ID of client connection. */
	int circuit_id_len;
	u_int8_t *remote_id;		/* Remote ID of client. */
	int remote_id_len;

	int got_requested_address;	/* True if client sent the
					   dhcp-requested-address option. */

	struct shared_network *shared_network;
	struct option_state *options;

	int authenticated;
};

/* A network interface's MAC address. */

struct hardware {
	u_int8_t hlen;
	u_int8_t hbuf [17];
};

#define	ROOT_GROUP	0
#define HOST_DECL	1
#define SHARED_NET_DECL	2
#define SUBNET_DECL	3
#define CLASS_DECL	4
#define	GROUP_DECL	5
#define POOL_DECL	6

#if !defined (DEFAULT_DDNS_TTL)
# define DEFAULT_DDNS_TTL 3600
#endif

/* Client option names */

#define	CL_TIMEOUT		1
#define	CL_SELECT_INTERVAL	2
#define CL_REBOOT_TIMEOUT	3
#define CL_RETRY_INTERVAL	4
#define CL_BACKOFF_CUTOFF	5
#define CL_INITIAL_INTERVAL	6
#define CL_BOOTP_POLICY		7
#define	CL_SCRIPT_NAME		8
#define CL_REQUESTED_OPTIONS	9
#define CL_REQUESTED_LEASE_TIME	10
#define CL_SEND_OPTIONS		11
#define CL_MEDIA		12
#define	CL_REJECT_LIST		13

#ifndef CL_DEFAULT_TIMEOUT
# define CL_DEFAULT_TIMEOUT	60
#endif

#ifndef CL_DEFAULT_SELECT_INTERVAL
# define CL_DEFAULT_SELECT_INTERVAL 0
#endif

#ifndef CL_DEFAULT_REBOOT_TIMEOUT
# define CL_DEFAULT_REBOOT_TIMEOUT 10
#endif

#ifndef CL_DEFAULT_RETRY_INTERVAL
# define CL_DEFAULT_RETRY_INTERVAL 300
#endif

#ifndef CL_DEFAULT_BACKOFF_CUTOFF
# define CL_DEFAULT_BACKOFF_CUTOFF 120
#endif

#ifndef CL_DEFAULT_INITIAL_INTERVAL
# define CL_DEFAULT_INITIAL_INTERVAL 10
#endif

#ifndef CL_DEFAULT_BOOTP_POLICY
# define CL_DEFAULT_BOOTP_POLICY P_ACCEPT
#endif

#ifndef CL_DEFAULT_REQUESTED_OPTIONS
# define CL_DEFAULT_REQUESTED_OPTIONS \
	{ DHO_SUBNET_MASK, \
	  DHO_BROADCAST_ADDRESS, \
	  DHO_TIME_OFFSET, \
	  DHO_ROUTERS, \
	  DHO_DOMAIN_NAME, \
	  DHO_DOMAIN_NAME_SERVERS, \
	  DHO_HOST_NAME }
#endif

/* Group of declarations that share common parameters. */
struct group {
	struct group *next;
	int authoritative;
	struct executable_statement *statements;
};

class DHCPv6Listener; /* forward */
class DHCPv6Client; /* forward */
class DHCPv4Listener; /* forward */
class DHCPv4Client; /* forward */

/* Authentication and BOOTP policy possibilities (not all values work
   for each). */
enum policy { P_IGNORE, P_ACCEPT, P_PREFER, P_REQUIRE, P_DONT };

/* Configuration information from the config file... */
struct client_config {
	u_int32_t *required_options;	/* Options server must supply. */
	u_int32_t *requested_options;	/* Options to request from server. */
	u_int32_t *dhcpv6_requested_options;	/* DHCPv6 ORO. */

	struct interface_info *interface;
	char *name;

	unsigned long long initial;	/* All exponential backoff intervals
					   start here. */
	unsigned long long retry;	/* If the protocol failed to produce
					   an address before the timeout,
					   try the protocol again after this
					   many seconds. */
	unsigned long long select;	/* Wait this many seconds from the
					   first DHCPDISCOVER before
					   picking an offered lease. */
	unsigned long long reboot;	/* When in INIT-REBOOT, wait this
					   long before giving up and going
					   to INIT. */
	unsigned long long cutoff;	/* When doing exponential backoff,
					   never back off to an interval
					   longer than this amount. */
	u_int32_t requested_lease;	/* Requested lease time, if user
					   doesn't configure one. */
	char *vendor_space_name;	/* Name of vendor ID option space. */
	enum policy bootp_policy;
					/* Ignore, accept or prefer BOOTP
					   responses. */
	enum policy auth_policy;	/* Require authentication, prefer
					   authentication, or don't try to
					   authenticate. */

	struct iaddrlist *reject_list;	/* Servers to reject. */
};

/* Relay agent server list. */
struct server_list {
	struct server_list *next;
	struct sockaddr_in to;
};

/* DHCPv6 Identity Association address (can be more than one per). */
struct ia_addr {
	struct ia_addr *next;		        /* If there's more than one. */
	struct iaddr address;			     /* Actual IPv6 address. */
	u_int64_t valid, preferred;	   /* Valid and preferred lifetimes. */
	struct ia *ia;			      /* IA containing this address. */

	/* Options to send to the server in this IA_ADDR. */
	struct option_state *send_options;

	/* Options received for this IA. */
	struct option_state *recv_options;
};

/* DHCPv6 Identity Association... */
struct ia {
	struct ia *next;    /* If there's more then one IA for an interface. */
	struct ia_addr *addresses;		    /* Addresses in this IA. */
	u_int64_t expiry;	   /* Expiry of the earliest preferred time. */

	/* IA Identifier. */
	u_int32_t id;						    /* IAID. */

	/* IA renewal and rebind times from server. */
	u_int32_t t1;
	u_int32_t t2;

	/* Options to send to the server in this IA. */
	struct option_state *send_options;

	/* Options received for this IA. */
	struct option_state *recv_options;
};

/* A complete, decoded response from a DHCPv6 server. */
struct dhcpv6_response {
  struct dhcpv6_response *next;
  struct option_state *options;
  struct ia *ias;
  u_int32_t xid;
  DHCPv6Client *state;
  struct interface_info *interface;
  TIME received_time;
  u_int8_t message_type;
  const char *name;
  struct dhcpv6_response *outer;
};

struct dhcpv6_client_context {
	struct dhcpv6_client_context *next;
	struct data_string duid;
};

/* Information about each network interface. */

struct interface_info {
	struct interface_info *next;	/* Next interface in list... */
	struct hardware lladdr;		/* Its link-layer address. */
	struct in_addr *ipv4s;		/* IPv4 Addresses associated with
					   interface. */
	int ipv4_addr_count;		/* Number of addresses associated with
					   interface. */
	int ipv4_addr_max;		/* Max number of addresses we can
					   store in current buffer. */

	struct in6_addr *ipv6s;		/* IPv6 Addresses associated with
					   interface. */
	int ipv6_addr_count;		/* Number of addresses associated with
					   interface. */
	int ipv6_addr_max;		/* Max number of addresses we can
					   store in current buffer. */
	int ipv6_ll_index;		/* Index of the link-local address for
					   this interface. */

	char name[IFNAMSIZ];		/* Its name... */
	int index;			/* Its index. */
	unsigned char *rbuf;		/* Read buffer, if required. */
	unsigned int rbuf_max;		/* Size of read buffer. */
	size_t rbuf_offset;		/* Current offset into buffer. */
	size_t rbuf_len;		/* Length of data in buffer. */

	int v4configured;		/* If set to 1, interface has at
					 * least one usable IPv4 address.
					 */
	int v6configured;		/* If set to 1, interface has at
					 * least one usable IPv6 address.
					 */
	int requested;			/* User has asked us to operate on
					 * this interface.
					 */

	/* Specific to the DHCPv4 relay agent. */
	u_int8_t *circuit_id;		/* Circuit ID associated with this
					   interface. */
	unsigned circuit_id_len;	/* Length of Circuit ID, if there
					   is one. */
	u_int8_t *remote_id;		/* Remote ID associated with this
					   interface (if any). */
	unsigned remote_id_len;		/* Length of Remote ID. */
	struct server_list *servers;	/* List of relay servers for this
					   interface. */

	/* Only used by DHCP client code. */
	DHCPv4Listener *v4listener;
	int num_v6listeners;
	int max_v6listeners;
	DHCPv6Listener **v6listeners;

#if defined(NEED_LPF) || defined(NEED_BPF)
	int pf_sock;
#endif
};

struct hardware_link {
	struct hardware_link *next;
	char name [IFNAMSIZ];
	struct hardware address;
};

typedef void (*tvref_t)(void *, void *);
typedef void (*tvunref_t)(void *);
struct timeout {
	struct timeout *next;
	TIME when;
	void (*func)(void *);
	void *what;
};

struct protocol {
	struct protocol *next;
	int fd;
	void (*handler)(struct protocol *);
	void *local;
};

struct icmp_state {
	int socket;
	void (*icmp_handler)(struct iaddr, u_int8_t *, int);
};

/* Bitmask of dhcp option codes. */
typedef unsigned char option_mask [16];

/* DHCP Option mask manipulation macros... */
#define OPTION_ZERO(mask)	(memset (mask, 0, 16))
#define OPTION_SET(mask, bit)	(mask [bit >> 8] |= (1 << (bit & 7)))
#define OPTION_CLR(mask, bit)	(mask [bit >> 8] &= ~(1 << (bit & 7)))
#define OPTION_ISSET(mask, bit)	(mask [bit >> 8] & (1 << (bit & 7)))
#define OPTION_ISCLR(mask, bit)	(!OPTION_ISSET (mask, bit))

/* An option occupies its length plus two header bytes (code and
    length) for every 255 bytes that must be stored. */
#define OPTION_SPACE(x)		((x) + 2 * ((x) / 255 + 1))

/* Default path to dhcpd config file. */
#ifndef _PATH_DHCLIENT_PID
#define _PATH_DHCLIENT_PID	"/var/run/dhclient.pid"
#endif

#ifndef _PATH_DHCLIENT_DUID
#define _PATH_DHCLIENT_DUID	"/var/db/dhcp-client-duid"
#endif

#ifndef _PATH_DHCLIENT_SCRIPT
#define _PATH_DHCLIENT_SCRIPT	"/etc/dhcp3/dhcp-client-script"
#endif

#ifndef _PATH_RESOLV_CONF
#define _PATH_RESOLV_CONF	"/etc/resolv.conf"
#endif

#ifndef _PATH_DHCRELAY_PID
#define _PATH_DHCRELAY_PID	"/var/run/dhcrelay.pid"
#endif

#ifndef DHCPD_LOG_FACILITY
#define DHCPD_LOG_FACILITY	LOG_DAEMON
#endif

#define MAX_TIME 0x7fffffff
#define MIN_TIME 0

HASH_FUNCTIONS_DECL (option_space, const char *, struct option_space, option_space_hash_t)
HASH_FUNCTIONS_DECL (option, const char *, struct option, option_hash_t)
HASH_FUNCTIONS_DECL (dns_zone, const char *, struct dns_zone, dns_zone_hash_t)
HASH_FUNCTIONS_DECL (auth_key, const char *, auth_key_t, auth_hash_t)

/* options.c */

extern struct option *vendor_cfg_option;
int parse_options(struct packet *);
int parse_option_buffer(struct option_state *, const unsigned char *,
			unsigned, struct option_space *);
struct option_space *find_option_option_space (struct option *, const char *);
int parse_encapsulated_suboptions (struct option_state *, struct option *,
				   const unsigned char *, unsigned,
				   struct option_space *, const char *);
int parse_twobyte_option_buffer(struct option_state *,
				const unsigned char *,
				unsigned, struct option_space *);
int decode_option_space(struct option_state *options,
			const unsigned char *buffer,
			unsigned len, struct option_space *option_space);
int fqdn_option_space_decode(struct option_state *,
			 const unsigned char *,
			 unsigned, struct option_space *);
int cons_options(struct dhcp_packet *,
		 int, struct option_state *,
		 int, int, int, struct data_string *, const char *);
int store_options(int *, unsigned char *, unsigned,
		  struct option_state *,
		  unsigned *, unsigned, unsigned, unsigned,
		  int, const char *);
int option_state_size(struct option_state *os, struct option_space *base);
const char *pretty_print_option(struct option *, const unsigned char *,
				unsigned, int);
int get_option (struct data_string *, struct option_space *,
		struct option_state *, unsigned);
struct option_cache *lookup_option(struct option_space *,
				   struct option_state *, unsigned);
struct option_cache *lookup_hashed_option(struct option_space *,
					  struct option_state *, unsigned);
void save_option_buffer (struct option_space *, struct option_state *,
			 struct buffer *, unsigned char *, unsigned,
			 struct option *, int);
void save_option(struct option_space *,
		 struct option_state *, struct option_cache *);
void save_hashed_option(struct option_space *,
			struct option_state *, struct option_cache *);
void delete_option(struct option_space *, struct option_state *, unsigned);
void delete_hashed_option(struct option_space *,
			  struct option_state *, unsigned);
void data_string_need(struct data_string *result, int need);
void data_string_putc(struct data_string *dest, int c);
void data_string_strcat(struct data_string *dest, const char *s);
void data_string_printf(struct data_string *dest, const char *fmt, ...)
	__attribute__((__format__(__printf__,2,3)));
void store_option(struct data_string *,
		  struct option_space *,
		  struct option_cache *);
int option_space_encapsulate(struct data_string *,
			     struct option_state *,
			     struct data_string *);
int hashed_option_space_encapsulate(struct data_string *,
				    struct option_state *,
				    struct option_space *);
int nwip_option_space_encapsulate(struct data_string *,
				  struct option_state *,
				  struct option_space *);
int fqdn_option_space_encapsulate (struct data_string *,
				   struct option_state *,
				   struct option_space *);
void suboption_foreach (struct option_state *, struct option_space *, void *,
			void (*) (struct option_cache *,
				  struct option_state *,
				  struct option_space *, void *),
			struct option_cache *, const char *);
int dns_fqdn_to_wire (unsigned char *, const unsigned char *, unsigned);
void option_space_foreach (struct option_state *,
			   struct option_space *, void *,
			   void (*) (struct option_cache *,
				     struct option_state *,
				     struct option_space *, void *));
void hashed_option_space_foreach (struct option_state *,
				  struct option_space *, void *,
				  void (*) (struct option_cache *,
					    struct option_state *,
					    struct option_space *, void *));
int linked_option_get(struct data_string *,
		      struct option_space *, struct option_state *, unsigned);
void save_linked_option (struct option_space *, struct option_state *,
			 struct option_cache *);
void linked_option_space_foreach (struct option_state *,
				  struct option_space *, void *,
				  void (*) (struct option_cache *,
					    struct option_state *,
					    struct option_space *, void *));
int linked_option_space_encapsulate (struct data_string *,
				     struct option_state *,
				     struct option_space *);
void delete_linked_option (struct option_space *,
			   struct option_state *, unsigned);
struct option_cache *lookup_linked_option (struct option_space *,
					   struct option_state *, unsigned);
void do_packet(struct interface_info *,
	       struct dhcp_packet *, unsigned, unsigned int, struct iaddr);
void add_enumeration (struct enumeration *);
struct enumeration *find_enumeration (const char *, int);
struct enumeration_value *find_enumeration_value (const char *, int,
						  const char *);
struct option *
find_option(struct option_space *option_space, unsigned code);
struct option *
define_option(struct option_space *option_space,
	      unsigned code, const char *format, const char *name);

/* alloc.c */
void *safemalloc(size_t);
struct buffer *buffer_allocate (unsigned len);
void data_string_copy (struct data_string *dest, struct data_string *src);
void data_string_forget (struct data_string *data);
void data_string_truncate (struct data_string *dp, unsigned len);
struct dns_host_entry *dns_host_entry_allocate (const char *hostname);
struct option_state *new_option_state(void);
pair cons(caddr_t, pair);
struct option_cache *make_const_option_cache(struct buffer **,
					     u_int8_t *, unsigned,
					     struct option *);

/* print.c */
char *quotify_string (const char *);
char *quotify_buf (const unsigned char *, unsigned);
char *print_base64 (const unsigned char *, unsigned);
char *print_hw_addr(int, int, unsigned char *);
void dump_raw(const unsigned char *, unsigned);
void dump_packet_option (struct option_cache *oc,
			 struct option_state *options,
			 struct option_space *u, void *foo);
void dump_packet(struct packet *);
void hash_dump(struct hash_table *);
char *print_hex_1(unsigned, const u_int8_t *, unsigned);
char *print_hex_2(unsigned, const u_int8_t *, unsigned);
char *print_hex_3(unsigned, const u_int8_t *, unsigned);
char *print_dotted_quads(unsigned, const u_int8_t *);
char *print_dec_1(unsigned long);
char *print_dec_2(unsigned long);
int token_print_indent_concat (FILE *, int, int,
			       const char *, const char *, ...);
int token_indent_data_string (FILE *, int, int, const char *, const char *,
			      struct data_string *);
int token_print_indent (FILE *, int, int,
			const char *, const char *, const char *);
void indent_spaces (FILE *, int);

/* socket.c */
ssize_t send_packet(struct interface_info *, void *, size_t, struct sockaddr *);
void dhcpv4_socket_setup(void);
void dhcpv6_socket_setup(void);
void if_statusprint(struct interface_info *info, const char *status);
void dhcpv6_multicast_relay_join(struct interface_info *info);
void dhcpv6_multicast_server_join(struct interface_info *info);

/* lpf.cpp */
void lpf_setup(struct interface_info *info);

/* bpf.cpp */
ssize_t bpf_send_packet(struct interface_info *interface,
			void *packet, size_t len, struct sockaddr_in *to);

/* discover.c */
extern struct interface_info *interfaces,
	*dummy_interfaces, *fallback_interface;
extern struct protocol *protocols;
extern int quiet_interface_discovery;

extern struct in_addr limited_broadcast;
extern struct in_addr local_address;

extern u_int16_t local_port;
extern u_int16_t remote_port;
extern u_int16_t listen_port;
extern u_int16_t local_port_dhcpv6;
extern u_int16_t remote_port_dhcpv6;
extern u_int16_t listen_port_dhcpv6;
extern int (*dhcp_interface_setup_hook) (struct interface_info *,
					 struct iaddr *);

extern struct interface_info **interface_vector;
extern int interface_count;
extern int interface_max;
isc_result_t interface_initialize (struct interface_info *);
void discover_interfaces(void);
isc_result_t got_v4_packet (struct interface_info *ip,
			    struct sockaddr_in *from,
			    char *buf, ssize_t length);
isc_result_t got_v6_packet (struct interface_info *ip,
			    struct sockaddr_in6 *from,
			    char *buf, ssize_t length);
void reinitialize_interfaces(void);
void interface_snorf (struct interface_info *tmp);

/* dispatch.c */
#define TIMEV_NANOSECONDS(tv) (((tv).tv_sec * 1000000000ULL) + \
			       ((tv).tv_usec) * 1000ULL)
#define NANO_SECONDS(seconds) ((seconds) * 1000000000ULL)
#define SECONDS(nano)	((nano) / 1000000000ULL)
#define MICROSECONDS(nano) ((nano) / 1000ULL)

extern unsigned long long cur_time;
void set_time(unsigned long long time);
void fetch_time(void);
isc_result_t dispatch(void);
isc_result_t dispatch_select(fd_set *ord,
                             fd_set *owt,
                             fd_set *oex, 
                             int omax, 
                             struct timeval *oto,
                             int *rcount);
isc_result_t register_io_object(void *v,
				int (*readfd)(void *),
				int (*writefd)(void *),
				isc_result_t (*reader)(void *),
				isc_result_t (*writer)(void *),
				isc_result_t (*reaper)(void *));
isc_result_t unregister_io_object(void *v);

/* tables.c */
extern struct option_space dhcp_option_space;
extern struct option_space dhcpv6_option_space;
extern struct option_space nwip_option_space;
extern struct option_space fqdn_option_space;
extern int dhcp_option_default_priority_list[];
extern int dhcp_option_default_priority_list_count;
extern struct const_option predef_options[];
extern int predef_option_count;
extern const char *hardware_types [256];
extern int option_space_count, option_space_max;
extern struct option_space **option_spaces;
extern option_space_hash_t *option_space_hash;
void initialize_common_option_spaces(void);
extern struct option_space *config_option_space;

/* inet.c */
struct iaddr subnet_number(struct iaddr, struct iaddr);
struct iaddr ip_addr(struct iaddr, struct iaddr, u_int32_t);
struct iaddr broadcast_addr(struct iaddr, struct iaddr);
u_int32_t host_addr(struct iaddr, struct iaddr);
int addr_eq(struct iaddr, struct iaddr);
char *piaddr(struct iaddr);
char *piaddrmask (struct iaddr, struct iaddr);
char *piaddr1(struct iaddr);

/* dhclient.c */
extern const char *path_dhclient_pid;
extern int interfaces_requested;

extern struct iaddr iaddr_broadcast;
extern struct iaddr iaddr_any;
extern struct in_addr inaddr_any;
extern struct sockaddr_in sockaddr_broadcast;
extern struct sockaddr *sockaddr_all_agents_and_servers;
extern struct in_addr giaddr;
extern struct iaddr iaddr_all_agents_and_servers;

extern struct client_config top_level_config;

extern int onetry;
extern int quiet;

/* common/v6packet.c */
void make_ia_option(struct data_string *output, struct ia *ia, int clientp);
void store_duid(unsigned char *buf, unsigned len, duid_t *duid);
u_int32_t dhcpv6_extract_xid(const unsigned char *packet, unsigned len);
struct dhcpv6_response *decode_dhcpv6_packet(const unsigned char *packet, unsigned len, struct dhcpv6_response *outer);
int extract_ias(struct dhcpv6_response *response, int code);
int extract_ia_addrs(struct ia *ia);

/* client/dbus.c */

int dhcp_option_ev_name (char *, size_t, struct option *);

void dbus_init(struct client_config *, const char *);
void dbus_option_add (struct option_cache *oc,
		      struct option_state *options,
		      struct option_space *u, void *stuff);
void dbus_send_lease(struct client_config *,
		     const char *, struct client_lease *,
		     struct option_state *);
int dbus_finish(struct client_config *);
void dbus_item_add(struct client_config *,
		   const char *, const char *, const char *, ...)
	__attribute__((__format__(__printf__,4,5)));
void dbus_send_ia_addr(struct client_config *config,
		       const char *type, struct ia_addr *address);
void dbus_send_ia(struct client_config *config, struct ia *ia);
char *dbus_compose_ia_prefix(struct client_config *config,
			     struct ia *ia, const char *extra);

/* route.c */
void add_route_direct(struct interface_info *, struct in_addr);
void add_route_net(struct interface_info *, struct in_addr,
			   struct in_addr);
void add_route_default_gateway(struct interface_info *, 
				       struct in_addr);
void remove_routes(struct in_addr);
void remove_if_route(struct interface_info *, struct in_addr);
void remove_all_if_routes(struct interface_info *);
void set_netmask(struct interface_info *, struct in_addr);
void set_broadcast_addr(struct interface_info *, struct in_addr);
void set_ip_address(struct interface_info *, struct in_addr);

/* dhcrelay.c */
void new_relay_server (char *, struct server_list **);
void relay(struct interface_info *,
	   struct dhcp_packet *, unsigned, unsigned int, struct iaddr);
int strip_relay_agent_options(struct interface_info *,
				      struct interface_info **,
				      struct dhcp_packet *, unsigned);
int find_interface_by_agent_option(struct dhcp_packet *,
					   struct interface_info **,
					   u_int8_t *, int);
int add_relay_agent_options(struct interface_info *,
				    struct dhcp_packet *,
				    unsigned, struct in_addr);

/* icmp.c */
extern struct icmp_state *icmp_state;
void icmp_startup (int, void (*)(struct iaddr,
				 u_int8_t *, int));
int icmp_readsocket(void *);
int icmp_echorequest(struct iaddr *);
isc_result_t icmp_echoreply(void *);

/* inet_addr.c */
#ifdef NEED_INET_ATON
int inet_aton(const char *, struct in_addr *);
#endif

/* convert.c */
u_int32_t getULong (const unsigned char *);
int32_t getLong (const unsigned char *);
u_int32_t getUShort (const unsigned char *);
int32_t getShort (const unsigned char *);
u_int32_t getUChar (const unsigned char *);
void putULong (unsigned char *, u_int32_t);
void putLong (unsigned char *, int32_t);
void putUShort (unsigned char *, u_int32_t);
void putShort (unsigned char *, int32_t);
void putUChar (unsigned char *, u_int32_t);
int converted_length (const unsigned char *, unsigned int, unsigned int);
int binary_to_ascii (unsigned char *, const unsigned char *,
		     unsigned int, unsigned int);

/* errwarn.c */
extern int log_priority;
extern int log_perror;
extern int log_syslog;
extern void (*log_cleanup) (void);

void log_fatal (const char *, ...)
	__attribute__((__format__(__printf__,1,2)));
int log_error (const char *, ...)
	__attribute__((__format__(__printf__,1,2)));
int log_info (const char *, ...)
	__attribute__((__format__(__printf__,1,2)));
int log_debug (const char *, ...)
	__attribute__((__format__(__printf__,1,2)));
void log_xxtrc (int seq, const char *fmt, ...)
	__attribute__((__format__(__printf__,2,3)));
void do_percentm (char *obuf, const char *ibuf);

/* auth.c */
isc_result_t auth_key_enter (auth_key_t *);
isc_result_t auth_key_lookup_name (auth_key_t **, const char *);

/* packet.c */
u_int32_t checksum (unsigned char *buf, unsigned nbytes, u_int32_t sum);
u_int32_t wrapsum (u_int32_t sum);

#if defined(NEED_PACKET_ASSEMBLY)
void assemble_ethernet_header (struct interface_info *interface,
			       unsigned char *buf,
			       unsigned *bufix,
			       struct hardware *to);
void assemble_udp_ip_header(struct interface_info *interface,
			    unsigned char *buf,
			    unsigned *bufix,
			    u_int32_t from,
			    u_int32_t to,
			    u_int32_t port,
			    unsigned char *data,
			    unsigned len);
#endif
#if defined(NEED_PACKET_DECODING)
ssize_t decode_ethernet_header(struct interface_info *interface,
			       unsigned char *buf,
			       unsigned bufix,
			       struct hardware *from);
ssize_t decode_udp_ip_header(struct interface_info *interface,
			     unsigned char *buf,
			     unsigned bufix,
			     struct sockaddr_in *from,
			     unsigned buflen,
			     unsigned *rbuflen);
#endif

/* toisc.c */
isc_result_t ns_rcode_to_isc (int nsr);
isc_result_t uerr2isc (int err);
ns_rcode isc_rcode_to_ns (isc_result_t isc);

/* result.c */
const char *isc_result_totext (isc_result_t result);

/* somewhere... */
void dhcp(struct packet *);
void bootp(struct packet *);
int parse_agent_information_option (struct packet *packet,
				    int len, u_int8_t *data);
unsigned cons_agent_information_options (struct option_state *cfg_options,
					 struct dhcp_packet *outpacket,
					 unsigned agentix,
					 unsigned length);

/* client/dummy.c */
void
dhcpv6_client_confreq(struct interface_info *ip, struct sockaddr_in6 *from,
		      char *packet, unsigned len, const char *name);

/* Local Variables:  */
/* mode:c++ */
/* c-file-style:"gnu" */
/* end: */
