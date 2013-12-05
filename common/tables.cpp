/* tables.c
 *
 * Tables of information...
 */

/* Copyright (c) 2002-2007 Nominum, Inc.   All rights reserved.
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
  "$Id: tables.cpp,v 1.7 2008/07/25 02:02:41 mellon Exp $ Copyright (c) 2005-2007 Nominum, Inc.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

/* DHCP Option names, formats and codes, from RFC2132.
 *
 * Format codes:
 *
 * I - IP address
 * l - 32-bit signed integer
 * L - 32-bit unsigned integer
 * s - 16-bit signed integer
 * S - 16-bit unsigned integer
 * b - 8-bit signed integer
 * B - 8-bit unsigned integer
 * t - ASCII text
 * f - flag (true or false)
 * A - array of whatever precedes (e.g., IA means array of one or more
 *     IP addresses)
 * a - array of the preceding character (e.g., IIa means two or more IP
 *     addresses)
 * U - name of an option space
 * F - implicit flag - the presence of the option indicates that the
 *     flag is true.
 * o - the preceding value is optional.
 * E - encapsulation, string or colon-seperated hex list (the latter
 *     two for parsing).   E is followed by a text string containing
 *     the name of the option space to encapsulate, followed by a '.'.
 *     If the E is immediately followed by '.', the applicable vendor
 *     option space is used if one is defined.
 * e - If an encapsulation directive is not the first thing in the string,
 *     the option scanner requires an efficient way to find the encapsulation.
 *     This is done by placing a 'e' at the beginning of the option.   The
 *     'e' has no other purpose, and is not required if 'E' is the first
 *     thing in the option.
 * X - either an ASCII string or binary data.   On output, the string is
 *     scanned to see if it's printable ASCII and, if so, output as a
 *     quoted string.   If not, it's output as colon-seperated hex.   On
 *     input, the option can be specified either as a quoted string or as
 *     a colon-seperated hex list.
 * N - enumeration.   N is followed by a text string containing
 *     the name of the set of enumeration values to parse or emit,
 *     followed by a '.'.   The width of the data is specified in the
 *     named enumeration.   Named enumerations are tracked in parse.c.
 * d - Domain name (i.e., FOO or FOO.BAR).
 * 6 - An IPv6 address.
 * O - IAdddr-options.
 * M - A DHCPv6 message, typically encapsulated in a relay message.
 * Q - 64 bits of data.

 * The following are encapsulations of the DHCPv6 option space; the reason
 * for giving them their own letters is that they have different purposes
 * and should give rise to data in different places in the v6 packet.   Or
 * anyway that's the theory.

 * T - IA_TA encapsulated options
 * n - IA_NA encapsulated options
 * P - IA_PD encapsulated options
 * p - IA_PD Prefix encapsulated options
 */

struct option_space dhcp_option_space;
struct option_space dhcpv6_option_space;
struct option_space nwip_option_space;
struct option_space fqdn_option_space;

/* Options are listed in reverse numerical order so that we don't
 * repeatedly expand the option_space option vector on initialization.
 */

struct const_option predef_options[] = {
  { "subnet-selection", "X",			&dhcp_option_space, 118 },
  { "name-service-search-order", "Ba",		&dhcp_option_space, 117 },
  { "autoconfiguration", "f",			&dhcp_option_space, 116 },
  { "uap-servers", "t",				&dhcp_option_space, 98 },
  { "authentication", "X",			&dhcp_option_space, 90 },
  { "nds-context", "X",				&dhcp_option_space, 87 },
  { "nds-tree-name", "X",			&dhcp_option_space, 86 },
  { "nds-servers", "Ia",			&dhcp_option_space, 85 },
  { "relay-agent-information", "Eagent",	&dhcp_option_space, 82 },
  { "fqdn", "Efqdn",				&dhcp_option_space, 81 },
  { "slp-service-scope", "fto",			&dhcp_option_space, 79 },
  { "slp-directory-agent", "fIa",		&dhcp_option_space, 78 },
  { "user-class", "t",				&dhcp_option_space, 77 },
  { "streettalk-directory-assistance-server", "Ia",
    &dhcp_option_space, 76 },
  { "streettalk-server", "Ia",			&dhcp_option_space, 75 },
  { "irc-server", "Ia",				&dhcp_option_space, 74 },
  { "finger-server", "Ia",			&dhcp_option_space, 73 },
  { "www-server", "Ia",				&dhcp_option_space, 72 },
  { "nntp-server", "Ia",			&dhcp_option_space, 71 },
  { "pop-server", "Ia",				&dhcp_option_space, 70 },
  { "smtp-server", "Ia",			&dhcp_option_space, 69 },
  { "mobile-ip-home-agent", "Ia",		&dhcp_option_space, 68 },
  { "bootfile-name", "t",			&dhcp_option_space, 67 },
  { "tftp-server-name", "t",			&dhcp_option_space, 66 },
  { "nisplus-servers", "Ia",			&dhcp_option_space, 65 },
  { "nisplus-domain", "t",			&dhcp_option_space, 64 },
  { "nwip-suboptions", "Enwip",			&dhcp_option_space, 63 },
  { "nwip-domain", "X",				&dhcp_option_space, 62 },
  { "dhcp-client-identifier", "X",		&dhcp_option_space, 61 },
  { "vendor-class-identifier", "X",		&dhcp_option_space, 60 },
  { "dhcp-rebinding-time", "L",			&dhcp_option_space, 59 },
  { "dhcp-renewal-time", "L",			&dhcp_option_space, 58 },
  { "dhcp-max-message-size", "S",		&dhcp_option_space, 57 },
  { "dhcp-message", "t",			&dhcp_option_space, 56 },
  { "dhcp-parameter-request-list", "Ba",	&dhcp_option_space, 55 },
  { "dhcp-server-identifier", "I",		&dhcp_option_space, 54 },
  { "dhcp-message-type", "B",			&dhcp_option_space, 53 },
  { "dhcp-option-overload", "B",		&dhcp_option_space, 52 },
  { "dhcp-lease-time", "L",			&dhcp_option_space, 51 },
  { "dhcp-requested-address", "I",		&dhcp_option_space, 50 },
  { "x-display-manager", "Ia",			&dhcp_option_space, 49 },
  { "font-servers", "Ia",			&dhcp_option_space, 48 },
  { "netbios-scope", "t",			&dhcp_option_space, 47 },
  { "netbios-node-type", "B",			&dhcp_option_space, 46 },
  { "netbios-dd-server", "Ia",			&dhcp_option_space, 45 },
  { "netbios-name-servers", "Ia",		&dhcp_option_space, 44 },
  { "vendor-encapsulated-options", "E",		&dhcp_option_space, 43 },
  { "ntp-servers", "Ia",			&dhcp_option_space, 42 },
  { "nis-servers", "Ia",			&dhcp_option_space, 41 },
  { "nis-domain", "t",				&dhcp_option_space, 40 },
  { "tcp-keepalive-garbage", "f",		&dhcp_option_space, 39 },
  { "tcp-keepalive-interval", "L",		&dhcp_option_space, 38 },
  { "default-tcp-ttl", "B",			&dhcp_option_space, 37 },
  { "ieee802-3-encapsulation", "f",		&dhcp_option_space, 36 },
  { "arp-cache-timeout", "L",			&dhcp_option_space, 35 },
  { "trailer-encapsulation", "f",		&dhcp_option_space, 34 },
  { "static-routes", "IIa",			&dhcp_option_space, 33 },
  { "router-solicitation-address", "I",		&dhcp_option_space, 32 },
  { "router-discovery", "f",			&dhcp_option_space, 31 },
  { "mask-supplier", "f",			&dhcp_option_space, 30 },
  { "perform-mask-discovery", "f",		&dhcp_option_space, 29 },
  { "broadcast-address", "I",			&dhcp_option_space, 28 },
  { "all-subnets-local", "f",			&dhcp_option_space, 27 },
  { "interface-mtu", "S",			&dhcp_option_space, 26 },
  { "path-mtu-plateau-table", "Sa",		&dhcp_option_space, 25 },
  { "path-mtu-aging-timeout", "L",		&dhcp_option_space, 24 },
  { "default-ip-ttl", "B",			&dhcp_option_space, 23 },
  { "max-dgram-reassembly", "S",		&dhcp_option_space, 22 },
  { "policy-filter", "IIa",			&dhcp_option_space, 21 },
  { "non-local-source-routing", "f",		&dhcp_option_space, 20 },
  { "ip-forwarding", "f",			&dhcp_option_space, 19 },
  { "extensions-path", "t",			&dhcp_option_space, 18 },
  { "root-path", "t",				&dhcp_option_space, 17 },
  { "swap-server", "I",				&dhcp_option_space, 16 },
  { "domain-name", "t",				&dhcp_option_space, 15 },
  { "merit-dump", "t",				&dhcp_option_space, 14 },
  { "boot-size", "S",				&dhcp_option_space, 13 },
  { "host-name", "X",				&dhcp_option_space, 12 },
  { "resource-location-servers", "Ia",		&dhcp_option_space, 11 },
  { "impress-servers", "Ia",			&dhcp_option_space, 10 },
  { "lpr-servers", "Ia",			&dhcp_option_space, 9 },
  { "cookie-servers", "Ia",			&dhcp_option_space, 8 },
  { "log-servers", "Ia",			&dhcp_option_space, 7 },
  { "domain-name-servers", "Ia",		&dhcp_option_space, 6 },
  { "ien116-name-servers", "Ia",		&dhcp_option_space, 5 },
  { "time-servers", "Ia",			&dhcp_option_space, 4 },
  { "routers", "Ia",				&dhcp_option_space, 3 },
  { "time-offset", "l",				&dhcp_option_space, 2 },
  { "subnet-mask", "I",				&dhcp_option_space, 1 },

  { "primary-dss", "I",				&nwip_option_space, 11 },
  { "nwip-1-1", "f",				&nwip_option_space, 10 },
  { "autoretry-secs", "B",			&nwip_option_space, 9 },
  { "autoretries", "B",				&nwip_option_space, 8 },
  { "nearest-nwip-server", "Ia",		&nwip_option_space, 7 },
  { "preferred-dss", "Ia",			&nwip_option_space, 6 },
  { "nsq-broadcast", "f",			&nwip_option_space, 5 },
  { "illegal-4", "",				&nwip_option_space, 4 },
  { "illegal-3", "",				&nwip_option_space, 3 },
  { "illegal-2", "",				&nwip_option_space, 2 },
  { "illegal-1", "",				&nwip_option_space, 1 },

  { "fqdn", "t",				&fqdn_option_space, 8 },
  { "domainname", "t",				&fqdn_option_space, 7 },
  { "hostname", "t",				&fqdn_option_space, 6 },
  { "rcode2", "B",				&fqdn_option_space, 5 },
  { "rcode1", "B",				&fqdn_option_space, 4 },
  { "encoded", "f",				&fqdn_option_space, 3 },
  { "server-update", "f",			&fqdn_option_space, 2 },
  { "no-client-update", "f",			&fqdn_option_space, 1 },

  { "fqdn", "Bd",				&dhcpv6_option_space, 39 },
  { "information-refresh_time", "x",		&dhcpv6_option_space, 32 },
  { "nis+-domain", "d",				&dhcpv6_option_space, 30 },
  { "nis-domain", "d",				&dhcpv6_option_space, 29 },
  { "nis+-servers", "6a",			&dhcpv6_option_space, 28 },
  { "nis-servers", "6a",			&dhcpv6_option_space, 27 },
  { "ia-prefix", "eLLB6p",			&dhcpv6_option_space, 26 },
  { "ia-pd", "eLLLP",				&dhcpv6_option_space, 25 },
  { "domain-search-list", "da",			&dhcpv6_option_space, 24 },
  { "domain-name-servers", "6a",		&dhcpv6_option_space, 23 },
  { "sip-servers", "da",			&dhcpv6_option_space, 22 },
  { "sip-server-names", "da",			&dhcpv6_option_space, 21 },
  { "reconfigure-accepted", "F",		&dhcpv6_option_space, 20 },
  { "reconfigure", "B",				&dhcpv6_option_space, 19 },
  { "interface-identifier", "X",		&dhcpv6_option_space, 18 },
  { "vendor-specific-information", "eLE", 	&dhcpv6_option_space, 17 },
  { "vendor-class", "Lxa",			&dhcpv6_option_space, 16 },
  { "user-class", "xa",				&dhcpv6_option_space, 15 },
  { "rapid-commit", "F",			&dhcpv6_option_space, 14 },
  { "status-code", "St",			&dhcpv6_option_space, 13 },
  { "server-unicast-address", "6",		&dhcpv6_option_space, 12 },
  { "authentication", "BBBQx",			&dhcpv6_option_space, 11 },
  { "relay-message", "M",			&dhcpv6_option_space, 9 },
  { "elapsed-time", "S",			&dhcpv6_option_space, 8 },
  { "preference", "B",				&dhcpv6_option_space, 7 },
  { "requested-options", "Sa",			&dhcpv6_option_space, 6 },
  { "ia-address", "LL6X",			&dhcpv6_option_space, 5 },
  { "ia-ta", "X",				&dhcpv6_option_space, 4 },
  { "ia-na", "X",				&dhcpv6_option_space, 3 },
  { "server-identifier", "X",			&dhcpv6_option_space, 2 },
  { "duid", "X",				&dhcpv6_option_space, 1 },
};

int predef_option_count = (sizeof predef_options) / (sizeof (struct option));

const char *hardware_types [] = {
  "unknown-0",
  "ethernet",
  "unknown-2",
  "unknown-3",
  "unknown-4",
  "unknown-5",
  "token-ring",
  "unknown-7",
  "fddi",
  "unknown-9",
  "unknown-10",
  "unknown-11",
  "unknown-12",
  "unknown-13",
  "unknown-14",
  "unknown-15",
  "unknown-16",
  "unknown-17",
  "unknown-18",
  "unknown-19",
  "unknown-20",
  "unknown-21",
  "unknown-22",
  "unknown-23",
  "unknown-24",
  "unknown-25",
  "unknown-26",
  "unknown-27",
  "unknown-28",
  "unknown-29",
  "unknown-30",
  "unknown-31",
  "unknown-32",
  "unknown-33",
  "unknown-34",
  "unknown-35",
  "unknown-36",
  "unknown-37",
  "unknown-38",
  "unknown-39",
  "unknown-40",
  "unknown-41",
  "unknown-42",
  "unknown-43",
  "unknown-44",
  "unknown-45",
  "unknown-46",
  "unknown-47",
  "unknown-48",
  "unknown-49",
  "unknown-50",
  "unknown-51",
  "unknown-52",
  "unknown-53",
  "unknown-54",
  "unknown-55",
  "unknown-56",
  "unknown-57",
  "unknown-58",
  "unknown-59",
  "unknown-60",
  "unknown-61",
  "unknown-62",
  "unknown-63",
  "unknown-64",
  "unknown-65",
  "unknown-66",
  "unknown-67",
  "unknown-68",
  "unknown-69",
  "unknown-70",
  "unknown-71",
  "unknown-72",
  "unknown-73",
  "unknown-74",
  "unknown-75",
  "unknown-76",
  "unknown-77",
  "unknown-78",
  "unknown-79",
  "unknown-80",
  "unknown-81",
  "unknown-82",
  "unknown-83",
  "unknown-84",
  "unknown-85",
  "unknown-86",
  "unknown-87",
  "unknown-88",
  "unknown-89",
  "unknown-90",
  "unknown-91",
  "unknown-92",
  "unknown-93",
  "unknown-94",
  "unknown-95",
  "unknown-96",
  "unknown-97",
  "unknown-98",
  "unknown-99",
  "unknown-100",
  "unknown-101",
  "unknown-102",
  "unknown-103",
  "unknown-104",
  "unknown-105",
  "unknown-106",
  "unknown-107",
  "unknown-108",
  "unknown-109",
  "unknown-110",
  "unknown-111",
  "unknown-112",
  "unknown-113",
  "unknown-114",
  "unknown-115",
  "unknown-116",
  "unknown-117",
  "unknown-118",
  "unknown-119",
  "unknown-120",
  "unknown-121",
  "unknown-122",
  "unknown-123",
  "unknown-124",
  "unknown-125",
  "unknown-126",
  "unknown-127",
  "unknown-128",
  "unknown-129",
  "unknown-130",
  "unknown-131",
  "unknown-132",
  "unknown-133",
  "unknown-134",
  "unknown-135",
  "unknown-136",
  "unknown-137",
  "unknown-138",
  "unknown-139",
  "unknown-140",
  "unknown-141",
  "unknown-142",
  "unknown-143",
  "unknown-144",
  "unknown-145",
  "unknown-146",
  "unknown-147",
  "unknown-148",
  "unknown-149",
  "unknown-150",
  "unknown-151",
  "unknown-152",
  "unknown-153",
  "unknown-154",
  "unknown-155",
  "unknown-156",
  "unknown-157",
  "unknown-158",
  "unknown-159",
  "unknown-160",
  "unknown-161",
  "unknown-162",
  "unknown-163",
  "unknown-164",
  "unknown-165",
  "unknown-166",
  "unknown-167",
  "unknown-168",
  "unknown-169",
  "unknown-170",
  "unknown-171",
  "unknown-172",
  "unknown-173",
  "unknown-174",
  "unknown-175",
  "unknown-176",
  "unknown-177",
  "unknown-178",
  "unknown-179",
  "unknown-180",
  "unknown-181",
  "unknown-182",
  "unknown-183",
  "unknown-184",
  "unknown-185",
  "unknown-186",
  "unknown-187",
  "unknown-188",
  "unknown-189",
  "unknown-190",
  "unknown-191",
  "unknown-192",
  "unknown-193",
  "unknown-194",
  "unknown-195",
  "unknown-196",
  "unknown-197",
  "unknown-198",
  "unknown-199",
  "unknown-200",
  "unknown-201",
  "unknown-202",
  "unknown-203",
  "unknown-204",
  "unknown-205",
  "unknown-206",
  "unknown-207",
  "unknown-208",
  "unknown-209",
  "unknown-210",
  "unknown-211",
  "unknown-212",
  "unknown-213",
  "unknown-214",
  "unknown-215",
  "unknown-216",
  "unknown-217",
  "unknown-218",
  "unknown-219",
  "unknown-220",
  "unknown-221",
  "unknown-222",
  "unknown-223",
  "unknown-224",
  "unknown-225",
  "unknown-226",
  "unknown-227",
  "unknown-228",
  "unknown-229",
  "unknown-230",
  "unknown-231",
  "unknown-232",
  "unknown-233",
  "unknown-234",
  "unknown-235",
  "unknown-236",
  "unknown-237",
  "unknown-238",
  "unknown-239",
  "unknown-240",
  "unknown-241",
  "unknown-242",
  "unknown-243",
  "unknown-244",
  "unknown-245",
  "unknown-246",
  "unknown-247",
  "unknown-248",
  "unknown-249",
  "unknown-250",
  "unknown-251",
  "unknown-252",
  "unknown-253",
  "unknown-254",
  "unknown-255" };

option_space_hash_t *option_space_hash;
struct option_space **option_spaces;
int option_space_count, option_space_max;

void initialize_common_option_spaces()
{
  int i;

  option_space_max = 10;
  option_spaces = (struct option_space **)
    safemalloc(option_space_max * sizeof (struct option_space *));
  memset(option_spaces, 0, option_space_max * sizeof (struct option_space *));

  /* Set up the DHCP option option_space... */
  dhcp_option_space.name = "dhcp";
  dhcp_option_space.lookup_func = lookup_hashed_option;
  dhcp_option_space.save_func = save_hashed_option;
  dhcp_option_space.delete_func = delete_hashed_option;
  dhcp_option_space.encapsulate = hashed_option_space_encapsulate;
  dhcp_option_space.foreach = hashed_option_space_foreach;
  dhcp_option_space.decode = parse_option_buffer;
  dhcp_option_space.length_size = 1;
  dhcp_option_space.tag_size = 1;
  dhcp_option_space.concatenate = 1;
  dhcp_option_space.store_tag = putUChar;
  dhcp_option_space.store_length = putUChar;
  dhcp_option_space.index = option_space_count++;
  option_spaces [dhcp_option_space.index] = &dhcp_option_space;

  /* Set up the DHCPv6 option option_space... */
  dhcpv6_option_space.name = "dhcpv6";
  dhcpv6_option_space.lookup_func = lookup_hashed_option;
  dhcpv6_option_space.save_func = save_hashed_option;
  dhcpv6_option_space.delete_func = delete_hashed_option;
  dhcpv6_option_space.encapsulate = hashed_option_space_encapsulate;
  dhcpv6_option_space.foreach = hashed_option_space_foreach;
  dhcpv6_option_space.decode = parse_twobyte_option_buffer;
  dhcpv6_option_space.length_size = 2;
  dhcpv6_option_space.tag_size = 2;
  dhcp_option_space.concatenate = 0;
  dhcpv6_option_space.store_tag = putUShort;
  dhcpv6_option_space.store_length = putUShort;
  dhcpv6_option_space.index = option_space_count++;
  option_spaces [dhcpv6_option_space.index] = &dhcpv6_option_space;

  /* Set up the Novell option option_space (for option 63)... */
  nwip_option_space.name = "nwip";
  nwip_option_space.lookup_func = lookup_linked_option;
  nwip_option_space.save_func = save_linked_option;
  nwip_option_space.delete_func = delete_linked_option;
  nwip_option_space.encapsulate = nwip_option_space_encapsulate;
  nwip_option_space.foreach = linked_option_space_foreach;
  nwip_option_space.decode = parse_option_buffer;
  nwip_option_space.length_size = 1;
  nwip_option_space.tag_size = 1;
  nwip_option_space.concatenate = 1;
  nwip_option_space.store_tag = putUChar;
  nwip_option_space.store_length = putUChar;
  nwip_option_space.enc_opt =
    find_option(&dhcp_option_space, DHO_NWIP_SUBOPTIONS);
  nwip_option_space.index = option_space_count++;
  option_spaces [nwip_option_space.index] = &nwip_option_space;

  /* Set up the FQDN option option_space... */
  fqdn_option_space.name = "fqdn";
  fqdn_option_space.lookup_func = lookup_linked_option;
  fqdn_option_space.save_func = save_linked_option;
  fqdn_option_space.delete_func = delete_linked_option;
  fqdn_option_space.encapsulate = fqdn_option_space_encapsulate;
  fqdn_option_space.foreach = linked_option_space_foreach;
  fqdn_option_space.decode = fqdn_option_space_decode;
  fqdn_option_space.length_size = 1;
  fqdn_option_space.tag_size = 1;
  fqdn_option_space.concatenate = 1;
  fqdn_option_space.store_tag = putUChar;
  fqdn_option_space.store_length = putUChar;
  fqdn_option_space.index = option_space_count++;
  fqdn_option_space.enc_opt =
    find_option(&dhcp_option_space, DHO_FQDN);
  option_spaces [fqdn_option_space.index] = &fqdn_option_space;

  /* Set up the hash of option_spaces. */
  option_space_new_hash(&option_space_hash, 1);
  option_space_hash_add(option_space_hash,
			dhcp_option_space.name, 0, &dhcp_option_space);
  option_space_hash_add(option_space_hash, dhcpv6_option_space.name, 0,
			&dhcpv6_option_space);
  option_space_hash_add(option_space_hash,
			nwip_option_space.name, 0, &nwip_option_space);
  option_space_hash_add(option_space_hash,
			fqdn_option_space.name, 0, &fqdn_option_space);

  /* Load all the predefined options. */
  for (i = 0; i < predef_option_count; i++)
    {
      (void)define_option(predef_options[i].option_space,
			  predef_options[i].code,
			  predef_options[i].format,
			  predef_options[i].name);
    }
}

/* XXXDPN: Moved here from hash.c, when it moved to libomapi.  Not sure
 * where these really belong.
 */
HASH_FUNCTIONS(option_space, const char *,
	       struct option_space, option_space_hash_t)

/* Local Variables:  */
/* mode:C++ */
/* c-file-style:"gnu" */
/* end: */
