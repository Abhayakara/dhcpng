#!/usr/bin/env python

import sys
import dhcp
import time
import struct
import os
import string

global V6Client
V6Client = None


class Controller:
    def __init__(self):
        self.options = {}
        self.state = "unmanaged"

    def start(self):
	self.options = {}
	self.add_addrs = []
	self.del_addrs = []
	self.resolver = None
	self.dsl = None
	self.cur_iface = None

    def finish(self):
	if self.resolver != None:
            print "Adding resolvers:", self.resolver, self.dsl
#            osx.setResolvers(self.resolver, self.dsl)
#		try:
#			rc = file("/etc/resolv.conf", "w")
#			if self.dsl != None:
#				rc.write("search")
#				for domain in self.dsl:
#					rc.write(" " + domain)
#				rc.write("\n")
#			for ns in self.resolver:
#				rc.write("nameserver " + ns + "\n")
#			rc.close()
#		except Exception, x:
#			print "file open failed: " + repr(x)

    def add_item(self, prefix, name, value):
	prefvec = string.split(prefix, "/")
	if name == 'reason':
		self.cur_iface = prefix
	elif name == 'action':
		if value == 'add':
			self.add_addrs.append(prefvec[1])
		elif value == 'remove':
			self.del_addrs.append(prefvec[1])
	elif name == 'dhcpv6.domain-name-servers':
		self.resolver = value
	elif name == 'dhcpv6.domain-search-list':
		self.dsl = value
	else:
		print prefix + "/" + name + " = " + repr(value)

dhcp.v6netsetup(546, 547)
# Get an interface object for wlan0.   This is mac-specific, and not the
# right way to do it.
wlan0 = dhcp.Interface("br0")
hwaddr = wlan0.lladdr
hwtype = wlan0.lltype
try:
  duif = file("/var/lib/dhcp/dhcp-client-duid", "r")
  duid = duif.read()
except Exception, v:
  print v
  duid = struct.pack("!HLHs", 1, int(time.time()), hwtype, hwaddr)
V6Client = dhcp.v6client("br0", Controller(), duid)
V6Client.state_soliciting()
try:
    dhcp.dispatch()
except KeyboardInterrupt:
    os._exit()
