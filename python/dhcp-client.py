#!/usr/bin/env python

import sys
import dhcp
import time
import struct
import threading
import os
import string
from SystemConfiguration import *
from Foundation import NSObject, NSRunLoop, NSDate

global V6Client
V6Client = None
global osx
osx = None

class SCDelegate(NSObject):
    def init(self):
        self = super(SCDelegate, self).init()
        self.last = {}
        self.haveIPv4 = False
        self.haveIPv6 = False
        self.V6ClientRunning = False
        self.resolvers = None
        self.domain = None
        self.dnsKey = u"State:/Network/Service/DHCP-en1/DNS"
#        dnsKey = u"Setup:/Network/Service/D65CD25D-281B-4AE4-890B-E2CBB890BEA2/DNS"
#        dnsKey = u"State:/Network/Global/DNS"
        return self

    def keysChanged_inDynamicStore_(self, changed, store):
        print "keysChanged called with store " + repr(store)
        for key in changed:
            info = SCDynamicStoreCopyValue(store, key)
            if key == u'State:/Network/Global/IPv4':
                if info != None and info.has_key('Router'):
                    self.haveIPv4 = True
                    print "have IPv4"
                else:
                    self.haveIPv4 = False
                    print "don't have IPv4"
            elif key == u'State:/Network/Global/IPv6':
                if info != None and info.has_key('Router'):
                    self.haveIPv6 = True
                    print "have IPv6"
                else:
                    self.haveIPv6 = False
                    print "don't have IPv6"
        info = SCDynamicStoreCopyValue(store, u"State:/Network/Global/DNS")
        if info != None:
            print "DNS info type is " + repr(info.__class__)
            for key in info.keys():
                item = info[key]
                print "Key " + key + " type is " + repr(item.__class__)
                print "Key " + key + " value is " + repr(item)
            
        else:
            print "no DNS info."
        if self.haveIPv6 and not self.haveIPv4 and not self.V6ClientRunning:
            V6Client.state_inform()
            self.V6ClientRunning = True
        else:
            V6Client.state_unmanaged()
            self.V6ClientRunning = False
        self.installResolvers(store)

    def setResolvers(self, resolvers, domain, store):
        self.resolvers = resolvers
        self.domain = domain
        self.installResolvers(store)
    
    def installResolvers(self, store):
        try:
#            if self.haveIPv4 or not self.haveIPv6:
#                print "not installing resolvers."
#            self.clearResolvers()
#                return
            if self.resolvers == None:
                print "no resolvers to install"
                return
            print "installing resolvers."
            dnsConf = {} #NSMutableDictionary.alloc().init()
            dnsConf["ServerAddresses"] = self.resolvers
            if self.domain != None:
                dnsConf["DomainName"] = self.domain # NSString.alloc().initWithString_(domain[0])
#            nsr = NSMutableArray.alloc().init()
#            for resolver in resolvers:
#                nsr.addObject_(NSString.alloc().initWithString_(resolver))
#            print "nsr: " + repr(nsr)
#            dnsConf["ServerAddresses"] = nsr

            print "dnsConf: " + repr(dnsConf)

            try:
                SCDynamicStoreRemoveValue(store, self.dnsKey)
            except Exception, e:
                print "key remove threw an exception: " + repr(e)
            try:
                SCDynamicStoreAddValue(store, self.dnsKey, dnsConf)
                print "addValue_forKey_ succeeded."
                try:
                    SCDynamicStoreNotifyValue(store, self.dnsKey)
                    print "notifyValueForKey_ succeeded."
                except Exception, e:
                    print "notifyValueForKey_ threw exception: " + repr(e)
            except Exception, e:
                    print "addValue_forKey threw exception: " + repr(e)
                
        except Exception, e:
            print "installResolvers threw an exception:", repr(e)

    def clearResolvers(self, store):
        SCDynamicStoreRemoveValue(store, self.dnsKey)
        SCDynamicStoreNotifyValue(store, self.dnsKey)


class OSXRunLoop():
    def callback(store, changedKeys, me):
        self.delegate.keysChanged_inDynamicStore(changedKeys, store)

    def __init__(self):
        ds = SCDynamicStoreCreate(None, "foo", self.callback, self)
        self.delegate = SCDelegate.alloc().init()
#        ds.setDelegate_(self.delegate)
#        ds.addToCurrentRunLoop()
        self.runloop = NSRunLoop.currentRunLoop()
        
        dnspattern = u"State:/Network/global/DNS"
        pattern = r'State:/Network/Global/IPv[46]'
#        keys = list(ds.keyListForPattern_(pattern))
#        keys.extend(list(ds.keyListForPattern_(dnspattern)))
#        ds.notifyValuesForKeys_matchingPatterns_(None, [pattern, dnspattern])
        keys = []
        keys.append(dnspattern)
        keys.append(pattern)
        SCDynamicStoreSetNotificationKeys(ds, None, keys)
#        self.delegate.keysChanged_inDynamicStore_(keys, ds)
        for key in keys:
            print "Watching key " + str(key)
        self.ds = ds

    def run(self):
        print "Running..."
        self.runloop.run()

        
    def setResolvers(self, resolvers, domain):
        self.delegate.setResolvers(resolvers, domain, self.ds)

    def clearResolvers(self):
        self.delegate.clearResolvers(self.ds)

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
#	try:
#	    for addr in self.del_addrs:
#		try:
#			os.system("ifconfig " +
#			          self.cur_iface + " inet6 -alias " + addr)
#		except Exception, v:
#			print "ifconfig failed: " + repr(v)
#	except Exception, v:
#	    print "del_addrs loop blew up: " + repr(v)
#	try:
#	    for addr in self.add_addrs:
#		try:
#			os.system("ifconfig " +
#			          self.cur_iface + " inet6 alias " + addr)
#		except Exception, v:
#			print ("ifconfig " + self.cur_iface +
#			       " inet6 alias " + addr + ": " + repr(v))
#	except Exception, v:
#	    print "add_addrs loop blew up: " + repr(v)
	if self.resolver != None:
            print "Adding resolvers..."
            osx.setResolvers(self.resolver, self.dsl)
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

def dhcpDispatch():
    try:
        dhcp.dispatch()
    except Exception, e:
        print "dhcp.dispatch() threw an exception: " + repr(e)
        sys.exit(0)

dhcp.v6netsetup()
# Get an interface object for en1.   This is mac-specific, and not the
# right way to do it.
en1 = dhcp.Interface("en1")
hwaddr = en1.lladdr
hwtype = en1.lltype
try:
  duif = file("/var/db/dhcp-client-duid", "r")
  duid = duif.read()
except Exception, v:
  print v
  duid = struct.pack("!HLHs", 1, int(time.time()), hwtype, hwaddr)
V6Client = dhcp.v6client("en1", Controller(), duid)
thread = threading.Thread(target=dhcpDispatch)
thread.daemon = True
thread.set_daemon(True)
thread.start()
print "done with OSX setup."
V6Client.state_soliciting()
osx = OSXRunLoop()
print "starting OSX run loop."
try:
    osx.run()
except Exception, e:
    print "osx.run() threw an exception: " + str(e)
    sys.exit(0)
