#!/usr/bin/env python

import sys
import dhcp
import time
import struct
import os
import string
import tornado.web
import tornado.httpserver
import tornado.ioloop
import tornado.escape
from tornado.ioloop import IOLoop

clients = {}
controllers = {}
links = []
interfaces = []
interface_names = None

def page_wrap(html):
    return ("<html>" + "<head>" +
            "<title>Summary of DHCP client interfaces</title>" +
            """    <!--[if lte IE 6]>
    <link rel="stylesheet" type="text/css" href="http://support-proto.nominum.com/static/user/ie6fixes.css" />
    <![endif]-->
    <!--[if gte IE 6]>
    <link rel="stylesheet" type="text/css" href="http://support-proto.nominum.com/static/user/main.css" />
    <![endif]-->
    <![if !IE]>
    <link rel="stylesheet" type="text/css" href="http://support-proto.nominum.com/static/user/main.css" />
    <![endif]>""" +
            "</head>" +
            "<body><center>" +
            html + 
            "</body></center></html>")

class dhcpp_select(object):
    """IOLoop implementation for dhc++, uses dhcp.dispatch_select instead
       of select or epoll."""
    def __init__(self):
        self.read_fds = set()
        self.write_fds = set()
        self.error_fds = set()
        self.fd_sets = (self.read_fds, self.write_fds, self.error_fds)

    def register(self, fd, events):
        if events & IOLoop.READ: self.read_fds.add(fd)
        if events & IOLoop.WRITE: self.write_fds.add(fd)
        if events & IOLoop.ERROR: self.error_fds.add(fd)

    def modify(self, fd, events):
        self.unregister(fd)
        self.register(fd, events)

    def unregister(self, fd):
        self.read_fds.discard(fd)
        self.write_fds.discard(fd)
        self.error_fds.discard(fd)

    def poll(self, timeout):
        readable, writeable, errors = dhcp.dispatch_select(self.read_fds,
                                                           self.write_fds,
                                                           self.error_fds,
                                                           timeout)

        events = {}
        for fd in readable:
            events[fd] = events.get(fd, 0) | IOLoop.READ
        for fd in writeable:
            events[fd] = events.get(fd, 0) | IOLoop.WRITE
        for fd in errors:
            events[fd] = events.get(fd, 0) | IOLoop.ERROR
        return events.items()


class InterfaceHandler(tornado.web.RequestHandler):
    def get(self, token):
        tokvec = token.split('/')
        if len(tokvec) == 0:
            raise tornado.web.HTTPError(404)
        if_name = tokvec[0]
        if not controllers.has_key(if_name):
            raise tornado.web.HTTPError(404)
        controller = controllers[if_name]
        client = clients[if_name]
        if len(tokvec) == 1:
            if controllers.has_key(if_name):
                preamble = ['<a href="/">' + if_name + '</a>']
                return self.write(page_wrap(controllers[if_name].get(preamble)))
        if tokvec[1] == 'delete':
            pass
        elif tokvec[1] == 'release':
            client.state_release()
            return self.redirect('/' + if_name + '/')
        elif tokvec[1] == 'stateful':
            client.state_soliciting()
            return self.redirect('/' + if_name + '/')
        elif tokvec[1] == 'stateless':
            client.state_inform()
            return self.redirect('/' + if_name + '/')
        raise tornado.web.HTTPError(404)
    
class Controller(object):
    def __init__(self, name):
        self.client = None
        self.options = {}
        self.state = "unmanaged"
        self.name = name
        self.addresses = {}
        self.optdict = {}

    def set_client(self, client):
        self.client = client

    def get(self, preamble):
        rv = '<h1>' + self.name + ": " + self.state + "</h1>"
        rv = rv + "<table>"
        for address in self.addresses.keys():
            preamble.append(address)
            rv = rv + self.get_options(preamble, self.addresses[address])
            del preamble[-1]
        return rv + self.get_options(preamble, self.optdict) + "</table>"
        
    def get_options(self, preamble, optdict):
        rv = ""
        optnames = optdict.keys()
        optnames.sort()
        for optname in optnames:
            # ... decode according to format ...
            optvalue = optdict[optname]
            if isinstance(optvalue, dict):
                preamble.append(optname)
                rv = rv + get_options(np, optvalue)
                del preamble[-1]
            else:
                rv = rv + self.render_option(preamble, optname, optvalue)
        return rv
                
    def render_option(self, preamble, optname, optvalue):
        if optname != None:
            preamble.append(optname)
        if isinstance(optvalue, bytearray):
            rv = self.do_preamble(preamble)
            colon = ""
            rv = rv + "<td>"
            for byte in optvalue:
                rv = rv + colon + format(byte, '02x')
                colon = ":"
            rv = rv + "</td></tr>"
        elif isinstance(optvalue, str):
            rv = self.do_preamble(preamble)
            rv = rv + ("<td>" +
                       tornado.escape.xhtml_escape(optvalue) + "</td>")
        elif isinstance(optvalue, list):
            rv = ""
            for element in optvalue:
                rv = rv + self.render_option(preamble, None, element)
        else:
            rv = self.do_preamble(preamble)
            rv = rv + "<td>" + str(optvalue) + "</td>"
        if optname != None:
            del preamble[-1]
        return rv

    def do_preamble(self, preamble):
        rv = "<tr>"
        for i in range(0, len(preamble)):
            element = preamble[i]
            rv = rv + "<td>" + str(element) + "</td>"
            preamble[i] = ""
        return rv
                

    def start(self):
	self.options = {}
	self.add_addrs = []
	self.del_addrs = []
	self.resolver = None
	self.dsl = None
	self.cur_iface = None
        self.settings = []
        self.next_addresses = self.addresses.copy()
        self.next_optdict = self.optdict.copy()

    def finish(self):
        self.addresses = self.next_addresses
        self.optdict = self.next_optdict
        if len(self.addresses.keys()) != 0:
            self.state = "stateful"
        elif len(self.optdict.keys()) != 0:
            self.state = "stateless"
        print repr(self.addresses)
        print repr(self.optdict)
        print self.state

    # Options can be nested, so we need to figure out which option dictionary
    # applies to a given prefix.   If the prefix is just the interface name,
    # that's going to be the option dictionary for that interface.   If the
    # second item in the prefix is an IP address, we need to recurse into the
    # option dictionary for that address.  Otherwise, we recurse into the
    # option dictionary for the interface.
    def find_optdict(self, prefvec):
        if len(prefvec) == 1:
            return self.next_optdict
        if self.next_addresses.has_key(prefvec[1]):
            return self.find_optdict_in(prefvec[2:],
                                        self.next_addresses[prefvec[1]])
        return self.find_optdict_in(prefvec[1:], self.next_optdict)

    def find_optdict_in(self, prefvec, optdict):
        # If there aren't any more elements in the prefix, we've found our
        # dictionary.
        if len(prefvec) == 0:
            return optdict;
        # If there is no dictionary for this option, make one
        if not optdict.has_key(prefvec[0]):
            optdict[prefvec[0]] = {}
        # Now recurse into it.
        return self.find_optdict_in(prefvec[1:], optdict[prefvec[0]])

    def add_item(self, prefix, name, value):
	prefvec = string.split(prefix, "/")
        print prefvec, name, repr(value)
	if name == 'reason':
            if value == 'released':
                self.next_addresses = {}
                self.optdict = {}
	elif name == 'action':
            if value == 'add':
                self.next_addresses[prefvec[1]] = {}
            elif value == 'remove':
                if self.next_addresses.has_key(prefvec[1]):
                    del self.next_addresses[prefvec[1]]
        elif name == 'valid':
            if self.next_addresses.has_key(prefvec[1]):
                self.next_addresses[prefvec[1]]['valid'] = value
        elif name == 'preferred':
            if self.next_addresses.has_key(prefvec[1]):
                self.next_addresses[prefvec[1]]['preferred'] = value
	elif name == 'option':
            optdict = self.find_optdict(prefvec)
            optdict[value[0]] = value[1]

class Summarizer(tornado.web.RequestHandler):
    def get(self):
        rv = "<h1>Interfaces that support IPv6</h1>"
        rv = rv + ("<table><tr>" +
                   "<th>name</th>"
                   "<th>state</th>"
                   "<th>address</th>"
                   "<th>dns</th></tr>")
        
        for interface in interfaces:
            controller = controllers[interface.name]
            addresses = controller.addresses.keys()
            if len(addresses) == 0:
                address = "-"
            elif len(addresses) == 1:
                address = addresses[0]
            else:
                address = (addresses[0] + " (" + str(len(addresses) - 1) +
                           " more)")
            dnsses = controller.optdict.get("dhcpv6.domain-name-servers", [])
            if len(dnsses) == 0:
                dns = "-"
            elif len(dnsses) == 1:
                dns = dnsses[0]
            else:
                dns = dnsses[0] + " (" + str(len(dnsses)) + " more)"

            rv = (rv + '<tr><td><a href="/' + interface.name + '/">' +
                  interface.name + "</a></td>" +
                  "<td>" + controller.state + "</td>" +
                  "<td>" + address + "</td>" +
                  "<td>" + dns + "</td>" +
                  ('<td><a href="/' +
                   interface.name + '/delete/">delete</a></td>') +
                  ('<td><a href="/' +
                   interface.name + '/release/">release</a></td>') +
                  ('<td><a href="/' +
                   interface.name + '/stateful/">stateful</a></td>') +
                  ('<td><a href="/' +
                   interface.name + '/stateless/">stateless</a></td>') +
                  "</tr>")

        self.write(page_wrap(rv))

interface_names = dhcp.discover_interfaces()
for name in interface_names:
    interface = dhcp.Interface(name)
    v6addrs = interface.v6addrs
    if len(v6addrs) > 0:
        local = False
        for addr in v6addrs:
            if addr == '::1':
                local = True
        if not local:
            interfaces.append(interface)
try:
  duif = file("dhcp-client-duid", "r")
  duid = duif.read()
  duif.close()
except Exception, v:
  print v
  hwaddr = interfaces[0].lladdr
  hwtype = interfaces[0].lltype
  duid = struct.pack("!HLHs", 1, int(time.time()), hwtype, hwaddr)
  try:
      duif = file("dhcp-client-duid", "w")
      duif.write(duid)
      duif.close()
  except:
      print "can't create dhcp-client-duid file."
dhcp.v6netsetup()

links = []
for interface in interfaces:
    name = interface.name
    controllers[name] = Controller(name)
    clients[name] = dhcp.v6client(name, controllers[name], duid)
    controllers[name].set_client(clients[name])
links.append(("/", Summarizer))
links.append(("/([/a-zA-Z0-9]*)/", InterfaceHandler))

ioloop = tornado.ioloop.IOLoop(impl=dhcpp_select())
application = tornado.web.Application(links)
http_server = tornado.httpserver.HTTPServer(application, io_loop=ioloop)
http_server.listen(8000)

# Controller needs to be tied in to AJAX events.

print "Starting I/O Loop..."
ioloop.start()
