# emacs: -*- mode: python; py-indent-offset: 4; indent-tabs-mode: t -*-
# vi: set ft=python sts=4 ts=4 sw=4 noet :

# This file is part of Fail2Ban.
#
# Fail2Ban is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Fail2Ban is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Fail2Ban; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

__author__ = "Fail2Ban Developers, Alexander Koeppe, Serg G. Brester"
__copyright__ = "Copyright (c) 2004-2016 Fail2ban Developers"
__license__ = "GPL"

import re
import socket
import struct

from .utils import Utils
from ..helpers import getLogger

# Gets the instance of the logger.
logSys = getLogger(__name__)


##
# Helper functions
#
#
def asip(ip):
	"""A little helper to guarantee ip being an IPAddr instance"""
	if isinstance(ip, IPAddr):
		return ip
	return IPAddr(ip)


##
# Utils class for DNS handling.
#
# This class contains only static methods used to handle DNS 
#
class DNSUtils:

	# todo: make configurable the expired time and max count of cache entries:
	CACHE_nameToIp = Utils.Cache(maxCount=1000, maxTime=5*60)
	CACHE_ipToName = Utils.Cache(maxCount=1000, maxTime=5*60)

	@staticmethod
	def dnsToIp(dns):
		""" Convert a DNS into an IP address using the Python socket module.
			Thanks to Kevin Drapel.
		"""
		# cache, also prevent long wait during retrieving of ip for wrong dns or lazy dns-system:
		ips = DNSUtils.CACHE_nameToIp.get(dns)
		if ips is not None: 
			return ips
		# retrieve ips
		try:
			ips = list()
			for result in socket.getaddrinfo(dns, None, 0, 0, socket.IPPROTO_TCP):
				ip = IPAddr(result[4][0])
				if ip.isValidIP():
					ips.append(ip)
		except socket.error, e:
			# todo: make configurable the expired time of cache entry:
			logSys.warning("Unable to find a corresponding IP address for %s: %s", dns, e)
			ips = list()
		DNSUtils.CACHE_nameToIp.set(dns, ips)
		return ips

	@staticmethod
	def ipToName(ip):
		# cache, also prevent long wait during retrieving of name for wrong addresses, lazy dns:
		v = DNSUtils.CACHE_ipToName.get(ip, ())
		if v != ():
			return v
		# retrieve name
		try:
			if not isinstance(ip, IPAddr):
				v = socket.gethostbyaddr(ip)[0]
			else:
				v = socket.gethostbyaddr(ip.ntoa())[0]
		except socket.error, e:
			logSys.debug("Unable to find a name for the IP %s: %s", ip, e)
			v = None
		DNSUtils.CACHE_ipToName.set(ip, v)
		return v

	@staticmethod
	def textToIp(text, useDns):
		""" Return the IP of DNS found in a given text.
		"""
		ipList = list()
		# Search for plain IP
		plainIP = IPAddr.searchIP(text)
		if plainIP is not None:
			ip = IPAddr(plainIP.group(0))
			if ip.isValidIP():
				ipList.append(ip)

		# If we are allowed to resolve -- give it a try if nothing was found
		if useDns in ("yes", "warn") and not ipList:
			# Try to get IP from possible DNS
			ip = DNSUtils.dnsToIp(text)
			ipList.extend(ip)
			if ip and useDns == "warn":
				logSys.warning("Determined IP using DNS Lookup: %s = %s",
					text, ipList)

		return ipList


##
# Class for IP address handling.
#
# This class contains methods for handling IPv4 and IPv6 addresses.
class IPAddr(object):
	""" provide functions to handle IPv4 and IPv6 addresses 
	"""

	IP_CRE = re.compile("^(?:\d{1,3}\.){3}\d{1,3}$")
	IP6_CRE = re.compile("^[0-9a-fA-F]{4}[0-9a-fA-F:]+:[0-9a-fA-F]{1,4}|::1$")

	# object attributes
	addr = 0
	family = socket.AF_UNSPEC
	plen = 0
	valid = False
	raw = ""

	# todo: make configurable the expired time and max count of cache entries:
	CACHE_OBJ = Utils.Cache(maxCount=1000, maxTime=5*60)

	def __new__(cls, ipstring, cidr=-1):
		# already correct IPAddr
		args = (ipstring, cidr)
		ip = IPAddr.CACHE_OBJ.get(args)
		if ip is not None:
			return ip
		ip = super(IPAddr, cls).__new__(cls)
		ip.__init(ipstring, cidr)
		IPAddr.CACHE_OBJ.set(args, ip)
		return ip

	# object methods
	def __init(self, ipstring, cidr=-1):
		""" initialize IP object by converting IP address string
			to binary to integer
		"""
		for family in [socket.AF_INET, socket.AF_INET6]:
			try:
				binary = socket.inet_pton(family, ipstring)
				self.valid = True
				break
			except socket.error:
				continue

		if self.valid and family == socket.AF_INET:
			# convert host to network byte order
			self.addr, = struct.unpack("!L", binary)
			self.family = family
			self.plen = 32

			# mask out host portion if prefix length is supplied
			if cidr != None and cidr >= 0:
				mask = ~(0xFFFFFFFFL >> cidr)
				self.addr = self.addr & mask
				self.plen = cidr

		elif self.valid and family == socket.AF_INET6:
			# convert host to network byte order
			hi, lo = struct.unpack("!QQ", binary)
			self.addr = (hi << 64) | lo
			self.family = family
			self.plen = 128

			# mask out host portion if prefix length is supplied
			if cidr != None and cidr >= 0:
				mask = ~(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFL >> cidr)
				self.addr = self.addr & mask
				self.plen = cidr

			# if IPv6 address is a IPv4-compatible, make instance a IPv4
			elif self.isInNet(IPAddr("::ffff:0:0", 96)):
				self.addr = lo & 0xFFFFFFFFL
				self.family = socket.AF_INET
				self.plen = 32
		else:
			# string couldn't be converted neither to a IPv4 nor
			# to a IPv6 address - retain raw input for later use
			# (e.g. DNS resolution)
			self.raw = ipstring

	def __repr__(self):
		return self.ntoa()

	def __str__(self):
		return self.ntoa()

	def __eq__(self, other):
		if not isinstance(other, IPAddr):
			if other is None: return False
			other = IPAddr(other)
		if not self.valid and not other.valid: return self.raw == other.raw
		if not self.valid or not other.valid: return False
		if self.addr != other.addr: return False
		if self.family != other.family: return False
		if self.plen != other.plen: return False
		return True

	def __ne__(self, other):
		if not isinstance(other, IPAddr):
			if other is None: return True
			other = IPAddr(other)
		if not self.valid and not other.valid: return self.raw != other.raw
		if self.addr != other.addr: return True
		if self.family != other.family: return True
		if self.plen != other.plen: return True
		return False

	def __lt__(self, other):
		if not isinstance(other, IPAddr):
			if other is None: return False
			other = IPAddr(other)
		return self.family < other.family or self.addr < other.addr

	def __add__(self, other):
		if not isinstance(other, IPAddr):
			other = IPAddr(other)
		return "%s%s" % (self, other)

	def __radd__(self, other):
		if not isinstance(other, IPAddr):
			other = IPAddr(other)
		return "%s%s" % (other, self)

	def __hash__(self):
		# should be the same as by string (because of possible compare with string):
		return hash(self.ntoa())
		#return hash(self.addr)^hash((self.plen<<16)|self.family)

	def hexdump(self):
		""" dump the ip address in as a hex sequence in
			network byte order - for debug purpose
		"""
		if self.family == socket.AF_INET:
			return "%08x" % self.addr
		elif self.family == socket.AF_INET6:
			return "%032x" % self.addr
		else:
			return ""
	
	def ntoa(self):
		""" represent IP object as text like the depricated 
			C pendant inet_ntoa() but address family independent
		"""
		if self.family == socket.AF_INET:
			# convert network to host byte order
			binary = struct.pack("!L", self.addr)
		elif self.family == socket.AF_INET6:
			# convert network to host byte order
			hi = self.addr >> 64
			lo = self.addr & 0xFFFFFFFFFFFFFFFFL
			binary = struct.pack("!QQ", hi, lo)
		else:
			return self.getRaw()

		return socket.inet_ntop(self.family, binary)

	def getPTR(self, suffix=""):
		""" generates the DNS PTR string of the provided IP address object
			if "suffix" is provided it will be appended as the second and top
			level reverse domain.
			if omitted it is implicitely set to the second and top level reverse
			domain of the according IP address family
		"""
		if self.family == socket.AF_INET:
			reversed_ip = ".".join(reversed(self.ntoa().split(".")))
			if not suffix:
				suffix = "in-addr.arpa."

			return "%s.%s" % (reversed_ip, suffix)

		elif self.family == socket.AF_INET6:
			reversed_ip = ".".join(reversed(self.hexdump()))
			if not suffix:
				suffix =  "ip6.arpa."

			return "%s.%s" % (reversed_ip, suffix)
			
		else:
			return ""

	def isIPv4(self):
		""" return true if the IP object is of address family AF_INET
		"""
		return self.family == socket.AF_INET

	def isIPv6(self):
		""" return true if the IP object is of address family AF_INET6
		"""
		return self.family == socket.AF_INET6

	def getRaw(self):
		""" returns the raw attribute - should only be set
			to a non-empty string if prior address conversion
			wasn't possible
		"""
		return self.raw

	def isValidIP(self):
		""" returns true if the IP object has been created
			from a valid IP address or false if not
		"""
		return self.valid

	
	def isInNet(self, net):
		""" returns true if the IP object is in the provided
			network (object)
		"""
		# if it isn't a valid IP address, try DNS resolution
		if not net.isValidIP() and net.getRaw() != "":
			# Check if IP in DNS
			return self in DNSUtils.dnsToIp(net.getRaw())

		if self.family != net.family:
			return False

		if self.family == socket.AF_INET:
			mask = ~(0xFFFFFFFFL >> net.plen)

		elif self.family == socket.AF_INET6:
			mask = ~(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFL >> net.plen)
		else:
			return False
		
		if self.addr & mask == net.addr:
			return True

		return False

	@property
	def maskplen(self):
		plen = 0
		if (hasattr(self, '_maskplen')):
			return self._plen
		maddr = self.addr
		while maddr:
			if not (maddr & 0x80000000):
				raise ValueError("invalid mask %r, no plen representation" % (self.ntoa(),))
			maddr = (maddr << 1) & 0xFFFFFFFFL
			plen += 1
		self._maskplen = plen
		return plen

		
	@staticmethod
	def masktoplen(maskstr):
		""" converts mask string to prefix length
			only used for IPv4 masks
		"""
		return IPAddr(maskstr).maskplen


	@staticmethod
	def searchIP(text):
		""" Search if an IP address if directly available and return
			it.
		"""
		match = IPAddr.IP_CRE.match(text)
		if match:
			return match
		else:
			match = IPAddr.IP6_CRE.match(text)
			if match:
				return match
			else:
				return None

