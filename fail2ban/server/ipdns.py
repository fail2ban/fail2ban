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

__author__ = "Fail2Ban Developers, Alexander Koeppe, Serg G. Brester, Yaroslav Halchenko"
__copyright__ = "Copyright (c) 2004-2016 Fail2ban Developers"
__license__ = "GPL"

import socket
import struct
import re

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
		ips = list()
		saveerr = None
		for fam, ipfam in ((socket.AF_INET, IPAddr.FAM_IPv4), (socket.AF_INET6, IPAddr.FAM_IPv6)):
			try:
				for result in socket.getaddrinfo(dns, None, fam, 0, socket.IPPROTO_TCP):
					ip = IPAddr(result[4][0], ipfam)
					if ip.isValid:
						ips.append(ip)
			except socket.error as e:
				saveerr = e
		if not ips and saveerr:
			logSys.warning("Unable to find a corresponding IP address for %s: %s", dns, saveerr)

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
			v = socket.gethostbyaddr(ip)[0]
		except socket.error as e:
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
			ip = IPAddr(plainIP)
			if ip.isValid:
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

	@staticmethod
	def getSelfNames():
		"""Get own host names of self"""
		# try find cached own hostnames (this tuple-key cannot be used elsewhere):
		key = ('self','dns')
		names = DNSUtils.CACHE_ipToName.get(key)
		# get it using different ways (a set with names of localhost, hostname, fully qualified):
		if names is None:
			names = set(['localhost'])
			for hostname in (socket.gethostname, socket.getfqdn):
				try:
					names |= set([hostname()])
				except Exception as e: # pragma: no cover
					logSys.warning("Retrieving own hostnames failed: %s", e)
		# cache and return :
		DNSUtils.CACHE_ipToName.set(key, names)
		return names

	@staticmethod
	def getSelfIPs():
		"""Get own IP addresses of self"""
		# try find cached own IPs (this tuple-key cannot be used elsewhere):
		key = ('self','ips')
		ips = DNSUtils.CACHE_nameToIp.get(key)
		# get it using different ways (a set with IPs of localhost, hostname, fully qualified):
		if ips is None:
			ips = set()
			for hostname in DNSUtils.getSelfNames():
				try:
					ips |= set(DNSUtils.textToIp(hostname, 'yes'))
				except Exception as e: # pragma: no cover
					logSys.warning("Retrieving own IPs of %s failed: %s", hostname, e)
		# cache and return :
		DNSUtils.CACHE_nameToIp.set(key, ips)
		return ips


##
# Class for IP address handling.
#
# This class contains methods for handling IPv4 and IPv6 addresses.
#
class IPAddr(object):
	"""Encapsulate functionality for IPv4 and IPv6 addresses
	"""

	IP_4_RE = r"""(?:\d{1,3}\.){3}\d{1,3}"""
	IP_6_RE = r"""(?:[0-9a-fA-F]{1,4}::?|::){1,7}(?:[0-9a-fA-F]{1,4}|(?<=:):)"""
	IP_4_6_CRE = re.compile(
	  r"""^(?:(?P<IPv4>%s)|\[?(?P<IPv6>%s)\]?)$""" % (IP_4_RE, IP_6_RE))
	# An IPv4 compatible IPv6 to be reused (see below)
	IP6_4COMPAT = None

	# object attributes
	__slots__ = '_family','_addr','_plen','_maskplen','_raw'

	# todo: make configurable the expired time and max count of cache entries:
	CACHE_OBJ = Utils.Cache(maxCount=1000, maxTime=5*60)

	CIDR_RAW = -2
	CIDR_UNSPEC = -1
	FAM_IPv4 = CIDR_RAW - socket.AF_INET
	FAM_IPv6 = CIDR_RAW - socket.AF_INET6

	def __new__(cls, ipstr, cidr=CIDR_UNSPEC):
		# check already cached as IPAddr
		args = (ipstr, cidr)
		ip = IPAddr.CACHE_OBJ.get(args)
		if ip is not None:
			return ip
		# wrap mask to cidr (correct plen):
		if cidr == IPAddr.CIDR_UNSPEC:
			ipstr, cidr = IPAddr.__wrap_ipstr(ipstr)
			args = (ipstr, cidr)
			# check cache again:
			if cidr != IPAddr.CIDR_UNSPEC:
				ip = IPAddr.CACHE_OBJ.get(args)
				if ip is not None:
					return ip
		ip = super(IPAddr, cls).__new__(cls)
		ip.__init(ipstr, cidr)
		IPAddr.CACHE_OBJ.set(args, ip)
		return ip

	@staticmethod
	def __wrap_ipstr(ipstr):
		# because of standard spelling of IPv6 (with port) enclosed in brackets ([ipv6]:port),
		# remove they now (be sure the <HOST> inside failregex uses this for IPv6 (has \[?...\]?)
		if len(ipstr) > 2 and ipstr[0] == '[' and ipstr[-1] == ']':
			ipstr = ipstr[1:-1]
		# test mask:
		if "/" not in ipstr:
			return ipstr, IPAddr.CIDR_UNSPEC
		s = ipstr.split('/', 1)
		# IP address without CIDR mask
		if len(s) > 2:
			raise ValueError("invalid ipstr %r, too many plen representation" % (ipstr,))
		if "." in s[1] or ":" in s[1]: # 255.255.255.0 resp. ffff:: style mask
			s[1] = IPAddr.masktoplen(s[1])
		s[1] = long(s[1])
		return s
		
	def __init(self, ipstr, cidr=CIDR_UNSPEC):
		""" initialize IP object by converting IP address string
			to binary to integer
		"""
		self._family = socket.AF_UNSPEC
		self._addr = 0
		self._plen = 0
		self._maskplen = None
		# always save raw value (normally used if really raw or not valid only):
		self._raw = ipstr
		# if not raw - recognize family, set addr, etc.:
		if cidr != IPAddr.CIDR_RAW:
			if cidr is not None and cidr < IPAddr.CIDR_RAW:
				family = [IPAddr.CIDR_RAW - cidr]
			else:
				family = [socket.AF_INET, socket.AF_INET6]
			for family in family:
				try:
					binary = socket.inet_pton(family, ipstr)
					self._family = family
					break
				except socket.error:
					continue

			if self._family == socket.AF_INET:
				# convert host to network byte order
				self._addr, = struct.unpack("!L", binary)
				self._plen = 32

				# mask out host portion if prefix length is supplied
				if cidr is not None and cidr >= 0:
					mask = ~(0xFFFFFFFFL >> cidr)
					self._addr &= mask
					self._plen = cidr

			elif self._family == socket.AF_INET6:
				# convert host to network byte order
				hi, lo = struct.unpack("!QQ", binary)
				self._addr = (hi << 64) | lo
				self._plen = 128

				# mask out host portion if prefix length is supplied
				if cidr is not None and cidr >= 0:
					mask = ~(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFL >> cidr)
					self._addr &= mask
					self._plen = cidr

				# if IPv6 address is a IPv4-compatible, make instance a IPv4
				elif self.isInNet(IPAddr.IP6_4COMPAT):
					self._addr = lo & 0xFFFFFFFFL
					self._family = socket.AF_INET
					self._plen = 32
		else:
			self._family = IPAddr.CIDR_RAW

	def __repr__(self):
		return self.ntoa

	def __str__(self):
		return self.ntoa

	def __reduce__(self):
		"""IPAddr pickle-handler, that simply wraps IPAddr to the str

		Returns a string as instance to be pickled, because fail2ban-client can't
		unserialize IPAddr objects
		"""
		return (str, (self.ntoa,))
	
	@property
	def addr(self):
		return self._addr

	@property
	def family(self):
		return self._family

	FAM2STR = {socket.AF_INET: 'inet4', socket.AF_INET6: 'inet6'}
	@property
	def familyStr(self):
		return IPAddr.FAM2STR.get(self._family)

	@property
	def plen(self):
		return self._plen

	@property
	def raw(self):
		"""The raw address

		Should only be set to a non-empty string if prior address
		conversion wasn't possible
		"""
		return self._raw

	@property
	def isValid(self):
		"""Either the object corresponds to a valid IP address
		"""
		return self._family != socket.AF_UNSPEC

	def __eq__(self, other):
		if self._family == IPAddr.CIDR_RAW and not isinstance(other, IPAddr):
			return self._raw == other
		if not isinstance(other, IPAddr):
			if other is None: return False
			other = IPAddr(other)
		if self._family != other._family: return False
		if self._family == socket.AF_UNSPEC:
			return self._raw == other._raw
		return (
			(self._addr == other._addr) and
			(self._plen == other._plen)
		)

	def __ne__(self, other):
		return not (self == other)

	def __lt__(self, other):
		if self._family == IPAddr.CIDR_RAW and not isinstance(other, IPAddr):
			return self._raw < other
		if not isinstance(other, IPAddr):
			if other is None: return False
			other = IPAddr(other)
		return self._family < other._family or self._addr < other._addr

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
		return hash(self.ntoa)
		#return hash(self._addr)^hash((self._plen<<16)|self._family)

	@property
	def hexdump(self):
		"""Hex representation of the IP address (for debug purposes)
		"""
		if self._family == socket.AF_INET:
			return "%08x" % self._addr
		elif self._family == socket.AF_INET6:
			return "%032x" % self._addr
		else:
			return ""

	# TODO: could be lazily evaluated
	@property
	def ntoa(self):
		""" represent IP object as text like the deprecated
			C pendant inet.ntoa but address family independent
		"""
		add = ''
		if self.isIPv4:
			# convert network to host byte order
			binary = struct.pack("!L", self._addr)
			if self._plen and self._plen < 32:
				add = "/%d" % self._plen
		elif self.isIPv6:
			# convert network to host byte order
			hi = self._addr >> 64
			lo = self._addr & 0xFFFFFFFFFFFFFFFFL
			binary = struct.pack("!QQ", hi, lo)
			if self._plen and self._plen < 128:
				add = "/%d" % self._plen
		else:
			return self._raw
		
		return socket.inet_ntop(self._family, binary) + add

	def getPTR(self, suffix=None):
		""" return the DNS PTR string of the provided IP address object

			If "suffix" is provided it will be appended as the second and top
			level reverse domain.
			If omitted it is implicitly set to the second and top level reverse
			domain of the according IP address family
		"""
		if self.isIPv4:
			exploded_ip = self.ntoa.split(".")
			if suffix is None:
				suffix = "in-addr.arpa."
		elif self.isIPv6:
			exploded_ip = self.hexdump
			if suffix is None:
				suffix = "ip6.arpa."
		else:
			return ""

		return "%s.%s" % (".".join(reversed(exploded_ip)), suffix)

	def getHost(self):
		"""Return the host name (DNS) of the provided IP address object
		"""
		return DNSUtils.ipToName(self.ntoa)

	@property
	def isIPv4(self):
		"""Either the IP object is of address family AF_INET
		"""
		return self.family == socket.AF_INET

	@property
	def isIPv6(self):
		"""Either the IP object is of address family AF_INET6
		"""
		return self.family == socket.AF_INET6

	def isInNet(self, net):
		"""Return either the IP object is in the provided network
		"""
		# if it isn't a valid IP address, try DNS resolution
		if not net.isValid and net.raw != "":
			# Check if IP in DNS
			return self in DNSUtils.dnsToIp(net.raw)

		if self.family != net.family:
			return False
		if self.isIPv4:
			mask = ~(0xFFFFFFFFL >> net.plen)
		elif self.isIPv6:
			mask = ~(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFL >> net.plen)
		else:
			return False
		
		return (self.addr & mask) == net.addr

	# Pre-calculated map: addr to maskplen
	def __getMaskMap():
		m6 = (1 << 128)-1
		m4 = (1 << 32)-1
		mmap = {m6: 128, m4: 32, 0: 0}
		m = 0
		for i in xrange(0, 128):
			m |= 1 << i
			if i < 32:
				mmap[m ^ m4] = 32-1-i
			mmap[m ^ m6] = 128-1-i
		return mmap

	MAP_ADDR2MASKPLEN = __getMaskMap()

	@property
	def maskplen(self):
		mplen = 0
		if self._maskplen is not None:
			return self._maskplen
		mplen = IPAddr.MAP_ADDR2MASKPLEN.get(self._addr)
		if mplen is None:
			raise ValueError("invalid mask %r, no plen representation" % (str(self),))
		self._maskplen = mplen
		return mplen
		
	@staticmethod
	def masktoplen(mask):
		"""Convert mask string to prefix length

		To be used only for IPv4 masks
		"""
		return IPAddr(mask).maskplen

	@staticmethod
	def searchIP(text):
		"""Search if text is an IP address, and return it if so, else None
		"""
		match = IPAddr.IP_4_6_CRE.match(text)
		if not match:
			return None
		ipstr = match.group('IPv4')
		if ipstr != '':
			return ipstr
		return match.group('IPv6')


# An IPv4 compatible IPv6 to be reused
IPAddr.IP6_4COMPAT = IPAddr("::ffff:0:0", 96)
