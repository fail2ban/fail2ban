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

# Author: Alexander Koeppe
# 

__author__ = "Alexander Koeppe"
__copyright__ = "Copyright (c) 2016 Alexander Koeppe"
__license__ = "GPL"

import inspect
import socket
import struct
import re

from functools import wraps


##
# Helper functions / decorator
# Thanks to Yaroslav Halchenko (yarikoptic)
#
def asip(ip):
	"""A little helper to guarantee ip being an IPAddr instance"""
	return ip if isinstance(ip, IPAddr) or ip is None else IPAddr(ip)


def iparg(f):
	"""A helper decorator to simplify use of asip throughout the code"""
	args = inspect.getargspec(f).args
	# I consider clarity better than trying to avoid any duplication here
	# also better to make a decision at code parsing stage, not within the
	# actual decorator function (i.e. checkip)
	if args and args[0] == 'self':
		# method -- just above simpler version
		@wraps(f)
		def checkip(self, ip=None, *argv, **kwargs):
			return f(self, asip(ip), *argv, **kwargs)
	else:
		@wraps(f)
		def checkip(ip=None, *argv, **kwargs):
			return f(asip(ip), *argv, **kwargs)

	return checkip


##
# Class for IP address handling.
#
# This class contains methods for handling IPv4 and IPv6 addresses.

class IPAddr:
	"""Encapsulate functionality for IPv4 and IPv6 addresses
	"""

	IP_CRE = re.compile("^(?:\d{1,3}\.){3}\d{1,3}$")
	IP6_CRE = re.compile("^[0-9a-fA-F]{4}[0-9a-fA-F:]+:[0-9a-fA-F]{1,4}|::1$")

	# object attributes
	_addr = 0
	_family = socket.AF_UNSPEC
	_plen = 0
	_isValid = False
	_raw = ""

	# object methods
	def __init__(self, ipstring, cidr=-1):
		""" initialize IP object by converting IP address string
			to binary to integer
		"""
		for family in [socket.AF_INET, socket.AF_INET6]:
			try:
				binary = socket.inet_pton(family, ipstring)
			except socket.error:
				continue
			else: 
				self._isValid = True
				break

		if self.isValid and family == socket.AF_INET:
			# convert host to network byte order
			self._addr, = struct.unpack("!L", binary)
			self._family = family
			self._plen = 32

			# mask out host portion if prefix length is supplied
			if cidr is not None and cidr >= 0:
				mask = ~(0xFFFFFFFFL >> cidr)
				self._addr &= mask
				self._plen = cidr

		elif self.isValid and family == socket.AF_INET6:
			# convert host to network byte order
			hi, lo = struct.unpack("!QQ", binary)
			self._addr = (hi << 64) | lo
			self._family = family
			self._plen = 128

			# mask out host portion if prefix length is supplied
			if cidr is not None and cidr >= 0:
				mask = ~(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFL >> cidr)
				self._addr &= mask
				self._plen = cidr

			# if IPv6 address is a IPv4-compatible, make instance a IPv4
			elif self.isInNet(_IPv6_v4COMPAT):
				self._addr = lo & 0xFFFFFFFFL
				self._family = socket.AF_INET
				self._plen = 32
		else:
			# string couldn't be converted neither to a IPv4 nor
			# to a IPv6 address - retain raw input for later use
			# (e.g. DNS resolution)
			self._raw = ipstring

	def __repr__(self):
		if self.isIPv4 and self.plen < 32:
			return "%s/%d" % (self.ntoa, self.plen)
		elif self.isIPv6 and self.plen < 128:
			return "%s/%d" % (self.ntoa, self.plen)
		else:
			return self.ntoa

	def __str__(self):
		return self.__repr__()
	
	@property
	def addr(self):
		return self._addr

	@property
	def family(self):
		return self._family

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
		return self._isValid

	@iparg
	def __eq__(self, other):
		if not (self.isValid or other.isValid):
			return self.raw == other.raw
		return (
			(self.isValid and other.isValid) and
			(self.addr == other.addr) and
			(self.family == other.family) and
			(self.plen == other.plen)
		)

	@iparg
	def __ne__(self, other):
		return not (self == other)

	@iparg
	def __lt__(self, other):
		return self.family < other.family or self.addr < other.addr

	@iparg
	def __add__(self, other):
		return "%s%s" % (self, other)

	@iparg
	def __radd__(self, other):
		return "%s%s" % (other, self)

	def __hash__(self):
		return hash(self.addr) ^ hash((self.plen << 16) | self.family)

	@property
	def hexdump(self):
		"""Hex representation of the IP address (for debug purposes)
		"""
		if self.family == socket.AF_INET:
			return "%08x" % self.addr
		elif self.family == socket.AF_INET6:
			return "%032x" % self.addr
		else:
			return ""

	# TODO: could be lazily evaluated
	@property
	def ntoa(self):
		""" represent IP object as text like the deprecated
			C pendant inet.ntoa but address family independent
		"""
		if self.isIPv4:
			# convert network to host byte order
			binary = struct.pack("!L", self._addr)
		elif self.isIPv6:
			# convert network to host byte order
			hi = self.addr >> 64
			lo = self.addr & 0xFFFFFFFFFFFFFFFFL
			binary = struct.pack("!QQ", hi, lo)
		else:
			return self.raw

		return socket.inet_ntop(self.family, binary)

	def getPTR(self, suffix=""):
		""" return the DNS PTR string of the provided IP address object

			If "suffix" is provided it will be appended as the second and top
			level reverse domain.
			If omitted it is implicitly set to the second and top level reverse
			domain of the according IP address family
		"""
		if self.isIPv4:
			exploded_ip = self.ntoa.split(".")
			if not suffix:
				suffix = "in-addr.arpa."
		elif self.isIPv6:
			exploded_ip = self.hexdump()
			if not suffix:
				suffix = "ip6.arpa."
		else:
			return ""

		return "%s.%s" % (".".join(reversed(exploded_ip)), suffix)

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

	@iparg
	def isInNet(self, net):
		"""Return either the IP object is in the provided network
		"""
		if self.family != net.family:
			return False
		if self.isIPv4:
			mask = ~(0xFFFFFFFFL >> net.plen)
		elif self.isIPv6:
			mask = ~(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFL >> net.plen)
		else:
			return False
		
		return self.addr & mask == net.addr

	@staticmethod
	@iparg
	def masktoplen(mask):
		"""Convert mask string to prefix length

		To be used only for IPv4 masks
		"""
		mask = mask.addr  # to avoid side-effect within original mask
		plen = 0
		while mask:
			mask = (mask << 1) & 0xFFFFFFFFL
			plen += 1
		return plen

	@staticmethod
	def searchIP(text):
		"""Search if text is an IP address, and return it if so, else None
		"""
		match = IPAddr.IP_CRE.match(text)
		if not match:
			match = IPAddr.IP6_CRE.match(text)
		return match if match else None

# An IPv4 compatible IPv6 to be reused
_IPv6_v4COMPAT = IPAddr("::ffff:0:0", 96)
