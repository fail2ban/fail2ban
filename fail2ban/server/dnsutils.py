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

__author__ = "Cyril Jaquier and Fail2Ban Contributors"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier, 2011-2013 Yaroslav Halchenko"
__license__ = "GPL"

import logging, socket, struct, re

# Gets the instance of the logger.
logSys = logging.getLogger(__name__)

##
# Utils class for DNS and IP handling.
#
# This class contains only static methods used to handle DNS and IP
# addresses.

IP_CRE = re.compile("^(?:\d{1,3}\.){3}\d{1,3}$")
IP6_CRE = re.compile("^(?:[0-9a-f:])+(/\d+)?$")

def dnsToIp(dns):
	""" Convert a DNS into an IP(v6) address using the Python socket module.
	"""
	addresses = []
	for family in (socket.AF_INET, socket.AF_INET6):
		try:
			address = socket.getaddrinfo(dns, None, family)
			addresses.append(address[0][4][0])
		except (socket.gaierror, IndexError), e:
			pass
	if len(addresses) == 0:
		logSys.warn("Unable to find a corresponding IP address for %s")
	return addresses

def searchIP(text):
	""" Search if an IP address if directly available and return
		it.
	"""
	if isValidIPv6(text):
		match = IP6_CRE.match(text)
	else:
		match = IP_CRE.match(text)
	if match:
		return match
	else:
		return None

def isValidIP(string):
	""" Return true if str is a valid IP
	"""
	s = string.split('/', 1)
	try:
		socket.inet_aton(s[0])
		return True
	except socket.error:
		return False

def isValidIPv6(string):
	""" Return true if str is a valid IPv6 address
	"""
	s = string.split('/', 1)
	try:
		socket.inet_pton(socket.AF_INET6, s[0])
		return True
	except socket.error:
		return False

def textToIp(text, useDns):
	""" Return the IP of DNS found in a given text.
	"""
	ipList = list()
	# Search for plain IP
	plainIP = searchIP(text)
	if not plainIP is None:
		plainIPStr = plainIP.group(0)
		if isValidIP(plainIPStr) or isValidIPv6(plainIPStr):
			ipList.append(plainIPStr)

	# If we are allowed to resolve -- give it a try if nothing was found
	if useDns in ("yes", "warn") and not ipList:
		# Try to get IP from possible DNS
		ip = dnsToIp(text)
		ipList.extend(ip)
		if ip and useDns == "warn":
			logSys.warning("Determined IP using DNS Lookup: %s = %s",
				text, ipList)

	return ipList

def cidr(i, n):
	""" Convert an IP address string with a CIDR mask into a 32-bit
		integer.
	"""
	# 32-bit IPv4 address mask
	MASK = 0xFFFFFFFFL
	return ~(MASK >> n) & MASK & addr2bin(i)

def cidr6(i, n):
	""" Convert an IPv6 address string with a CIDR mask into 128-bit
		integer.
	"""
	# 128-bit IPv6 address mask
	MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFL
	return ~(MASK >> n) & MASK & addr62bin(i)

def addr2bin(string):
	""" Convert a string IPv4 address into an unsigned integer.
	"""
	return struct.unpack("!L", socket.inet_aton(string))[0]

def addr62bin(string):
	""" Convert a string IPv6 address into an unsigned integer.
	"""
	hi, lo = struct.unpack('!QQ', socket.inet_pton(socket.AF_INET6, string))
	return (hi << 64) | lo

def bin2addr(addr):
	""" Convert a numeric IPv4 address into string n.n.n.n form.
	"""
	return socket.inet_ntoa(struct.pack("!L", addr))
