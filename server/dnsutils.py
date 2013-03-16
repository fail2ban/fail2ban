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

# Author: Cyril Jaquier
#
# $Revision$

##
# Utils class for DNS and IP handling.
#
# This class contains only static methods used to handle DNS and IP
# addresses.

import socket, struct
import re

import logging
# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.dnsutils")


class DNSUtils:

	IP_CRE = re.compile("^(?:\d{1,3}\.){3}\d{1,3}$")
	IP_CRE6 = re.compile("^(?:[0-9:A-Fa-f]{3,})$")
	
	#@staticmethod
	def dnsToIp(dns):
		""" Convert a DNS into an IP address using the Python socket module.
			Thanks to Kevin Drapel. IPv6 by Daniel Black
		"""
		try:
			addresses = socket.getaddrinfo(dns,None)
			ipList = list()
			# Returns list of addresstype, address tuples
			for a in addresses:
				fip = (  a[0], a[4][0] )
				if fip not in ipList:
					ipList.append(fip)

			return ipList

		except socket.gaierror:
			logSys.warn("Unable to find a corresponding IP address for %s"
						% dns)
			return list()
	dnsToIp = staticmethod(dnsToIp)

	#@staticmethod
	def searchIP(text):
		""" Search if an IP address if directly available and return
			it.
		"""
		match = DNSUtils.IP_CRE.match(text)
		if match:
			return (socket.AF_INET, match.group(0) )
		else:
			match = DNSUtils.IP_CRE6.match(text)
			if match:
				""" Right Here, we faced to a ipv6
				"""
				return (socket.AF_INET6, match.group(0) )
			else:
				return None
	searchIP = staticmethod(searchIP)

	#@staticmethod
	def ipFamily(string):
		# Return true if str is a valid IP
		s = string.split('/', 1)
		# try to convert to ipv4
		try:
			socket.inet_aton(s[0])
			return socket.AF_INET
		except socket.error:
			# if it had failed try to convert ipv6
			try:  
				socket.inet_pton(socket.AF_INET6, s[0])
				return socket.AF_INET6
			except socket.error: 
				# not a valid address in both stacks
				return False
	ipFamily = staticmethod(ipFamily)

	#@staticmethod
	def textToIp(text, useDns):
		""" Return the IP of DNS found in a given text.
		"""
		ipList = list()
		# Search for plain IP
		plainIP = DNSUtils.searchIP(text)
		if plainIP:
			plainIPStr = plainIP[1]
			ipfamily=DNSUtils.ipFamily(plainIPStr)
			if ipfamily:
				ipList.append( ( ipfamily, plainIPStr) )

		# If we are allowed to resolve -- give it a try if nothing was found
		if useDns in ("yes", "warn") and not ipList:
			# Try to get IP from possible DNS
			ip = DNSUtils.dnsToIp(text)
			ipList.extend(ip)
			if ip and useDns == "warn":
				logSys.warning("Determined IP using DNS Lookup: %s = %s",
					text, ipList)

		return ipList
	textToIp = staticmethod(textToIp)

	#@staticmethod
	def cidr(i, n, f):
		""" Convert an IP address string with a CIDR mask into a long
		"""
		if f == socket.AF_INET6:
			MASK = (2**128) - 1
		else:
			# 32-bit IPv4 address mask
			MASK = (2**32) - 1
		return ~(MASK >> n) & DNSUtils.addr2bin(i, f)
	cidr = staticmethod(cidr)

	#@staticmethod
	def truncatetoprefix(i, n, f):
		""" Convert an Ip address to the prefix n omitting the host parts
		"""
		ip_int = DNSUtils.cidr(i, n, f)
		# copied from ipaddr _string_from_ip_int

		if f == socket.AF_INET6:
			hex_str = '%032x' % ip_int
			hextets = []
			for x in range(0, 32, 4):
				hextets.append('%x' % int(hex_str[x:x+4], 16))
			return ':'.join(hextets) + '/' + str(n)
		else:
			raise ValueError('have not done IPv4 yet...')
	truncatetoprefix = staticmethod(truncatetoprefix)
	
	#@staticmethod
	def addr2bin(string, f):
		""" Convert a string IP address into an unsigned long.
		"""
		s = socket.inet_pton(f,string)
		if f == socket.AF_INET6:
			h,l = struct.unpack("!QQ",s)
			return h << 64 | l
		else:
			return struct.unpack("!L", s)[0]
	addr2bin = staticmethod(addr2bin)
