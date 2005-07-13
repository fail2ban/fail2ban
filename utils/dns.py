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
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

# Author: Cyril Jaquier
# 
# $Revision: 1.7.2.1 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 1.7.2.1 $"
__date__ = "$Date: 2005/07/12 13:10:14 $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import os, re, socket, struct

def dnsToIp(dns):
	""" Convert a DNS into an IP address using the Python socket module.
		Thanks to Kevin Drapel.
	"""
	try:
		return socket.gethostbyname_ex(dns)[2]
	except socket.gaierror:
		return list()

def textToDns(text):
	""" Search for possible DNS in an arbitrary text.
		Thanks to Tom Pike.
	"""
	match = re.findall("(?:(?:\w|-)+\.){2,}\w+", text)
	if match:
		return match
	else:
		return []

def searchIP(text):
	""" Search if an IP address if directly available and return
		it.
	"""
	match = re.findall("(?:\d{1,3}\.){3}\d{1,3}", text)
	if match:
		return match
	else:
		return []

def textToIp(text):
	""" Return the IP of DNS found in a given text.
	"""
	ipList = list()
	# Search for plain IP
	plainIP = searchIP(text)
	for element in plainIP:
		ipList.append(element)
	if not ipList:
		# Try to get IP from possible DNS
		dnsList = textToDns(text)
		for element in dnsList:
			dns = dnsToIp(element)
			for e in dns:
				ipList.append(e)
	return ipList

def cidr(i, n):
	""" Convert an IP address string with a CIDR mask into a 32-bit
		integer.
	"""
	# 32-bit IPv4 address mask
	MASK = 0xFFFFFFFFL
	return ~(MASK >> n) & MASK & addr2bin(i)

def addr2bin(str):
	""" Convert a string IPv4 address into an unsigned integer.
	"""
	return struct.unpack("!L", socket.inet_aton(str))[0]

def bin2addr(addr):
	""" Convert a numeric IPv4 address into string n.n.n.n form.
	"""
	return socket.inet_ntoa(struct.pack("!L", addr))
