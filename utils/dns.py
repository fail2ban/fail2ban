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
# $Revision$

__author__ = "Cyril Jaquier"
__version__ = "$Revision$"
__date__ = "$Date$"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import os, re

def dnsToIp(dns):
	""" Convert a DNS into an IP address using the "host" command.
		We make sure that there is no malicious usage of this function.
	"""
	ipList = list()
	# Check for command injection
	if checkInjection(dns):
		return ipList
	result = os.popen("host "+dns, 'r')
	for i in result.readlines():
		match = re.search("(?:\d{1,3}\.){3}\d{1,3}", i)
		if match:
			ipList.append(match.group())
	return ipList

def checkInjection(command):
	""" Check that command could not be used to inject shell commands.
	"""
	# Characters which have nothing to do in "command"
	invalid = "<|>|;|\&|\||`|!"
	match = re.search(invalid, command)
	if match:
		return True
	else:
		return False

def textToDns(text):
	""" Search for possible DNS in an arbitrary text.
	"""
	match = re.findall("\w*\.\w*\.\w*", text)
	if match:
		return match
	else:
		return None

def searchIP(text):
	""" Search if an IP address if directly available and return
		it.
	"""
	match = re.findall("(?:\d{1,3}\.){3}\d{1,3}", text)
	if match:
		return match
	else:
		return None

def textToIp(text):
	""" Return the IP of DNS found in a given text.
	"""
	ipList = list()
	# Search for plain IP
	plainIP = searchIP(text)
	if plainIP:
		for element in plainIP:
			ipList.append(element)
	else:
		# Try to get IP from possible DNS
		dnsList = textToDns(text)
		for element in dnsList:
			dns = dnsToIp(element)
			for e in dns:
				ipList.append(e)
	return ipList

if __name__ == "__main__":
	print textToIp("jlkjlk 123.456.789.000 jlkjl rhost=lslpc49.epfl.ch www.google.ch")
	