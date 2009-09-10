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
# $Revision: 752 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 752 $"
__date__ = "$Date: 2009-09-01 23:21:30 +0200 (Tue, 01 Sep 2009) $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

from failmanager import FailManager
from ticket import FailTicket
from jailthread import JailThread
from datedetector import DateDetector
from mytime import MyTime
from failregex import FailRegex, Regex, RegexException

import logging, re, os

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.filter")

##
# Log reader class.
#
# This class reads a log file and detects login failures or anything else
# that matches a given regular expression. This class is instanciated by
# a Jail object.

class Filter(JailThread):

	##
	# Constructor.
	#
	# Initialize the filter object with default values.
	# @param jail the jail object
	
	def __init__(self, jail):
		JailThread.__init__(self)
		## The jail which contains this filter.
		self.jail = jail
		## The failures manager.
		self.failManager = FailManager()
		## The regular expression list matching the failures.
		self.__failRegex = list()
		## The regular expression list with expressions to ignore.
		self.__ignoreRegex = list()
		## The amount of time to look back.
		self.__findTime = 6000
		## The ignore IP list.
		self.__ignoreIpList = []
		
		self.dateDetector = DateDetector()
		self.dateDetector.addDefaultTemplate()
		logSys.debug("Created Filter")


	##
	# Add a regular expression which matches the failure.
	#
	# The regular expression can also match any other pattern than failures
	# and thus can be used for many purporse.
	# @param value the regular expression
	
	def addFailRegex(self, value):
		try:
			regex = FailRegex(value)
			self.__failRegex.append(regex)
		except RegexException, e:
			logSys.error(e)
	

	def delFailRegex(self, index):
		try:
			del self.__failRegex[index]
		except IndexError:
			logSys.error("Cannot remove regular expression. Index %d is not "
						 "valid" % index)
	
	##
	# Get the regular expression which matches the failure.
	#
	# @return the regular expression
	
	def getFailRegex(self):
		failRegex = list()
		for regex in self.__failRegex:
			failRegex.append(regex.getRegex())
		return failRegex
	
	##
	# Add the regular expression which matches the failure.
	#
	# The regular expression can also match any other pattern than failures
	# and thus can be used for many purporse.
	# @param value the regular expression
	
	def addIgnoreRegex(self, value):
		try:
			regex = Regex(value)
			self.__ignoreRegex.append(regex)
		except RegexException, e:
			logSys.error(e)
	
	def delIgnoreRegex(self, index):
		try:
			del self.__ignoreRegex[index]
		except IndexError:
			logSys.error("Cannot remove regular expression. Index %d is not "
						 "valid" % index)
	
	##
	# Get the regular expression which matches the failure.
	#
	# @return the regular expression
	
	def getIgnoreRegex(self):
		ignoreRegex = list()
		for regex in self.__ignoreRegex:
			ignoreRegex.append(regex.getRegex())
		return ignoreRegex
	
	##
	# Set the time needed to find a failure.
	#
	# This value tells the filter how long it has to take failures into
	# account.
	# @param value the time
	
	def setFindTime(self, value):
		self.__findTime = value
		self.failManager.setMaxTime(value)
		logSys.info("Set findtime = %s" % value)
	
	##
	# Get the time needed to find a failure.
	#
	# @return the time
	
	def getFindTime(self):
		return self.__findTime
	
	##
	# Set the maximum retry value.
	#
	# @param value the retry value
	
	def setMaxRetry(self, value):
		self.failManager.setMaxRetry(value)
		logSys.info("Set maxRetry = %s" % value)
	
	##
	# Get the maximum retry value.
	#
	# @return the retry value
	
	def getMaxRetry(self):
		return self.failManager.getMaxRetry()
	
	##
	# Main loop.
	#
	# This function is the main loop of the thread. It checks if the
	# file has been modified and looks for failures.
	# @return True when the thread exits nicely

	def run(self):
		raise Exception("run() is abstract")
	
	##
	# Ban an IP - http://blogs.buanzo.com.ar/2009/04/fail2ban-patch-ban-ip-address-manually.html
	# Arturo 'Buanzo' Busleiman <buanzo@buanzo.com.ar>
	#
	# to enable banip fail2ban-client BAN command
	
	def addBannedIP(self, ip):
		unixTime = time.time()
		self.failManager.addFailure(FailTicket(ip, unixTime))
		return ip
	
	##
	# Add an IP/DNS to the ignore list.
	#
	# IP addresses in the ignore list are not taken into account
	# when finding failures. CIDR mask and DNS are also accepted.
	# @param ip IP address to ignore
	
	def addIgnoreIP(self, ip):
		logSys.debug("Add " + ip + " to ignore list")
		self.__ignoreIpList.append(ip)
		
	def delIgnoreIP(self, ip):
		logSys.debug("Remove " + ip + " from ignore list")
		self.__ignoreIpList.remove(ip)
		
	def getIgnoreIP(self):
		return self.__ignoreIpList
	
	##
	# Check if IP address/DNS is in the ignore list.
	#
	# Check if the given IP address matches an IP address/DNS or a CIDR
	# mask in the ignore list.
	# @param ip IP address
	# @return True if IP address is in ignore list
	
	def inIgnoreIPList(self, ip):
		for i in self.__ignoreIpList:
			# An empty string is always false
			if i == "":
				continue
			s = i.split('/', 1)
			# IP address without CIDR mask
			if len(s) == 1:
				s.insert(1, '32')
			s[1] = long(s[1])
			try:
				a = DNSUtils.cidr(s[0], s[1])
				b = DNSUtils.cidr(ip, s[1])
			except Exception:
				# Check if IP in DNS
				ips = DNSUtils.dnsToIp(i)
				if ip in ips:
					return True
				else:
					continue
			if a == b:
				return True
		return False
	

	def processLine(self, line):
		try:
			# Decode line to UTF-8
			l = line.decode('utf-8')
		except UnicodeDecodeError:
			l = line
		timeMatch = self.dateDetector.matchTime(l)
		if timeMatch:
			# Lets split into time part and log part of the line
			timeLine = timeMatch.group()
			# Lets leave the beginning in as well, so if there is no
			# anchore at the beginning of the time regexp, we don't
			# at least allow injection. Should be harmless otherwise
			logLine  = l[:timeMatch.start()] + l[timeMatch.end():]
		else:
			timeLine = l
			logLine = l
		return self.findFailure(timeLine, logLine)

	def processLineAndAdd(self, line):
		for element in self.processLine(line):
			ip = element[0]
			unixTime = element[1]
			if unixTime < MyTime.time() - self.getFindTime():
				break
			if self.inIgnoreIPList(ip):
				logSys.debug("Ignore %s" % ip)
				continue
			logSys.debug("Found %s" % ip)
			self.failManager.addFailure(FailTicket(ip, unixTime))

	##
	# Returns true if the line should be ignored.
	#
	# Uses ignoreregex.
	# @param line: the line
	# @return: a boolean

	def ignoreLine(self, line):
		for ignoreRegex in self.__ignoreRegex:
			ignoreRegex.search(line)
			if ignoreRegex.hasMatched():
				return True
		return False

	##
	# Finds the failure in a line given split into time and log parts.
	#
	# Uses the failregex pattern to find it and timeregex in order
	# to find the logging time.
	# @return a dict with IP and timestamp.

	def findFailure(self, timeLine, logLine):
		failList = list()
		# Checks if we must ignore this line.
		if self.ignoreLine(logLine):
			# The ignoreregex matched. Return.
			return failList
		# Iterates over all the regular expressions.
		for failRegex in self.__failRegex:
			failRegex.search(logLine)
			if failRegex.hasMatched():
				# The failregex matched.
				date = self.dateDetector.getUnixTime(timeLine)
				if date == None:
					logSys.debug("Found a match for '" + logLine +"' but no "
								 + "valid date/time found for '"
								 + timeLine + "'. Please contact the "
								 + "author in order to get support for this "
								 + "format")
				else:
					try:
						host = failRegex.getHost()
						ipMatch = DNSUtils.textToIp(host)
						if ipMatch:
							for ip in ipMatch:
								failList.append([ip, date])
							# We matched a regex, it is enough to stop.
							break
					except RegexException, e:
						logSys.error(e)
		return failList
	

	##
	# Get the status of the filter.
	#
	# Get some informations about the filter state such as the total
	# number of failures.
	# @return a list with tuple
	
	def status(self):
		ret = [("Currently failed", self.failManager.size()), 
			   ("Total failed", self.failManager.getFailTotal())]
		return ret


class FileFilter(Filter):
	
	def __init__(self, jail):
		Filter.__init__(self, jail)
		## The log file path.
		self.__logPath = []
	
	##
	# Add a log file path
	#
	# @param path log file path

	def addLogPath(self, path, tail = False):
		container = FileContainer(path, tail)
		self.__logPath.append(container)
	
	##
	# Delete a log path
	#
	# @param path the log file to delete
	
	def delLogPath(self, path):
		for log in self.__logPath:
			if log.getFileName() == path:
				self.__logPath.remove(log)
				return

	##
	# Get the log file path
	#
	# @return log file path
		
	def getLogPath(self):
		return self.__logPath
	
	##
	# Check whether path is already monitored.
	#
	# @param path The path
	# @return True if the path is already monitored else False
	
	def containsLogPath(self, path):
		for log in self.__logPath:
			if log.getFileName() == path:
				return True
		return False
	
	def getFileContainer(self, path):
		for log in self.__logPath:
			if log.getFileName() == path:
				return log
		return None
	
	##
	# Gets all the failure in the log file.
	#
	# Gets all the failure in the log file which are newer than
	# MyTime.time()-self.findTime. When a failure is detected, a FailTicket
	# is created and is added to the FailManager.
	
	def getFailures(self, filename):
		container = self.getFileContainer(filename)
		if container == None:
			logSys.error("Unable to get failures in " + filename)
			return False
		# Try to open log file.
		try:
			container.open()
		except Exception, e:
			logSys.error("Unable to open %s" % filename)
			logSys.exception(e)
			return False
		
		line = container.readline()
		while not line == "":
			if not self._isActive():
				# The jail has been stopped
				break
			self.processLineAndAdd(line)
			# Read a new line.
			line = container.readline()
		container.close()
		return True
	
	def status(self):
		ret = Filter.status(self)
		path = [m.getFileName() for m in self.getLogPath()]
		ret.append(("File list", path))
		return ret

##
# FileContainer class.
#
# This class manages a file handler and takes care of log rotation detection.
# In order to detect log rotation, the hash (MD5) of the first line of the file
# is computed and compared to the previous hash of this line.

import md5

class FileContainer:
	
	def __init__(self, filename, tail = False):
		self.__filename = filename
		self.__tail = tail
		self.__handler = None
		# Try to open the file. Raises an exception if an error occured.
		handler = open(filename)
		stats = os.fstat(handler.fileno())
		self.__ino = stats.st_ino
		try:
			firstLine = handler.readline()
			# Computes the MD5 of the first line.
			self.__hash = md5.new(firstLine).digest()
			# Start at the beginning of file if tail mode is off.
			if tail:
				handler.seek(0, 2)
				self.__pos = handler.tell()
			else:
				self.__pos = 0
		finally:
			handler.close()
	
	def getFileName(self):
		return self.__filename
	
	def open(self):
		self.__handler = open(self.__filename)
		firstLine = self.__handler.readline()
		# Computes the MD5 of the first line.
		myHash = md5.new(firstLine).digest()
		stats = os.fstat(self.__handler.fileno())
		# Compare hash and inode
		if self.__hash != myHash or self.__ino != stats.st_ino:
			logSys.info("Log rotation detected for %s" % self.__filename)
			self.__hash = myHash
			self.__ino = stats.st_ino
			self.__pos = 0
		# Sets the file pointer to the last position.
		self.__handler.seek(self.__pos)
	
	def readline(self):
		if self.__handler == None:
			return ""
		return self.__handler.readline()
	
	def close(self):
		if not self.__handler == None:
			# Saves the last position.
			self.__pos = self.__handler.tell()
			# Closes the file.
			self.__handler.close()
			self.__handler = None



##
# Utils class for DNS and IP handling.
#
# This class contains only static methods used to handle DNS and IP
# addresses.

import socket, struct

class DNSUtils:
	
	IP_CRE = re.compile("^(?:\d{1,3}\.){3}\d{1,3}$")
	
	#@staticmethod
	def dnsToIp(dns):
		""" Convert a DNS into an IP address using the Python socket module.
			Thanks to Kevin Drapel.
		"""
		try:
			return socket.gethostbyname_ex(dns)[2]
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
			return match
		else:
			return None
	searchIP = staticmethod(searchIP)
	
	#@staticmethod
	def isValidIP(string):
		""" Return true if str is a valid IP
		"""
		s = string.split('/', 1)
		try:
			socket.inet_aton(s[0])
			return True
		except socket.error:
			return False
	isValidIP = staticmethod(isValidIP)
	
	#@staticmethod
	def textToIp(text):
		""" Return the IP of DNS found in a given text.
		"""
		ipList = list()
		# Search for plain IP
		plainIP = DNSUtils.searchIP(text)
		if not plainIP == None:
			plainIPStr = plainIP.group(0)
			if DNSUtils.isValidIP(plainIPStr):
				ipList.append(plainIPStr)
		if not ipList:
			# Try to get IP from possible DNS
			ip = DNSUtils.dnsToIp(text)
			for e in ip:
				ipList.append(e)
		return ipList
	textToIp = staticmethod(textToIp)
	
	#@staticmethod
	def cidr(i, n):
		""" Convert an IP address string with a CIDR mask into a 32-bit
			integer.
		"""
		# 32-bit IPv4 address mask
		MASK = 0xFFFFFFFFL
		return ~(MASK >> n) & MASK & DNSUtils.addr2bin(i)
	cidr = staticmethod(cidr)
	
	#@staticmethod
	def addr2bin(string):
		""" Convert a string IPv4 address into an unsigned integer.
		"""
		return struct.unpack("!L", socket.inet_aton(string))[0]
	addr2bin = staticmethod(addr2bin)
	
	#@staticmethod
	def bin2addr(addr):
		""" Convert a numeric IPv4 address into string n.n.n.n form.
		"""
		return socket.inet_ntoa(struct.pack("!L", addr))
	bin2addr = staticmethod(bin2addr)
