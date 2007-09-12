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

from failmanager import FailManager
from failticket import FailTicket
from jailthread import JailThread
from datedetector import DateDetector
from mytime import MyTime
from regex import Regex, RegexException
from failregex import FailRegex

import logging, re

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
		## The log file handler.
		self.__crtHandler = None
		self.__crtFilename = None
		## The log file path.
		self.__logPath = []
		## The regular expression list matching the failures.
		self.__failRegex = list()
		## The regular expression list with expressions to ignore.
		self.__ignoreRegex = list()
		## The amount of time to look back.
		self.__findTime = 6000
		## The ignore IP list.
		self.__ignoreIpList = []
		## The last position of the file.
		self.__lastPos = dict()
		## The last date in tht log file.
		self.__lastDate = dict()
		
		self.dateDetector = DateDetector()
		self.dateDetector.addDefaultTemplate()
		logSys.info("Created Filter")


	##
	# Add a log file path
	#
	# @param path log file path

	def addLogPath(self, path):
		self.getLogPath().append(path)
		# Initialize default values
		self.__lastDate[path] = 0
		self.__lastPos[path] = 0
	
	##
	# Delete a log path
	#
	# @param path the log file to delete
	
	def delLogPath(self, path):
		self.getLogPath().remove(path)
		del self.__lastDate[path]
		del self.__lastPos[path]

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
		try:
			self.getLogPath().index(path)
			return True
		except ValueError:
			return False
	
	##
	# Set the regular expression which matches the time.
	#
	# @param value the regular expression
	
	def setTimeRegex(self, value):
		self.dateDetector.setDefaultRegex(value)
		logSys.info("Set default regex = %s" % value)
	
	##
	# Get the regular expression which matches the time.
	#
	# @return the regular expression
		
	def getTimeRegex(self):
		return self.dateDetector.getDefaultRegex()
	
	##
	# Set the time pattern.
	#
	# @param value the time pattern
	
	def setTimePattern(self, value):
		self.dateDetector.setDefaultPattern(value)
		logSys.info("Set default pattern = %s" % value)
	
	##
	# Get the time pattern.
	#
	# @return the time pattern
	
	def getTimePattern(self):
		return self.dateDetector.getDefaultPattern()
	
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
				return False
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
					return False
			if a == b:
				return True
		return False
	
	##
	# Open the log file.
	
	def __openLogFile(self, filename):
		""" Opens the log file specified on init.
		"""
		try:
			self.__crtFilename = filename
			self.__crtHandler = open(filename)
			logSys.debug("Opened " + filename)
			return True
		except OSError:
			logSys.error("Unable to open " + filename)
		except IOError:
			logSys.error("Unable to read " + filename +
						 ". Please check permissions")
		return False
	
	##
	# Close the log file.
	
	def __closeLogFile(self):
		self.__crtFilename = None
		self.__crtHandler.close()

	##
	# Set the file position.
	#
	# Sets the file position. We must take care of log file rotation
	# and reset the position to 0 in that case. Use the log message
	# timestamp in order to detect this.
	
	def __setFilePos(self):
		line = self.__crtHandler.readline()
		lastDate = self.__lastDate[self.__crtFilename]
		lineDate = self.dateDetector.getUnixTime(line)
		if lastDate < lineDate:
			logSys.debug("Date " + `lastDate` + " is smaller than " + `lineDate`)
			logSys.debug("Log rotation detected for " + self.__crtFilename)
			self.__lastPos[self.__crtFilename] = 0
		lastPos = self.__lastPos[self.__crtFilename]
		logSys.debug("Setting file position to " + `lastPos` + " for " +
					 self.__crtFilename)
		self.__crtHandler.seek(lastPos)

	##
	# Get the file position.
	
	def __getFilePos(self):
		return self.__crtHandler.tell()

	##
	# Gets all the failure in the log file.
	#
	# Gets all the failure in the log file which are newer than
	# MyTime.time()-self.findTime. When a failure is detected, a FailTicket
	# is created and is added to the FailManager.
	
	def getFailures(self, filename):
		# Try to open log file.
		if not self.__openLogFile(filename):
			logSys.error("Unable to get failures in " + filename)
			return False
		self.__setFilePos()
		lastTimeLine = None
		for line in self.__crtHandler:
			if not self._isActive():
				# The jail has been stopped
				break
			try:
				# Decode line to UTF-8
				line = line.decode('utf-8')
			except UnicodeDecodeError:
				pass
			timeMatch = self.dateDetector.matchTime(line)
			if not timeMatch:
				# There is no valid time in this line
				continue
			# Lets split into time part and log part of the line
			timeLine = timeMatch.group()
			# Lets leave the beginning in as well, so if there is no
			# anchore at the beginning of the time regexp, we don't
			# at least allow injection. Should be harmless otherwise
			logLine  = line[:timeMatch.start()] + line[timeMatch.end():]
			lastTimeLine = timeLine
			for element in self.findFailure(timeLine, logLine):
				ip = element[0]
				unixTime = element[1]
				if unixTime < MyTime.time()-self.__findTime:
					break
				if self.inIgnoreIPList(ip):
					logSys.debug("Ignore "+ip)
					continue
				logSys.debug("Found "+ip)
				self.failManager.addFailure(FailTicket(ip, unixTime))
		self.__lastPos[filename] = self.__getFilePos()
		if lastTimeLine:
			self.__lastDate[filename] = self.dateDetector.getUnixTime(lastTimeLine)
		self.__closeLogFile()
		return True

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


##
# Utils class for DNS and IP handling.
#
# This class contains only static methods used to handle DNS and IP
# addresses.

import socket, struct

class DNSUtils:
	
	DNS_CRE = re.compile("(?:(?:\w|-)+\.){2,}\w+")
	IP_CRE = re.compile("(?:\d{1,3}\.){3}\d{1,3}")
	
	@staticmethod
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
	
	@staticmethod
	def searchIP(text):
		""" Search if an IP address if directly available and return
			it.
		"""
		match = DNSUtils.IP_CRE.match(text)
		if match:
			return match
		else:
			return None
	
	@staticmethod
	def isValidIP(string):
		""" Return true if str is a valid IP
		"""
		s = string.split('/', 1)
		try:
			socket.inet_aton(s[0])
			return True
		except socket.error:
			return False
	
	@staticmethod
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
	
	@staticmethod
	def cidr(i, n):
		""" Convert an IP address string with a CIDR mask into a 32-bit
			integer.
		"""
		# 32-bit IPv4 address mask
		MASK = 0xFFFFFFFFL
		return ~(MASK >> n) & MASK & DNSUtils.addr2bin(i)
	
	@staticmethod
	def addr2bin(string):
		""" Convert a string IPv4 address into an unsigned integer.
		"""
		return struct.unpack("!L", socket.inet_aton(string))[0]
	
	@staticmethod
	def bin2addr(addr):
		""" Convert a numeric IPv4 address into string n.n.n.n form.
		"""
		return socket.inet_ntoa(struct.pack("!L", addr))
