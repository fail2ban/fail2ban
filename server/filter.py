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

import time, logging, re

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
		JailThread.__init__(self, jail)
		## The jail which contains this filter.
		self.jail = jail
		## The failures manager.
		self.failManager = FailManager()
		self.modified = False
		## The log file handler.
		self.__crtHandler = None
		self.__crtFilename = None
		## The log file path.
		self.__logPath = []
		## The regular expression matching the failure.
		self.__failRegex = ''
		self.__failRegexObj = None
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
	# Set the regular expression which matches the failure.
	#
	# The regular expression can also match any other pattern than failures
	# and thus can be used for many purporse.
	# @param value the regular expression
	
	def setFailRegex(self, value):
		self.__failRegex = value
		self.__failRegexObj = re.compile(value)
		logSys.info("Set failregex = %s" % value)
	
	##
	# Get the regular expression which matches the failure.
	#
	# @return the regular expression
	
	def getFailRegex(self):
		return self.__failRegex
	
	##
	# Set the time needed to find a failure.
	#
	# This value tells the filter how long it has to take failures into
	# account.
	# @param value the time
	
	def setFindTime(self, value):
		self.__findTime = value
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
	# Set the maximum time a failure stays in the list.
	#
	# @param value the maximum time
	
	def setMaxTime(self, value):
		self.failManager.setMaxTime(value)
		logSys.info("Set maxTime = %s" % value)
	
	##
	# Get the maximum time a failure stays in the list.
	#
	# @return the time value
	
	def getMaxTime(self):
		return self.failManager.getMaxTime()

	##
	# Main loop.
	#
	# This function is the main loop of the thread. It checks if the
	# file has been modified and looks for failures.
	# @return True when the thread exits nicely

	def run(self):
		raise Exception("run() is abstract")
	
	##
	# Add an IP to the ignore list.
	#
	# IP addresses in the ignore list are not taken into account
	# when finding failures. CIDR mask are also accepted.
	# @param ip IP address to ignore
	
	def addIgnoreIP(self, ip):
		if DNSUtils.isValidIP(ip):
			logSys.debug("Add " + ip + " to ignore list")
			self.__ignoreIpList.append(ip)
		else:
			logSys.warn(ip + " is not a valid address")
		
	def delIgnoreIP(self, ip):
		logSys.debug("Remove " + ip + " from ignore list")
		self.__ignoreIpList.remove(ip)
		
	def getIgnoreIP(self):
		return self.__ignoreIpList
	
	##
	# Check if IP address is in the ignore list.
	#
	# Check if the given IP address matches an IP address or a CIDR
	# mask in the ignore list.
	# @param ip IP address
	# @return True if IP address is in ignore list
	
	def inIgnoreIPList(self, ip):
		for i in self.__ignoreIpList:
			s = i.split('/', 1)
			# IP address without CIDR mask
			if len(s) == 1:
				s.insert(1, '32')
			s[1] = long(s[1])
			try:
				a = DNSUtils.cidr(s[0], s[1])
				b = DNSUtils.cidr(ip, s[1])
			except Exception:
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
	# time.time()-self.findTime. When a failure is detected, a FailTicket
	# is created and is added to the FailManager.
	
	def getFailures(self, filename):
		ipList = dict()
		ret = self.__openLogFile(filename)
		if not ret:
			logSys.error("Unable to get failures in " + filename)
			return False
		self.__setFilePos()
		lastLine = None
		for line in self.__crtHandler:
			try:
				# Try to convert UTF-8 string to Latin-1
				#line = line.decode('utf-8').encode('latin-1')
				line = line.decode('utf-8')
			except UnicodeDecodeError:
				pass
			#except UnicodeEncodeError:
			#	logSys.warn("Mmhh... Are you sure you watch the correct file?")
			if not self.dateDetector.matchTime(line):
				# There is no valid time in this line
				continue
			lastLine = line
			for element in self.findFailure(line):
				ip = element[0]
				unixTime = element[1]
				if unixTime < time.time()-self.__findTime:
					break
				if self.inIgnoreIPList(ip):
					logSys.debug("Ignore "+ip)
					continue
				logSys.debug("Found "+ip)
				self.failManager.addFailure(FailTicket(ip, unixTime))
		self.__lastPos[filename] = self.__getFilePos()
		if lastLine:
			self.__lastDate[filename] = self.dateDetector.getUnixTime(lastLine)
		self.__closeLogFile()
		return True

	##
	# Finds the failure in a line.
	#
	# Uses the failregex pattern to find it and timeregex in order
	# to find the logging time.
	# @return a dict with IP and timestamp.

	def findFailure(self, line):
		failList = list()
		match = self.__failRegexObj.search(line)
		if match:
			date = self.dateDetector.getUnixTime(match.string)
			if date <> None:
				try:
					ipMatch = DNSUtils.textToIp(match.group("host"))
					if ipMatch:
						for ip in ipMatch:
							failList.append([ip, date])
				except IndexError:
					logSys.error("There is no 'host' group in the rule. " +
								 "Please correct your configuration.")
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
	
	dnsCRE = re.compile("(?:(?:\w|-)+\.){2,}\w+")
	ipCRE = re.compile("(?:\d{1,3}\.){3}\d{1,3}")
	
	@staticmethod
	def dnsToIp(dns):
		""" Convert a DNS into an IP address using the Python socket module.
			Thanks to Kevin Drapel.
		"""
		try:
			return socket.gethostbyname_ex(dns)[2]
		except socket.gaierror:
			return list()
	
	@staticmethod
	def textToDns(text):
		""" Search for possible DNS in an arbitrary text.
			Thanks to Tom Pike.
		"""
		match = DNSUtils.dnsCRE.match(text)
		if match:
			return match
		else:
			return None
	
	@staticmethod
	def searchIP(text):
		""" Search if an IP address if directly available and return
			it.
		"""
		match = DNSUtils.ipCRE.match(text)
		if match:
			return match
		else:
			return None
	
	@staticmethod
	def isValidIP(str):
		""" Return true if str is a valid IP
		"""
		s = str.split('/', 1)
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
			dns = DNSUtils.textToDns(text)
			if not dns == None:
				ip = DNSUtils.dnsToIp(dns.group(0))
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
	def addr2bin(str):
		""" Convert a string IPv4 address into an unsigned integer.
		"""
		return struct.unpack("!L", socket.inet_aton(str))[0]
	
	@staticmethod
	def bin2addr(addr):
		""" Convert a numeric IPv4 address into string n.n.n.n form.
		"""
		return socket.inet_ntoa(struct.pack("!L", addr))
