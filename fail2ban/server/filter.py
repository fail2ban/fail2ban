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

__author__ = "Cyril Jaquier"
__version__ = "$Revision$"
__date__ = "$Date$"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

from failmanager import FailManagerEmpty
from failmanager import FailManager
from ticket import FailTicket
from jailthread import JailThread
from datedetector import DateDetector
from datetemplate import DatePatternRegex
from mytime import MyTime
from failregex import FailRegex, Regex, RegexException

import logging, re, os, fcntl, time, sys, locale, codecs

# Gets the instance of the logger.
logSys = logging.getLogger(__name__)

##
# Log reader class.
#
# This class reads a log file and detects login failures or anything else
# that matches a given regular expression. This class is instantiated by
# a Jail object.

class Filter(JailThread):

	##
	# Constructor.
	#
	# Initialize the filter object with default values.
	# @param jail the jail object

	def __init__(self, jail, useDns='warn'):
		JailThread.__init__(self)
		## The jail which contains this filter.
		self.jail = jail
		## The failures manager.
		self.failManager = FailManager()
		## The regular expression list matching the failures.
		self.__failRegex = list()
		## The regular expression list with expressions to ignore.
		self.__ignoreRegex = list()
		## Use DNS setting
		self.setUseDns(useDns)
		## The amount of time to look back.
		self.__findTime = 6000
		## The ignore IP list.
		self.__ignoreIpList = []
		## Size of line buffer
		self.__lineBufferSize = 1
		## Line buffer
		self.__lineBuffer = []
		## Store last time stamp, applicable for multi-line
		self.__lastTimeLine = ""

		self.dateDetector = DateDetector()
		self.dateDetector.addDefaultTemplate()
		logSys.debug("Created %s" % self)


	def __repr__(self):
		return "%s(%r)" % (self.__class__.__name__, self.jail)

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
			raise e


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
	# and thus can be used for many purpose.
	# @param value the regular expression

	def addIgnoreRegex(self, value):
		try:
			regex = Regex(value)
			self.__ignoreRegex.append(regex)
		except RegexException, e:
			logSys.error(e)
			raise e 

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
	# Set the Use DNS mode
	# @param value the usedns mode

	def setUseDns(self, value):
		if isinstance(value, bool):
			value = {True: 'yes', False: 'no'}[value]
		value = value.lower()			  # must be a string by now
		if not (value in ('yes', 'no', 'warn')):
			logSys.error("Incorrect value %r specified for usedns. "
						 "Using safe 'no'" % (value,))
			value = 'no'
		logSys.debug("Setting usedns = %s for %s" % (value, self))
		self.__useDns = value

	##
	# Get the usedns mode
	# @return the usedns mode

	def getUseDns(self):
		return self.__useDns

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
	# Set the date detector pattern, removing Defaults
	#
	# @param pattern the date template pattern

	def setDatePattern(self, pattern):
		dateDetector = DateDetector()
		template = DatePatternRegex()
		if pattern[0] == "^": # Special extra to enable anchor
			template.setPattern(pattern[1:], anchor=True)
		else:
			template.setPattern(pattern, anchor=False)
		dateDetector.appendTemplate(template)
		self.dateDetector = dateDetector
		logSys.info("Date pattern set to `%r`: `%s`" %
			(pattern, template.getName()))
		logSys.debug("Date pattern regex for %r: %s" %
			(pattern, template.getRegex()))

	##
	# Get the date detector pattern, or Default Detectors if not changed
	#
	# @return pattern of the date template pattern

	def getDatePattern(self):
		templates = self.dateDetector.getTemplates()
		if len(templates) > 1:
			return None # Default Detectors in use
		elif len(templates) == 1:
			pattern =  templates[0].getPattern()
			if templates[0].getRegex()[0] == "^":
				pattern = "^" + pattern
			return pattern, templates[0].getName()

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
	# Set the maximum line buffer size.
	#
	# @param value the line buffer size

	def setMaxLines(self, value):
		if int(value) <= 0:
			raise ValueError("maxlines must be integer greater than zero")
		self.__lineBufferSize = int(value)
		logSys.info("Set maxlines = %i" % self.__lineBufferSize)

	##
	# Get the maximum line buffer size.
	#
	# @return the line buffer size

	def getMaxLines(self):
		return self.__lineBufferSize

	##
	# Main loop.
	#
	# This function is the main loop of the thread. It checks if the
	# file has been modified and looks for failures.
	# @return True when the thread exits nicely

	def run(self): # pragma: no cover
		raise Exception("run() is abstract")

	##
	# Ban an IP - http://blogs.buanzo.com.ar/2009/04/fail2ban-patch-ban-ip-address-manually.html
	# Arturo 'Buanzo' Busleiman <buanzo@buanzo.com.ar>
	#
	# to enable banip fail2ban-client BAN command

	def addBannedIP(self, ip):
		unixTime = MyTime.time()
		for i in xrange(self.failManager.getMaxRetry()):
			self.failManager.addFailure(FailTicket(ip, unixTime))

		# Perform the banning of the IP now.
		try: # pragma: no branch - exception is the only way out
			while True:
				ticket = self.failManager.toBan()
				self.jail.putFailTicket(ticket)
		except FailManagerEmpty:
			self.failManager.cleanup(MyTime.time())

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
		"""Split the time portion from log msg and return findFailures on them
		"""
		timeMatch = self.dateDetector.matchTime(line)
		if timeMatch:
			# Lets split into time part and log part of the line
			timeLine = timeMatch.group()
			self.__lastTimeLine = timeLine
			# Lets leave the beginning in as well, so if there is no
			# anchore at the beginning of the time regexp, we don't
			# at least allow injection. Should be harmless otherwise
			logLine  = line[:timeMatch.start()] + line[timeMatch.end():]
		else:
			timeLine = self.__lastTimeLine or line
			logLine = line
		self.__lineBuffer = ((self.__lineBuffer +
				[logLine])[-self.__lineBufferSize:])
		return self.findFailure(timeLine, "".join(self.__lineBuffer))

	def processLineAndAdd(self, line):
		"""Processes the line for failures and populates failManager
		"""
		for element in self.processLine(line):
			ip = element[0]
			unixTime = element[1]
			logSys.debug("Processing line with time:%s and ip:%s"
						 % (unixTime, ip))
			if unixTime < MyTime.time() - self.getFindTime():
				logSys.debug("Ignore line since time %s < %s - %s"
							 % (unixTime, MyTime.time(), self.getFindTime()))
				break
			if self.inIgnoreIPList(ip):
				logSys.debug("Ignore %s" % ip)
				continue
			logSys.debug("Found %s" % ip)
			self.failManager.addFailure(FailTicket(ip, unixTime, [line]))

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
		# Iterates over all the regular expressions.
		for failRegex in self.__failRegex:
			failRegex.search(logLine)
			if failRegex.hasMatched():
				# Checks if we must ignore this match.
				if self.ignoreLine("".join(failRegex.getMatchedLines())):
					# The ignoreregex matched. Remove ignored match.
					self.__lineBuffer = failRegex.getUnmatchedLines()
					continue
				# The failregex matched.
				date = self.dateDetector.getUnixTime(timeLine)
				if date == None:
					logSys.debug("Found a match for %r but no valid date/time "
								 "found for %r. Please try setting a custom "
								 "date pattern. If format is complex, please "
								 "file a detailed issue on"
								 " https://github.com/fail2ban/fail2ban/issues "
								 "in order to get support for this format."
								 % (logLine, timeLine))
				else:
					self.__lineBuffer = failRegex.getUnmatchedLines()
					try:
						host = failRegex.getHost()
						ipMatch = DNSUtils.textToIp(host, self.__useDns)
						if ipMatch:
							for ip in ipMatch:
								failList.append([ip, date])
							# We matched a regex, it is enough to stop.
							break
					except RegexException, e: # pragma: no cover - unsure if reachable
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

	def __init__(self, jail, **kwargs):
		Filter.__init__(self, jail, **kwargs)
		## The log file path.
		self.__logPath = []
		self.setLogEncoding("auto")

	##
	# Add a log file path
	#
	# @param path log file path

	def addLogPath(self, path, tail = False):
		if self.containsLogPath(path):
			logSys.error(path + " already exists")
		else:
			container = FileContainer(path, self.getLogEncoding(), tail)
			self.__logPath.append(container)
			logSys.info("Added logfile = %s" % path)
			self._addLogPath(path)			# backend specific

	def _addLogPath(self, path):
		# nothing to do by default
		# to be overridden by backends
		pass


	##
	# Delete a log path
	#
	# @param path the log file to delete

	def delLogPath(self, path):
		for log in self.__logPath:
			if log.getFileName() == path:
				self.__logPath.remove(log)
				logSys.info("Removed logfile = %s" % path)
				self._delLogPath(path)
				return

	def _delLogPath(self, path):
		# nothing to do by default
		# to be overridden by backends
		pass

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

	##
	# Set the log file encoding
	#
	# @param encoding the encoding used with log files

	def setLogEncoding(self, encoding):
		if encoding.lower() == "auto":
			encoding = locale.getpreferredencoding()
		codecs.lookup(encoding) # Raise LookupError if invalid codec
		for log in self.getLogPath():
			log.setEncoding(encoding)
		self.__encoding = encoding
		logSys.info("Set jail log file encoding to %s" % encoding)

	##
	# Get the log file encoding
	#
	# @return log encoding value

	def getLogEncoding(self):
		return self.__encoding

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
		# see http://python.org/dev/peps/pep-3151/
		except IOError, e:
			logSys.error("Unable to open %s" % filename)
			logSys.exception(e)
			return False
		except OSError, e: # pragma: no cover - requires race condition to tigger this
			logSys.error("Error opening %s" % filename)
			logSys.exception(e)
			return False
		except OSError, e: # pragma: no cover - Requires implemention error in FileContainer to generate
			logSys.error("Internal errror in FileContainer open method - please report as a bug to https://github.com/fail2ban/fail2ban/issues")
			logSys.exception(e)
			return False

		while True:
			line = container.readline()
			if not line or not self._isActive():
				# The jail reached the bottom or has been stopped
				break
			self.processLineAndAdd(line)
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

try:
	import hashlib
	md5sum = hashlib.md5
except ImportError: # pragma: no cover
	# hashlib was introduced in Python 2.5.  For compatibility with those
	# elderly Pythons, import from md5
	import md5
	md5sum = md5.new

class FileContainer:

	def __init__(self, filename, encoding, tail = False):
		self.__filename = filename
		self.setEncoding(encoding)
		self.__tail = tail
		self.__handler = None
		# Try to open the file. Raises an exception if an error occured.
		handler = open(filename, 'rb')
		stats = os.fstat(handler.fileno())
		self.__ino = stats.st_ino
		try:
			firstLine = handler.readline()
			# Computes the MD5 of the first line.
			self.__hash = md5sum(firstLine).digest()
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

	def setEncoding(self, encoding):
		codecs.lookup(encoding) # Raises LookupError if invalid
		self.__encoding = encoding

	def getEncoding(self):
		return self.__encoding

	def open(self):
		self.__handler = open(self.__filename, 'rb')
		# Set the file descriptor to be FD_CLOEXEC
		fd = self.__handler.fileno()
		flags = fcntl.fcntl(fd, fcntl.F_GETFD)
		fcntl.fcntl(fd, fcntl.F_SETFD, flags | fcntl.FD_CLOEXEC)
		firstLine = self.__handler.readline()
		# Computes the MD5 of the first line.
		myHash = md5sum(firstLine).digest()
		stats = os.fstat(self.__handler.fileno())
		# Compare hash and inode
		if self.__hash != myHash or self.__ino != stats.st_ino:
			logSys.debug("Log rotation detected for %s" % self.__filename)
			self.__hash = myHash
			self.__ino = stats.st_ino
			self.__pos = 0
		# Sets the file pointer to the last position.
		self.__handler.seek(self.__pos)

	def readline(self):
		if self.__handler == None:
			return ""
		line = self.__handler.readline()
		try:
			line = line.decode(self.getEncoding(), 'strict')
		except UnicodeDecodeError:
			logSys.warning("Error decoding line from '%s' with '%s': %s" %
				(self.getFileName(), self.getEncoding(), `line`))
			if sys.version_info >= (3,): # In python3, must be decoded
				line = line.decode(self.getEncoding(), 'ignore')
		return line

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
			logSys.warning("Unable to find a corresponding IP address for %s"
						% dns)
			return list()
		except socket.error, e:
			logSys.warning("Socket error raised trying to resolve hostname %s: %s"
						% (dns, e))
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
	def textToIp(text, useDns):
		""" Return the IP of DNS found in a given text.
		"""
		ipList = list()
		# Search for plain IP
		plainIP = DNSUtils.searchIP(text)
		if not plainIP is None:
			plainIPStr = plainIP.group(0)
			if DNSUtils.isValidIP(plainIPStr):
				ipList.append(plainIPStr)

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
