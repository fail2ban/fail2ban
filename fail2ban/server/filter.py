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

import codecs
import fcntl
import locale
import os
import re
import sys

from .failmanager import FailManagerEmpty, FailManager
from .ticket import FailTicket
from .jailthread import JailThread
from .datedetector import DateDetector
from .datetemplate import DatePatternRegex, DateEpoch, DateTai64n
from .mytime import MyTime
from .failregex import FailRegex, Regex, RegexException
from .action import CommandAction
from ..helpers import getLogger

# Gets the instance of the logger.
logSys = getLogger(__name__)

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
		self.__findTime = 600
		## The ignore IP list.
		self.__ignoreIpList = []
		## Size of line buffer
		self.__lineBufferSize = 1
		## Line buffer
		self.__lineBuffer = []
		## Store last time stamp, applicable for multi-line
		self.__lastTimeText = ""
		self.__lastDate = None
		## External command
		self.__ignoreCommand = False

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
			if "\n" in regex.getRegex() and not self.getMaxLines() > 1:
				logSys.warning(
					"Mutliline regex set for jail '%s' "
					"but maxlines not greater than 1")
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
		if pattern is None:
			self.dateDetector = None
			return
		elif pattern.upper() == "EPOCH":
			template = DateEpoch()
			template.name = "Epoch"
		elif pattern.upper() == "TAI64N":
			template = DateTai64n()
			template.name = "TAI64N"
		else:
			template = DatePatternRegex(pattern)
		self.dateDetector = DateDetector()
		self.dateDetector.appendTemplate(template)
		logSys.info("Date pattern set to `%r`: `%s`" %
			(pattern, template.name))
		logSys.debug("Date pattern regex for %r: %s" %
			(pattern, template.regex))

	##
	# Get the date detector pattern, or Default Detectors if not changed
	#
	# @return pattern of the date template pattern

	def getDatePattern(self):
		if self.dateDetector is not None:
			templates = self.dateDetector.templates
			if len(templates) > 1:
				return None, "Default Detectors"
			elif len(templates) == 1:
				if hasattr(templates[0], "pattern"):
					pattern =  templates[0].pattern
				else:
					pattern = None
				return pattern, templates[0].name

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
	# Set external command, for ignoredips
	#

	def setIgnoreCommand(self, command):
		self.__ignoreCommand = command

	##
	# Get external command, for ignoredips
	#

	def getIgnoreCommand(self):
		return self.__ignoreCommand

	##
	# Ban an IP - http://blogs.buanzo.com.ar/2009/04/fail2ban-patch-ban-ip-address-manually.html
	# Arturo 'Buanzo' Busleiman <buanzo@buanzo.com.ar>
	#
	# to enable banip fail2ban-client BAN command

	def addBannedIP(self, ip):
		if self.inIgnoreIPList(ip):
			logSys.warning('Requested to manually ban an ignored IP %s. User knows best. Proceeding to ban it.' % ip)

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

	def logIgnoreIp(self, ip, log_ignore, ignore_source="unknown source"):
		if log_ignore:
			logSys.info("[%s] Ignore %s by %s" % (self.jail.name, ip, ignore_source))

	def getIgnoreIP(self):
		return self.__ignoreIpList

	##
	# Check if IP address/DNS is in the ignore list.
	#
	# Check if the given IP address matches an IP address/DNS or a CIDR
	# mask in the ignore list.
	# @param ip IP address
	# @return True if IP address is in ignore list

	def inIgnoreIPList(self, ip, log_ignore=False):
		for i in self.__ignoreIpList:
			# An empty string is always false
			if i == "":
				continue
			s = i.split('/', 1)
			# IP address without CIDR mask
			if len(s) == 1:
				s.insert(1, '32')
			elif "." in s[1]: # 255.255.255.0 style mask
				s[1] = len(re.search(
					"(?<=b)1+", bin(DNSUtils.addr2bin(s[1]))).group())
			s[1] = long(s[1])
			try:
				a = DNSUtils.addr2bin(s[0], cidr=s[1])
				b = DNSUtils.addr2bin(ip, cidr=s[1])
			except Exception:
				# Check if IP in DNS
				ips = DNSUtils.dnsToIp(i)
				if ip in ips:
					self.logIgnoreIp(ip, log_ignore, ignore_source="dns")
					return True
				else:
					continue
			if a == b:
				self.logIgnoreIp(ip, log_ignore, ignore_source="ip")
				return True

		if self.__ignoreCommand:
			command = CommandAction.replaceTag(self.__ignoreCommand, { 'ip': ip } )
			logSys.debug('ignore command: ' + command)
			ret_ignore = CommandAction.executeCmd(command)
			self.logIgnoreIp(ip, log_ignore and ret_ignore, ignore_source="command")
			return ret_ignore

		return False

	def processLine(self, line, date=None, returnRawHost=False,
		checkAllRegex=False):
		"""Split the time portion from log msg and return findFailures on them
		"""
		if date:
			tupleLine = line
		else:
			l = line.rstrip('\r\n')
			logSys.log(7, "Working on line %r", line)

			timeMatch = self.dateDetector.matchTime(l)
			if timeMatch:
				tupleLine  = (
					l[:timeMatch.start()],
					l[timeMatch.start():timeMatch.end()],
					l[timeMatch.end():])
			else:
				tupleLine = (l, "", "")

		return "".join(tupleLine[::2]), self.findFailure(
			tupleLine, date, returnRawHost, checkAllRegex)

	def processLineAndAdd(self, line, date=None):
		"""Processes the line for failures and populates failManager
		"""
		for element in self.processLine(line, date)[1]:
			ip = element[1]
			unixTime = element[2]
			lines = element[3]
			logSys.debug("Processing line with time:%s and ip:%s"
						 % (unixTime, ip))
			if unixTime < MyTime.time() - self.getFindTime():
				logSys.debug("Ignore line since time %s < %s - %s"
							 % (unixTime, MyTime.time(), self.getFindTime()))
				break
			if self.inIgnoreIPList(ip, log_ignore=True):
				continue
			logSys.info("[%s] Found %s" % (self.jail.name, ip))
			## print "D: Adding a ticket for %s" % ((ip, unixTime, [line]),)
			self.failManager.addFailure(FailTicket(ip, unixTime, lines))

	##
	# Returns true if the line should be ignored.
	#
	# Uses ignoreregex.
	# @param line: the line
	# @return: a boolean

	def ignoreLine(self, tupleLines):
		for ignoreRegexIndex, ignoreRegex in enumerate(self.__ignoreRegex):
			ignoreRegex.search(tupleLines)
			if ignoreRegex.hasMatched():
				return ignoreRegexIndex
		return None

	##
	# Finds the failure in a line given split into time and log parts.
	#
	# Uses the failregex pattern to find it and timeregex in order
	# to find the logging time.
	# @return a dict with IP and timestamp.

	def findFailure(self, tupleLine, date=None, returnRawHost=False,
		checkAllRegex=False):
		failList = list()

		# Checks if we must ignore this line.
		if self.ignoreLine([tupleLine[::2]]) is not None:
			# The ignoreregex matched. Return.
			logSys.log(7, "Matched ignoreregex and was \"%s\" ignored",
				"".join(tupleLine[::2]))
			return failList

		timeText = tupleLine[1]
		if date:
			self.__lastTimeText = timeText
			self.__lastDate = date
		elif timeText:

			dateTimeMatch = self.dateDetector.getTime(timeText)

			if dateTimeMatch is None:
				logSys.error("findFailure failed to parse timeText: " + timeText)
				date = self.__lastDate

			else:
				# Lets get the time part
				date = dateTimeMatch[0]

				self.__lastTimeText = timeText
				self.__lastDate = date
		else:
			timeText = self.__lastTimeText or "".join(tupleLine[::2])
			date = self.__lastDate

		self.__lineBuffer = (
			self.__lineBuffer + [tupleLine])[-self.__lineBufferSize:]
		logSys.log(5, "Looking for failregex match of %r" % self.__lineBuffer)

		# Iterates over all the regular expressions.
		for failRegexIndex, failRegex in enumerate(self.__failRegex):
			failRegex.search(self.__lineBuffer)
			if failRegex.hasMatched():
				# The failregex matched.
				logSys.log(7, "Matched %s", failRegex)
				# Checks if we must ignore this match.
				if self.ignoreLine(failRegex.getMatchedTupleLines()) \
						is not None:
					# The ignoreregex matched. Remove ignored match.
					self.__lineBuffer = failRegex.getUnmatchedTupleLines()
					logSys.log(7, "Matched ignoreregex and was ignored")
					if not checkAllRegex:
						break
					else:
						continue
				if date is None:
					logSys.warning(
						"Found a match for %r but no valid date/time "
						"found for %r. Please try setting a custom "
						"date pattern (see man page jail.conf(5)). "
						"If format is complex, please "
						"file a detailed issue on"
						" https://github.com/fail2ban/fail2ban/issues "
						"in order to get support for this format."
						 % ("\n".join(failRegex.getMatchedLines()), timeText))
				else:
					self.__lineBuffer = failRegex.getUnmatchedTupleLines()
					try:
						host = failRegex.getHost()
						if returnRawHost:
							failList.append([failRegexIndex, host, date,
								 failRegex.getMatchedLines()])
							if not checkAllRegex:
								break
						else:
							ipMatch = DNSUtils.textToIp(host, self.__useDns)
							if ipMatch:
								for ip in ipMatch:
									failList.append([failRegexIndex, ip, date,
										 failRegex.getMatchedLines()])
								if not checkAllRegex:
									break
					except RegexException, e: # pragma: no cover - unsure if reachable
						logSys.error(e)
		return failList

	def status(self, flavor="basic"):
		"""Status of failures detected by filter.
		"""
		ret = [("Currently failed", self.failManager.size()),
		       ("Total failed", self.failManager.getFailTotal())]
		return ret


class FileFilter(Filter):

	def __init__(self, jail, **kwargs):
		Filter.__init__(self, jail, **kwargs)
		## The log file path.
		self.__logs = dict()
		self.setLogEncoding("auto")

	##
	# Add a log file path
	#
	# @param path log file path

	def addLogPath(self, path, tail=False):
		if path in self.__logs:
			logSys.error(path + " already exists")
		else:
			log = FileContainer(path, self.getLogEncoding(), tail)
			db = self.jail.database
			if db is not None:
				lastpos = db.addLog(self.jail, log)
				if lastpos and not tail:
					log.setPos(lastpos)
			self.__logs[path] = log
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
		try:
			log = self.__logs.pop(path)
		except KeyError:
			return
		db = self.jail.database
		if db is not None:
			db.updateLog(self.jail, log)
		logSys.info("Removed logfile = %s" % path)
		self._delLogPath(path)
		return

	def _delLogPath(self, path): # pragma: no cover - overwritten function
		# nothing to do by default
		# to be overridden by backends
		pass

	##
	# Get the log containers
	#
	# @return log containers

	def getLogs(self):
		return self.__logs.values()

	##
	# Check whether path is already monitored.
	#
	# @param path The path
	# @return True if the path is already monitored else False

	def containsLogPath(self, path):
		return path in self.__logs

	##
	# Set the log file encoding
	#
	# @param encoding the encoding used with log files

	def setLogEncoding(self, encoding):
		if encoding.lower() == "auto":
			encoding = locale.getpreferredencoding()
		codecs.lookup(encoding) # Raise LookupError if invalid codec
		for log in self.__logs.itervalues():
			log.setEncoding(encoding)
		self.__encoding = encoding
		logSys.info("Set jail log file encoding to %s" % encoding)

	##
	# Get the log file encoding
	#
	# @return log encoding value

	def getLogEncoding(self):
		return self.__encoding

	def getLog(self, path):
		return self.__logs.get(path, None)

	##
	# Gets all the failure in the log file.
	#
	# Gets all the failure in the log file which are newer than
	# MyTime.time()-self.findTime. When a failure is detected, a FailTicket
	# is created and is added to the FailManager.

	def getFailures(self, filename):
		log = self.getLog(filename)
		if log is None:
			logSys.error("Unable to get failures in " + filename)
			return False
		# Try to open log file.
		try:
			has_content = log.open()
		# see http://python.org/dev/peps/pep-3151/
		except IOError, e:
			logSys.error("Unable to open %s" % filename)
			logSys.exception(e)
			return False
		except OSError, e: # pragma: no cover - requires race condition to tigger this
			logSys.error("Error opening %s" % filename)
			logSys.exception(e)
			return False
		except Exception, e: # pragma: no cover - Requires implemention error in FileContainer to generate
			logSys.error("Internal errror in FileContainer open method - please report as a bug to https://github.com/fail2ban/fail2ban/issues")
			logSys.exception(e)
			return False

		# yoh: has_content is just a bool, so do not expect it to
		# change -- loop is exited upon break, and is not entered at
		# all if upon container opening that one was empty.  If we
		# start reading tested to be empty container -- race condition
		# might occur leading at least to tests failures.
		while has_content:
			line = log.readline()
			if not line or not self.active:
				# The jail reached the bottom or has been stopped
				break
			self.processLineAndAdd(line)
		log.close()
		db = self.jail.database
		if db is not None:
			db.updateLog(self.jail, log)
		return True

	def status(self, flavor="basic"):
		"""Status of Filter plus files being monitored.
		"""
		ret = super(FileFilter, self).status(flavor=flavor)
		path = self.__logs.keys()
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
		# Try to open the file. Raises an exception if an error occurred.
		handler = open(filename, 'rb')
		stats = os.fstat(handler.fileno())
		self.__ino = stats.st_ino
		try:
			firstLine = handler.readline()
			# Computes the MD5 of the first line.
			self.__hash = md5sum(firstLine).hexdigest()
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

	def getHash(self):
		return self.__hash

	def getPos(self):
		return self.__pos

	def setPos(self, value):
		self.__pos = value

	def open(self):
		self.__handler = open(self.__filename, 'rb')
		# Set the file descriptor to be FD_CLOEXEC
		fd = self.__handler.fileno()
		flags = fcntl.fcntl(fd, fcntl.F_GETFD)
		fcntl.fcntl(fd, fcntl.F_SETFD, flags | fcntl.FD_CLOEXEC)
		# Stat the file before even attempting to read it
		stats = os.fstat(self.__handler.fileno())
		if not stats.st_size:
			# yoh: so it is still an empty file -- nothing should be
			#      read from it yet
			# print "D: no content -- return"
			return False
		firstLine = self.__handler.readline()
		# Computes the MD5 of the first line.
		myHash = md5sum(firstLine).hexdigest()
		## print "D: fn=%s hashes=%s/%s inos=%s/%s pos=%s rotate=%s" % (
		## 	self.__filename, self.__hash, myHash, stats.st_ino, self.__ino, self.__pos,
		## 	self.__hash != myHash or self.__ino != stats.st_ino)
		## sys.stdout.flush()
		# Compare hash and inode
		if self.__hash != myHash or self.__ino != stats.st_ino:
			logSys.info("Log rotation detected for %s" % self.__filename)
			self.__hash = myHash
			self.__ino = stats.st_ino
			self.__pos = 0
		# Sets the file pointer to the last position.
		self.__handler.seek(self.__pos)
		return True

	@staticmethod
	def decode_line(filename, enc, line):
		try:
			line = line.decode(enc, 'strict')
		except UnicodeDecodeError:
			logSys.warning(
				"Error decoding line from '%s' with '%s'."
				" Consider setting logencoding=utf-8 (or another appropriate"
				" encoding) for this jail. Continuing"
				" to process line ignoring invalid characters: %r" %
				(filename, enc, line))
			# decode with replacing error chars:
			line = line.decode(enc, 'replace')
		return line

	def readline(self):
		if self.__handler is None:
			return ""
		return FileContainer.decode_line(
			self.getFileName(), self.getEncoding(), self.__handler.readline())

	def close(self):
		if not self.__handler is None:
			# Saves the last position.
			self.__pos = self.__handler.tell()
			# Closes the file.
			self.__handler.close()
			self.__handler = None
		## print "D: Closed %s with pos %d" % (handler, self.__pos)
		## sys.stdout.flush()


##
# JournalFilter class.
#
# Base interface class for systemd journal filters

class JournalFilter(Filter): # pragma: systemd no cover

	def addJournalMatch(self, match): # pragma: no cover - Base class, not used
		pass

	def delJournalMatch(self, match): # pragma: no cover - Base class, not used
		pass

	def getJournalMatch(self, match): # pragma: no cover - Base class, not used
		return []

##
# Utils class for DNS and IP handling.
#
# This class contains only static methods used to handle DNS and IP
# addresses.

import socket
import struct


class DNSUtils:

	IP_CRE = re.compile("^(?:\d{1,3}\.){3}\d{1,3}$")

	@staticmethod
	def dnsToIp(dns):
		""" Convert a DNS into an IP address using the Python socket module.
			Thanks to Kevin Drapel.
		"""
		# retrieve ip (todo: use AF_INET6 for IPv6)
		try:
			return set([i[4][0] for i in socket.getaddrinfo(dns, None, socket.AF_INET, 0, socket.IPPROTO_TCP)])
		except socket.error, e:
			logSys.warning("Unable to find a corresponding IP address for %s: %s"
						% (dns, e))
			return list()
		except socket.error, e:
			logSys.warning("Socket error raised trying to resolve hostname %s: %s"
						% (dns, e))
			return list()

	@staticmethod
	def ipToName(ip):
		try:
			return socket.gethostbyaddr(ip)[0]
		except socket.error, e:
			logSys.debug("Unable to find a name for the IP %s: %s" % (ip, e))
			return None

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

	@staticmethod
	def addr2bin(ipstring, cidr=None):
		""" Convert a string IPv4 address into binary form.
		If cidr is supplied, return the network address for the given block
		"""
		if cidr is None:
			return struct.unpack("!L", socket.inet_aton(ipstring))[0]
		else:
			MASK = 0xFFFFFFFFL
			return ~(MASK >> cidr) & MASK & DNSUtils.addr2bin(ipstring)

	@staticmethod
	def bin2addr(ipbin):
		""" Convert a binary IPv4 address into string n.n.n.n form.
		"""
		return socket.inet_ntoa(struct.pack("!L", ipbin))
