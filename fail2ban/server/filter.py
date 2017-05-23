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
import datetime
import fcntl
import logging
import os
import re
import sys
import time

from .failmanager import FailManagerEmpty, FailManager
from .ipdns import DNSUtils, IPAddr
from .ticket import FailTicket
from .jailthread import JailThread
from .datedetector import DateDetector
from .mytime import MyTime
from .failregex import FailRegex, Regex, RegexException
from .action import CommandAction
from .utils import Utils
from ..helpers import getLogger, PREFER_ENC
from .strptime import validateTimeZone

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
		## Regular expression pre-filtering matching the failures.
		self.__prefRegex = None
		## The regular expression list matching the failures.
		self.__failRegex = list()
		## The regular expression list with expressions to ignore.
		self.__ignoreRegex = list()
		## Use DNS setting
		self.setUseDns(useDns)
		## The amount of time to look back.
		self.__findTime = 600
		## Ignore own IPs flag:
		self.__ignoreSelf = True
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
		## Default or preferred encoding (to decode bytes from file or journal):
		self.__encoding = PREFER_ENC
		## Cache temporary holds failures info (used by multi-line for wrapping e. g. conn-id to host):
		self.__mlfidCache = None
		## Error counter (protected, so can be used in filter implementations)
		## if it reached 100 (at once), run-cycle will go idle
		self._errors = 0
		## return raw host (host is not dns):
		self.returnRawHost = False
		## check each regex (used for test purposes):
		self.checkAllRegex = False
		## if true ignores obsolete failures (failure time < now - findTime):
		self.checkFindTime = True
		## if set, treat log lines without explicit time zone to be in this time zone
		self.logtimezone = None
		## Ticks counter
		self.ticks = 0

		self.dateDetector = DateDetector()
		logSys.debug("Created %s", self)

	def __repr__(self):
		return "%s(%r)" % (self.__class__.__name__, self.jail)

	@property
	def jailName(self):
		return (self.jail is not None and self.jail.name or "~jailless~")

	def clearAllParams(self):
		""" Clear all lists/dicts parameters (used by reloading)
		"""
		self.delFailRegex()
		self.delIgnoreRegex()
		self.delIgnoreIP()

	def reload(self, begin=True):
		""" Begin or end of reloading resp. refreshing of all parameters
		"""
		if begin:
			self.clearAllParams()
			if hasattr(self, 'getLogPaths'):
				self._reload_logs = dict((k, 1) for k in self.getLogPaths())
		else:
			if hasattr(self, '_reload_logs'):
				# if it was not reloaded - remove obsolete log file:
				for path in self._reload_logs:
					self.delLogPath(path)
				delattr(self, '_reload_logs')

	@property
	def mlfidCache(self):
		if self.__mlfidCache:
			return self.__mlfidCache
		self.__mlfidCache = Utils.Cache(maxCount=100, maxTime=5*60)
		return self.__mlfidCache

	@property
	def prefRegex(self):
		return self.__prefRegex
	@prefRegex.setter
	def prefRegex(self, value):
		if value:
			self.__prefRegex = Regex(value, useDns=self.__useDns)
		else:
			self.__prefRegex = None

	##
	# Add a regular expression which matches the failure.
	#
	# The regular expression can also match any other pattern than failures
	# and thus can be used for many purporse.
	# @param value the regular expression

	def addFailRegex(self, value):
		multiLine = self.getMaxLines() > 1
		try:
			regex = FailRegex(value, prefRegex=self.__prefRegex, multiline=multiLine,
				useDns=self.__useDns)
			self.__failRegex.append(regex)
		except RegexException as e:
			logSys.error(e)
			raise e

	def delFailRegex(self, index=None):
		try:
			# clear all:
			if index is None:
				del self.__failRegex[:]
				return
			# delete by index:
			del self.__failRegex[index]
		except IndexError:
			logSys.error("Cannot remove regular expression. Index %d is not "
						 "valid", index)

	##
	# Get the regular expressions as list.
	#
	# @return the regular expression list

	def getFailRegex(self):
		return [regex.getRegex() for regex in self.__failRegex]

	##
	# Add the regular expression which matches the failure.
	#
	# The regular expression can also match any other pattern than failures
	# and thus can be used for many purpose.
	# @param value the regular expression

	def addIgnoreRegex(self, value):
		try:
			regex = Regex(value, useDns=self.__useDns)
			self.__ignoreRegex.append(regex)
		except RegexException as e:
			logSys.error(e)
			raise e 

	def delIgnoreRegex(self, index=None):
		try:
			# clear all:
			if index is None:
				del self.__ignoreRegex[:]
				return
			# delete by index:
			del self.__ignoreRegex[index]
		except IndexError:
			logSys.error("Cannot remove regular expression. Index %d is not "
						 "valid", index)

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
		if not (value in ('yes', 'warn', 'no', 'raw')):
			logSys.error("Incorrect value %r specified for usedns. "
						 "Using safe 'no'", value)
			value = 'no'
		logSys.debug("Setting usedns = %s for %s", value, self)
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
		value = MyTime.str2seconds(value)
		self.__findTime = value
		self.failManager.setMaxTime(value)
		logSys.info("  findtime: %s", value)

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
		else:
			dd = DateDetector()
			if not isinstance(pattern, (list, tuple)):
				pattern = filter(bool, map(str.strip, re.split('\n+', pattern)))
			for pattern in pattern:
				dd.appendTemplate(pattern)
			self.dateDetector = dd

	##
	# Get the date detector pattern, or Default Detectors if not changed
	#
	# @return pattern of the date template pattern

	def getDatePattern(self):
		if self.dateDetector is not None:
			templates = self.dateDetector.templates
			# lazy template init, by first match
			if not len(templates) or len(templates) > 2:
				return None, "Default Detectors"
			elif len(templates):
				if hasattr(templates[0], "pattern"):
					pattern =  templates[0].pattern
				else:
					pattern = None
				return pattern, templates[0].name
		return None

	##
	# Set the log default time zone
	#
	# @param tz the symbolic timezone (for now fixed offset only: UTC[+-]HHMM)

	def setLogTimeZone(self, tz):
		self.logtimezone = validateTimeZone(tz)

	##
	# Get the log default timezone
	#
	# @return symbolic timezone (a string)

	def getLogTimeZone(self):
		return self.logtimezone

	##
	# Set the maximum retry value.
	#
	# @param value the retry value

	def setMaxRetry(self, value):
		self.failManager.setMaxRetry(value)
		logSys.info("  maxRetry: %s", value)

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
		logSys.info("  maxLines: %i", self.__lineBufferSize)

	##
	# Get the maximum line buffer size.
	#
	# @return the line buffer size

	def getMaxLines(self):
		return self.__lineBufferSize

	##
	# Set the log file encoding
	#
	# @param encoding the encoding used with log files

	def setLogEncoding(self, encoding):
		if encoding.lower() == "auto":
			encoding = PREFER_ENC
		codecs.lookup(encoding) # Raise LookupError if invalid codec
		self.__encoding = encoding
		logSys.info("  encoding: %s", encoding)
		return encoding

	##
	# Get the log file encoding
	#
	# @return log encoding value

	def getLogEncoding(self):
		return self.__encoding

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
		if not isinstance(ip, IPAddr):
			ip = IPAddr(ip)
		if self.inIgnoreIPList(ip):
			logSys.warning('Requested to manually ban an ignored IP %s. User knows best. Proceeding to ban it.', ip)

		unixTime = MyTime.time()
		self.failManager.addFailure(FailTicket(ip, unixTime), self.failManager.getMaxRetry())

		# Perform the banning of the IP now.
		try: # pragma: no branch - exception is the only way out
			while True:
				ticket = self.failManager.toBan(ip)
				self.jail.putFailTicket(ticket)
		except FailManagerEmpty:
			self.failManager.cleanup(MyTime.time())

		return ip

	##
	# Ignore own IP/DNS.
	#
	@property
	def ignoreSelf(self):
		return self.__ignoreSelf

	@ignoreSelf.setter
	def ignoreSelf(self, value):
		self.__ignoreSelf = value

	##
	# Add an IP/DNS to the ignore list.
	#
	# IP addresses in the ignore list are not taken into account
	# when finding failures. CIDR mask and DNS are also accepted.
	# @param ip IP address to ignore

	def addIgnoreIP(self, ipstr):
		# An empty string is always false
		if ipstr == "":
			return
		# Create IP address object
		ip = IPAddr(ipstr)

		# log and append to ignore list
		logSys.debug("  Add %r to ignore list (%r)", ip, ipstr)
		self.__ignoreIpList.append(ip)

	def delIgnoreIP(self, ip=None):
		# clear all:
		if ip is None:
			del self.__ignoreIpList[:]
			return
		# delete by ip:
		logSys.debug("  Remove %r from ignore list", ip)
		self.__ignoreIpList.remove(ip)

	def logIgnoreIp(self, ip, log_ignore, ignore_source="unknown source"):
		if log_ignore:
			logSys.info("[%s] Ignore %s by %s", self.jailName, ip, ignore_source)

	def getIgnoreIP(self):
		return self.__ignoreIpList

	##
	# Check if IP address/DNS is in the ignore list.
	#
	# Check if the given IP address matches an IP address/DNS or a CIDR
	# mask in the ignore list.
	# @param ip IP address object
	# @return True if IP address is in ignore list

	def inIgnoreIPList(self, ip, log_ignore=False):
		if not isinstance(ip, IPAddr):
			ip = IPAddr(ip)

		# check own IPs should be ignored and 'ip' is self IP:
		if self.__ignoreSelf and ip in DNSUtils.getSelfIPs():
			return True

		for net in self.__ignoreIpList:
			# check if the IP is covered by ignore IP
			if ip.isInNet(net):
				self.logIgnoreIp(ip, log_ignore, ignore_source=("ip" if net.isValid else "dns"))
				return True

		if self.__ignoreCommand:
			command = CommandAction.replaceTag(self.__ignoreCommand, { 'ip': ip } )
			logSys.debug('ignore command: %s', command)
			ret, ret_ignore = CommandAction.executeCmd(command, success_codes=(0, 1))
			ret_ignore = ret and ret_ignore == 0
			self.logIgnoreIp(ip, log_ignore and ret_ignore, ignore_source="command")
			return ret_ignore

		return False

	def processLine(self, line, date=None):
		"""Split the time portion from log msg and return findFailures on them
		"""
		if date:
			tupleLine = line
		else:
			l = line.rstrip('\r\n')
			logSys.log(7, "Working on line %r", line)

			(timeMatch, template) = self.dateDetector.matchTime(l)
			if timeMatch:
				tupleLine  = (
					l[:timeMatch.start(1)],
					l[timeMatch.start(1):timeMatch.end(1)],
					l[timeMatch.end(1):],
					(timeMatch, template)
				)
			else:
				tupleLine = (l, "", "", None)

		# save last line (lazy convert of process line tuple to string on demand):
		self.processedLine = lambda: "".join(tupleLine[::2])
		return self.findFailure(tupleLine, date)

	def processLineAndAdd(self, line, date=None):
		"""Processes the line for failures and populates failManager
		"""
		try:
			for element in self.processLine(line, date):
				ip = element[1]
				unixTime = element[2]
				fail = element[3]
				logSys.debug("Processing line with time:%s and ip:%s", 
						unixTime, ip)
				if self.inIgnoreIPList(ip, log_ignore=True):
					continue
				logSys.info(
					"[%s] Found %s - %s", self.jailName, ip, datetime.datetime.fromtimestamp(unixTime).strftime("%Y-%m-%d %H:%M:%S")
				)
				tick = FailTicket(ip, unixTime, data=fail)
				self.failManager.addFailure(tick)
			# reset (halve) error counter (successfully processed line):
			if self._errors:
				self._errors //= 2
		except Exception as e:
			logSys.error("Failed to process line: %r, caught exception: %r", line, e,
				exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)
			# incr common error counter:
			self.commonError()

	def commonError(self):
		# incr error counter, stop processing (going idle) after 100th error :
		self._errors += 1
		# sleep a little bit (to get around time-related errors):
		time.sleep(self.sleeptime)
		if self._errors >= 100:
			logSys.error("Too many errors at once (%s), going idle", self._errors)
			self._errors //= 2
			self.idle = True

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

	def _mergeFailure(self, mlfid, fail, failRegex):
		mlfidFail = self.mlfidCache.get(mlfid) if self.__mlfidCache else None
		# if multi-line failure id (connection id) known:
		if mlfidFail:
			mlfidGroups = mlfidFail[1]
			# update - if not forget (disconnect/reset):
			if not fail.get('mlfforget'):
				mlfidGroups.update(fail)
			else:
				self.mlfidCache.unset(mlfid) # remove cached entry
			# merge with previous info:
			fail2 = mlfidGroups.copy()
			fail2.update(fail)
			if not fail.get('nofail'): # be sure we've correct current state
				try:
					del fail2['nofail']
				except KeyError:
					pass
			fail2["matches"] = fail.get("matches", []) + failRegex.getMatchedTupleLines()
			fail = fail2
		elif not fail.get('mlfforget'):
			mlfidFail = [self.__lastDate, fail]
			self.mlfidCache.set(mlfid, mlfidFail)
			if fail.get('nofail'):
				fail["matches"] = failRegex.getMatchedTupleLines()
		return fail


	##
	# Finds the failure in a line given split into time and log parts.
	#
	# Uses the failregex pattern to find it and timeregex in order
	# to find the logging time.
	# @return a dict with IP and timestamp.

	def findFailure(self, tupleLine, date=None):
		failList = list()

		returnRawHost = self.returnRawHost
		cidr = IPAddr.CIDR_UNSPEC
		if self.__useDns == "raw":
			returnRawHost = True
			cidr = IPAddr.CIDR_RAW

		# Checks if we mut ignore this line.
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

			dateTimeMatch = self.dateDetector.getTime(timeText, tupleLine[3],
								  default_tz=self.logtimezone)

			if dateTimeMatch is None:
				logSys.error("findFailure failed to parse timeText: %s", timeText)
				date = self.__lastDate

			else:
				# Lets get the time part
				date = dateTimeMatch[0]

				self.__lastTimeText = timeText
				self.__lastDate = date
		else:
			timeText = self.__lastTimeText or "".join(tupleLine[::2])
			date = self.__lastDate

		if self.checkFindTime and date is not None and date < MyTime.time() - self.getFindTime():
			logSys.log(5, "Ignore line since time %s < %s - %s", 
				date, MyTime.time(), self.getFindTime())
			return failList

		if self.__lineBufferSize > 1:
			orgBuffer = self.__lineBuffer = (
				self.__lineBuffer + [tupleLine[:3]])[-self.__lineBufferSize:]
		else:
			orgBuffer = self.__lineBuffer = [tupleLine[:3]]
		logSys.log(5, "Looking for failregex match of %r", self.__lineBuffer)

		# Pre-filter fail regex (if available):
		preGroups = {}
		if self.__prefRegex:
			self.__prefRegex.search(self.__lineBuffer)
			if not self.__prefRegex.hasMatched():
				return failList
			preGroups = self.__prefRegex.getGroups()
			logSys.log(7, "Pre-filter matched %s", preGroups)
			repl = preGroups.get('content')
			# Content replacement:
			if repl:
				del preGroups['content']
				self.__lineBuffer = [('', '', repl)]

		# Iterates over all the regular expressions.
		for failRegexIndex, failRegex in enumerate(self.__failRegex):
			failRegex.search(self.__lineBuffer, orgBuffer)
			if not failRegex.hasMatched():
				continue
			# The failregex matched.
			logSys.log(7, "Matched %s", failRegex)
			# Checks if we must ignore this match.
			if self.ignoreLine(failRegex.getMatchedTupleLines()) \
					is not None:
				# The ignoreregex matched. Remove ignored match.
				self.__lineBuffer = failRegex.getUnmatchedTupleLines()
				logSys.log(7, "Matched ignoreregex and was ignored")
				if not self.checkAllRegex:
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
					"in order to get support for this format.",
					 "\n".join(failRegex.getMatchedLines()), timeText)
				continue
			self.__lineBuffer = failRegex.getUnmatchedTupleLines()
			# retrieve failure-id, host, etc from failure match:
			try:
				raw = returnRawHost
				if preGroups:
					fail = preGroups.copy()
					fail.update(failRegex.getGroups())
				else:
					fail = failRegex.getGroups()
				# first try to check we have mlfid case (caching of connection id by multi-line):
				mlfid = fail.get('mlfid')
				if mlfid is not None:
					fail = self._mergeFailure(mlfid, fail, failRegex)
					# bypass if no-failure case:
					if fail.get('nofail'):
						logSys.log(7, "Nofail by mlfid %r in regex %s: %s",
							mlfid, failRegexIndex, fail.get('mlfforget', "waiting for failure"))
						if not self.checkAllRegex: return failList
				else:
					# matched lines:
					fail["matches"] = fail.get("matches", []) + failRegex.getMatchedTupleLines()
				# failure-id:
				fid = fail.get('fid')
				# ip-address or host:
				host = fail.get('ip4')
				if host is not None:
					cidr = IPAddr.FAM_IPv4
					raw = True
				else:
					host = fail.get('ip6')
					if host is not None:
						cidr = IPAddr.FAM_IPv6
						raw = True
				if host is None:
					host = fail.get('dns')
					if host is None:
						# first try to check we have mlfid case (cache connection id):
						if fid is None and mlfid is None:
								# if no failure-id also (obscure case, wrong regex), throw error inside getFailID:
								fid = failRegex.getFailID()
						host = fid
						cidr = IPAddr.CIDR_RAW
				# if mlfid case (not failure):
				if host is None:
					logSys.log(7, "No failure-id by mlfid %r in regex %s: %s",
						mlfid, failRegexIndex, fail.get('mlfforget', "waiting for identifier"))
					if not self.checkAllRegex: return failList
					ips = [None]
				# if raw - add single ip or failure-id,
				# otherwise expand host to multiple ips using dns (or ignore it if not valid):
				elif raw:
					ip = IPAddr(host, cidr)
					# check host equal failure-id, if not - failure with complex id:
					if fid is not None and fid != host:
						ip = IPAddr(fid, IPAddr.CIDR_RAW)
					ips = [ip]
				# otherwise, try to use dns conversion:
				else:
					ips = DNSUtils.textToIp(host, self.__useDns)
				# append failure with match to the list:
				for ip in ips:
					failList.append([failRegexIndex, ip, date, fail])
				if not self.checkAllRegex:
					break
			except RegexException as e: # pragma: no cover - unsure if reachable
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
		self.__autoSeek = dict()

	##
	# Add a log file path
	#
	# @param path log file path

	def addLogPath(self, path, tail=False, autoSeek=True):
		if path in self.__logs:
			if hasattr(self, '_reload_logs') and path in self._reload_logs:
				del self._reload_logs[path]
			else:
				logSys.error(path + " already exists")
		else:
			log = FileContainer(path, self.getLogEncoding(), tail)
			db = self.jail.database
			if db is not None:
				lastpos = db.addLog(self.jail, log)
				if lastpos and not tail:
					log.setPos(lastpos)
			self.__logs[path] = log
			logSys.info("Added logfile: %r (pos = %s, hash = %s)" , path, log.getPos(), log.getHash())
			if autoSeek:
				# if default, seek to "current time" - "find time":
				if isinstance(autoSeek, bool):
					autoSeek = MyTime.time() - self.getFindTime()
				self.__autoSeek[path] = autoSeek
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
		logSys.info("Removed logfile: %r", path)
		self._delLogPath(path)
		return

	def _delLogPath(self, path): # pragma: no cover - overwritten function
		# nothing to do by default
		# to be overridden by backends
		pass

	##
	# Get the log file names
	#
	# @return log paths

	def getLogPaths(self):
		return self.__logs.keys()

	##
	# Get the log containers
	#
	# @return log containers

	def getLogs(self):
		return self.__logs.values()

	##
	# Get the count of log containers
	#
	# @return count of log containers

	def getLogCount(self):
		return len(self.__logs)

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
		encoding = super(FileFilter, self).setLogEncoding(encoding)
		for log in self.__logs.itervalues():
			log.setEncoding(encoding)

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
			logSys.error("Unable to get failures in %s", filename)
			return False
		# We should always close log (file), otherwise may be locked (log-rotate, etc.)
		try:
			# Try to open log file.
			try:
				has_content = log.open()
			# see http://python.org/dev/peps/pep-3151/
			except IOError as e:
				logSys.error("Unable to open %s", filename)
				if e.errno != 2: # errno.ENOENT
					logSys.exception(e)
				return False
			except OSError as e: # pragma: no cover - requires race condition to tigger this
				logSys.error("Error opening %s", filename)
				logSys.exception(e)
				return False
			except Exception as e: # pragma: no cover - Requires implemention error in FileContainer to generate
				logSys.error("Internal error in FileContainer open method - please report as a bug to https://github.com/fail2ban/fail2ban/issues")
				logSys.exception(e)
				return False

			# seek to find time for first usage only (prevent performance decline with polling of big files)
			if self.__autoSeek.get(filename):
				startTime = self.__autoSeek[filename]
				del self.__autoSeek[filename]
				# prevent completely read of big files first time (after start of service), 
				# initial seek to start time using half-interval search algorithm:
				try:
					self.seekToTime(log, startTime)
				except Exception as e: # pragma: no cover
					logSys.error("Error during seek to start time in \"%s\"", filename)
					raise
					logSys.exception(e)
					return False

			if has_content:
				while not self.idle:
					line = log.readline()
					if not line or not self.active:
						# The jail reached the bottom or has been stopped
						break
					self.processLineAndAdd(line)
		finally:
			log.close()
		db = self.jail.database
		if db is not None:
			db.updateLog(self.jail, log)
		return True

	##
	# Seeks to line with date (search using half-interval search algorithm), to start polling from it
	#

	def seekToTime(self, container, date, accuracy=3):
		fs = container.getFileSize()
		if logSys.getEffectiveLevel() <= logging.DEBUG:
			logSys.debug("Seek to find time %s (%s), file size %s", date, 
				datetime.datetime.fromtimestamp(date).strftime("%Y-%m-%d %H:%M:%S"), fs)
		minp = container.getPos()
		maxp = fs
		tryPos = minp
		lastPos = -1
		foundPos = 0
		foundTime = None
		cntr = 0
		unixTime = None
		movecntr = accuracy
		while maxp > minp:
			if tryPos is None:
				pos = int(minp + (maxp - minp) / 2)
			else:
				pos, tryPos = tryPos, None
			# because container seek will go to start of next line (minus CRLF):
			pos = max(0, pos-2)
			seekpos = pos = container.seek(pos)
			cntr += 1
			# within next 5 lines try to find any legal datetime:
			lncntr = 5;
			dateTimeMatch = None
			nextp = None
			while True:
				line = container.readline()
				if not line:
					break
				(timeMatch, template) = self.dateDetector.matchTime(line)
				if timeMatch:
					dateTimeMatch = self.dateDetector.getTime(
						line[timeMatch.start():timeMatch.end()],
						(timeMatch, template),
						default_tz=self.logtimezone)
				else:
					nextp = container.tell()
					if nextp > maxp:
						pos = seekpos
						break
					pos = nextp
				if not dateTimeMatch and lncntr:
					lncntr -= 1
					continue
				break
		 	# not found at this step - stop searching
			if dateTimeMatch:
				unixTime = dateTimeMatch[0]
				if unixTime >= date:
					if foundTime is None or unixTime <= foundTime:
						foundPos = pos
						foundTime = unixTime
					if pos == maxp:
						pos = seekpos
					if pos < maxp:
						maxp = pos
				else:
					if foundTime is None or unixTime >= foundTime:
						foundPos = pos
						foundTime = unixTime
					if nextp is None:
						nextp = container.tell()
					pos = nextp
					if pos > minp:
						minp = pos
			# if we can't move (position not changed)
			if pos == lastPos:
				movecntr -= 1
				if movecntr <= 0:
		 			break
				# we have found large area without any date mached 
				# or end of search - try min position (because can be end of previous line):
				if minp != lastPos:
					lastPos = tryPos = minp
					continue
				break
			lastPos = pos
		# always use smallest pos, that could be found:
		foundPos = container.seek(minp, False)
		container.setPos(foundPos)
		if logSys.getEffectiveLevel() <= logging.DEBUG:
			logSys.debug("Position %s from %s, found time %s (%s) within %s seeks", lastPos, fs, foundTime, 
				(datetime.datetime.fromtimestamp(foundTime).strftime("%Y-%m-%d %H:%M:%S") if foundTime is not None else ''), cntr)
		
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
	try:
		md5sum = hashlib.md5
		# try to use it (several standards like FIPS forbid it):
		md5sum(' ').hexdigest()
	except: # pragma: no cover
		md5sum = hashlib.sha1
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

	def getFileSize(self):
		return os.path.getsize(self.__filename);

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
			logSys.log(logging.MSG, "Log rotation detected for %s", self.__filename)
			self.__hash = myHash
			self.__ino = stats.st_ino
			self.__pos = 0
		# Sets the file pointer to the last position.
		self.__handler.seek(self.__pos)
		return True

	def seek(self, offs, endLine=True):
		h = self.__handler
		# seek to given position
		h.seek(offs, 0)
		# goto end of next line
		if offs and endLine:
			h.readline()
		# get current real position
		return h.tell()

	def tell(self):
		# get current real position
		return self.__handler.tell()

	@staticmethod
	def decode_line(filename, enc, line):
		try:
			return line.decode(enc, 'strict')
		except (UnicodeDecodeError, UnicodeEncodeError) as e:
			global _decode_line_warn
			lev = logging.DEBUG
			if _decode_line_warn.get(filename, 0) <= MyTime.time():
				lev = logging.WARNING
				_decode_line_warn[filename] = MyTime.time() + 24*60*60
			logSys.log(lev,
				"Error decoding line from '%s' with '%s'."
				" Consider setting logencoding=utf-8 (or another appropriate"
				" encoding) for this jail. Continuing"
				" to process line ignoring invalid characters: %r",
				filename, enc, line)
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

_decode_line_warn = {}


##
# JournalFilter class.
#
# Base interface class for systemd journal filters

class JournalFilter(Filter): # pragma: systemd no cover

	def clearAllParams(self):
		super(JournalFilter, self).clearAllParams()
		self.delJournalMatch()

	def addJournalMatch(self, match): # pragma: no cover - Base class, not used
		pass

	def delJournalMatch(self, match=None): # pragma: no cover - Base class, not used
		pass

	def getJournalMatch(self, match): # pragma: no cover - Base class, not used
		return []

