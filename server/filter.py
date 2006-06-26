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
# $Revision: 1.1 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 1.1 $"
__date__ = "$Date: 2004/10/10 13:33:40 $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

from failmanager import FailManager
from failmanager import FailManagerEmpty
from failticket import FailTicket
from jailthread import JailThread
from utils.dns import *
import time, logging, os, re, sys, socket

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
		## The log file handler.
		self.fileHandler = None
		## The log file path.
		self.logPath = ''
		## The regular expression matching the date.
		self.timeRegex = ''
		## The pattern matching the date.
		self.timePattern = ''
		## The regular expression matching the failure.
		self.failRegex = ''
		## The amount of time to look back.
		self.findTime = 6000
		## The ignore IP list.
		self.ignoreIpList = []
		## The time of the last modification of the file.
		self.lastModTime = 0
		## The last position of the file.
		self.lastPos = 0
		## The last date in tht log file.
		self.lastDate = 0
		## The file statistics.
		self.logStats = None
		logSys.info("Created Filter")

	##
	# Set the log file path
	#
	# @param value log file path

	def setLogPath(self, value):
		self.logPath = value
		logSys.info("Set logfile = %s" % value)

	##
	# Get the log file path
	#
	# @return log file path
		
	def getLogPath(self):
		return self.logPath
	
	##
	# Set the regular expression which matches the time.
	#
	# @param value the regular expression
	
	def setTimeRegex(self, value):
		self.timeRegex = value
		logSys.info("Set timeregex = %s" % value)
	
	##
	# Get the regular expression which matches the time.
	#
	# @return the regular expression
		
	def getTimeRegex(self):
		return self.timeRegex
	
	##
	# Set the time pattern.
	#
	# @param value the time pattern
	
	def setTimePattern(self, value):
		self.timePattern = value
		logSys.info("Set timepattern = %s" % value)
	
	##
	# Get the time pattern.
	#
	# @return the time pattern
	
	def getTimePattern(self):
		return self.timePattern
	
	##
	# Set the regular expression which matches the failure.
	#
	# The regular expression can also match any other pattern than failures
	# and thus can be used for many purporse.
	# @param value the regular expression
	
	def setFailRegex(self, value):
		self.failRegex = value
		logSys.info("Set failregex = %s" % value)
	
	##
	# Get the regular expression which matches the failure.
	#
	# @return the regular expression
	
	def getFailRegex(self):
		return self.failRegex
	
	##
	# Set the time needed to find a failure.
	#
	# This value tells the filter how long it has to take failures into
	# account.
	# @param value the time
	
	def setFindTime(self, value):
		self.findTime = value
		logSys.info("Set findtime = %s" % value)
	
	##
	# Get the time needed to find a failure.
	#
	# @return the time
	
	def getFindTime(self):
		return self.findTime
	
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
		self.setActive(True)
		while self.isActive():
			if not self.isIdle:
				if self.isModified():
					self.getFailures()
				try:
					ticket = self.failManager.toBan()
					self.jail.putFailTicket(ticket)
				except FailManagerEmpty:
					self.failManager.cleanup(time.time())
					time.sleep(self.sleepTime)
			else:
				time.sleep(self.sleepTime)
		logSys.debug(self.jail.getName() + ": filter terminated")
		return True
	
	##
	# Add an IP to the ignore list.
	#
	# IP addresses in the ignore list are not taken into account
	# when finding failures. CIDR mask are also accepted.
	# @param ip IP address to ignore
	
	def addIgnoreIP(self, ip):
		logSys.debug("Add " + ip + " to ignore list")
		self.ignoreIpList.append(ip)
	
	##
	# Check if IP address is in the ignore list.
	#
	# Check if the given IP address matches an IP address or a CIDR
	# mask in the ignore list.
	# @param ip IP address
	# @return True if IP address is in ignore list
	
	def inIgnoreIPList(self, ip):
		for i in self.ignoreIpList:
			s = i.split('/', 1)
			# IP address without CIDR mask
			if len(s) == 1:
				s.insert(1, '32')
			s[1] = long(s[1])
			try:
				a = cidr(s[0], s[1])
				b = cidr(ip, s[1])
			except Exception:
				return False
			if a == b:
				return True
		return False
	
	##
	# Open the log file.
	
	def openLogFile(self):
		""" Opens the log file specified on init.
		"""
		try:
			self.fileHandler = open(self.logPath)
		except OSError:
			logSys.error("Unable to open "+self.logPath)
	
	##
	# Close the log file.
	
	def closeLogFile(self):
		self.fileHandler.close()
	
	##
	# Checks if the log file has been modified.
	#
	# Checks if the log file has been modified using os.stat().
	# @return True if log file has been modified
	
	def isModified(self):
		try:
			self.logStats = os.stat(self.logPath)
			if self.lastModTime == self.logStats.st_mtime:
				return False
			else:
				logSys.debug(self.logPath + " has been modified")
				self.lastModTime = self.logStats.st_mtime
				return True
		except OSError:
			logSys.error("Unable to get stat on " + self.logPath)
			return False

	##
	# Set the file position.
	#
	# Sets the file position. We must take care of log file rotation
	# and reset the position to 0 in that case. Use the log message
	# timestamp in order to detect this.
	
	def setFilePos(self):
		line = self.fileHandler.readline()
		if self.lastDate < self.getTime(line):
			logSys.debug("Date " + `self.lastDate` + " is " + "smaller than " +
							`self.getTime(line)`)
			logSys.debug("Log rotation detected for " + self.logPath)
			self.lastPos = 0
		
		logSys.debug("Setting file position to " + `self.lastPos` + " for " +
						self.logPath)
		self.fileHandler.seek(self.lastPos)

	##
	# Get the file position.
	
	def getFilePos(self):
		return self.fileHandler.tell()

	##
	# Gets all the failure in the log file.
	#
	# Gets all the failure in the log file which are newer than
	# time.time()-self.findTime. When a failure is detected, a FailTicket
	# is created and is added to the FailManager.
	
	def getFailures(self):
		ipList = dict()
		logSys.debug(self.logPath)
		self.openLogFile()
		self.setFilePos()
		lastLine = None
		for line in self.fileHandler:
			try:
				# Try to convert UTF-8 string to Latin-1
				line = line.decode('utf-8').encode('latin-1')
			except UnicodeDecodeError:
				pass
			if not self.hasTime(line):
				# There is no valid time in this line
				continue
			lastLine = line
			for element in self.findFailure(line):
				ip = element[0]
				unixTime = element[1]
				if unixTime < time.time()-self.findTime:
					break
				if self.inIgnoreIPList(ip):
					logSys.debug("Ignore "+ip)
					continue
				logSys.debug("Found "+ip)
				self.failManager.addFailure(FailTicket(ip, unixTime))
		self.lastPos = self.getFilePos()
		if lastLine:
			self.lastDate = self.getTime(lastLine)
		self.closeLogFile()

	##
	# Finds the failure in a line.
	#
	# Uses the failregex pattern to find it and timeregex in order
	# to find the logging time.
	# @return a dict with IP and timestamp.

	def findFailure(self, line):
		failList = list()
		match = re.search(self.failRegex, line)
		if match:
			timeMatch = re.search(self.timeRegex, match.string)
			if timeMatch:
				date = self.getUnixTime(timeMatch.group())
				ipMatch = textToIp(match.string)
				if ipMatch:
					for ip in ipMatch:
						failList.append([ip, date])
		return failList
	
	##
	# Check is a line contains a valid date.
	#
	# @param line the line
	# @return True if the line contains a valid date
	
	def hasTime(self, line):
		timeMatch = re.search(self.timeRegex, line)
		if timeMatch:
			return True
		else:
			return False

	##
	# Get the time of a log line.
	#
	# @param line the line
	# @return the timestamp of the log line
	
	def getTime(self, line):
		date = 0
		timeMatch = re.search(self.timeRegex, line)
		if timeMatch:
			date = self.getUnixTime(timeMatch.group())
		return date

	##
	# Get the Unix timestamp.
	#
	# Get the Unix timestamp of a given date. Pattern should describe the
	# date construction of value.
	# @param value the date
	# @return the Unix timestamp
		
	def getUnixTime(self, value):
		try:
			# Check if the parsed value is in TAI64N format
			if not self.timePattern.lower() == "tai64n":
				date = list(time.strptime(value, self.timePattern))
			else:
				# extract part of format which represents seconds since epoch
				seconds_since_epoch = value[2:17]
				date = list(time.gmtime(int(seconds_since_epoch, 16)))
		except ValueError, e:
			logSys.error(e)
			logSys.error("Please check the format and your locale settings.")
			return None
		if date[0] < 2000:
			# There is probably no year field in the logs
			date[0] = time.gmtime()[0]
			# Bug fix for #1241756
			# If the date is greater than the current time, we suppose
			# that the log is not from this year but from the year before
			#if time.mktime(date) > time.time():
			#	date[0] -= 1
		unixTime = time.mktime(date)
		return unixTime

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
	