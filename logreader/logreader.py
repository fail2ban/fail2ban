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

import os, sys, time, re, logging

from utils.dns import *

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban")

class LogReader:
	""" Reads a log file and reports information about IP that make password
		failure, bad user or anything else that is considered as doubtful login
		attempt.	
	"""
	
	def __init__(self, logPath, timeregex, timepattern, failregex,
				  maxRetry, findTime):
		self.logPath = logPath
		self.maxRetry = maxRetry
		self.timeregex = timeregex
		self.timepattern = timepattern
		self.failregex = failregex
		self.findTime = findTime
		self.ignoreIpList = []
		self.lastModTime = 0
		self.lastPos = 0
		self.lastDate = 0
		self.logStats = None
	
	def getMaxRetry(self):
		""" Gets the maximum number of failures
		"""
		return self.maxRetry
	
	def getFindTime(self):
		""" Gets the find time.
		"""
		return self.findTime
	
	def addIgnoreIP(self, ip):
		""" Adds an IP to the ignore list.
		"""
		logSys.debug("Add "+ip+" to ignore list")
		self.ignoreIpList.append(ip)
		
	def inIgnoreIPList(self, ip):
		""" Checks if IP is in the ignore list.
		"""
		for i in self.ignoreIpList:
			s = i.split('/', 1)
			# IP address without CIDR mask
			if len(s) == 1:
				s.insert(1, '32')
			s[1] = long(s[1])
			a = cidr(s[0], s[1])
			b = cidr(ip, s[1])
			if a == b:
				return True
		return False
	
	def openLogFile(self):
		""" Opens the log file specified on init.
		"""
		try:
			fileHandler = open(self.logPath)
		except OSError:
			logSys.error("Unable to open "+self.logPath)
			sys.exit(-1)
		return fileHandler
		
	def isModified(self):
		""" Checks if the log file has been modified using os.stat().
		"""
		try:
			self.logStats = os.stat(self.logPath)
		except OSError:
			logSys.error("Unable to get stat on "+self.logPath)
			sys.exit(-1)
		
		if self.lastModTime == self.logStats.st_mtime:
			return False
		else:
			logSys.debug(self.logPath+" has been modified")
			self.lastModTime = self.logStats.st_mtime
			return True
	
	def setFilePos(self, file):
		""" Sets the file position. We must take care of log file rotation
			and reset the position to 0 in that case. Use the log message
			timestamp in order to detect this.		
		"""
		line = file.readline()
		if self.lastDate < self.getTime(line):
			logSys.debug("Date " + `self.lastDate` + " is " + "smaller than " +
							`self.getTime(line)`)
			logSys.debug("Log rotation detected for " + self.logPath)
			self.lastPos = 0
		
		logSys.debug("Setting file position to " + `self.lastPos` + " for " +
						self.logPath)
		file.seek(self.lastPos)
	
	def getFailures(self):
		""" Gets all the failure in the log file which are
			newer than time.time()-self.findTime.
			
			Returns a dict with the IP, the number of failure
			and the latest failure time.
		"""
		ipList = dict()
		logSys.debug(self.logPath)
		logFile = self.openLogFile()
		self.setFilePos(logFile)
		lastLine = ''
		for line in logFile:
			lastLine = line
			failList = self.findFailure(line)
			for element in failList:
				ip = element[0]
				unixTime = element[1]
				if unixTime < time.time()-self.findTime:
					break
				if self.inIgnoreIPList(ip):
					logSys.debug("Ignore "+ip)
					continue
				logSys.debug("Found "+ip)
				if ipList.has_key(ip):
					ipList[ip] = (ipList[ip][0]+1, unixTime)
				else:
					ipList[ip] = (1, unixTime)
		self.lastPos = logFile.tell()
		self.lastDate = self.getTime(lastLine)
		logFile.close()
		return ipList

	def findFailure(self, line):
		""" Finds the failure in line. Uses the failregex pattern
			to find it and timeregex in order to find the logging
			time.
			
			Returns a dict with IP and timestamp.
		"""
		failList = list()
		match = re.search(self.failregex, line)
		if match:
			timeMatch = re.search(self.timeregex, match.string)
			if timeMatch:
				date = self.getUnixTime(timeMatch.group())
				ipMatch = textToIp(match.string)
				if ipMatch:
					for ip in ipMatch:
						failList.append([ip, date])
		return failList
	
	def getTime(self, line):
		""" Gets the time of a log message.
		"""
		date = 0
		timeMatch = re.search(self.timeregex, line)
		if timeMatch:
			date = self.getUnixTime(timeMatch.group())
		return date
		
	def getUnixTime(self, value):
		""" Returns the Unix timestamp of the given value.
			Pattern should describe the date construction of
			value.
		"""
		date = list(time.strptime(value, self.timepattern))
		if date[0] < 2000:
			# There is probably no year field in the logs
			date[0] = time.gmtime()[0]
			# Bug fix for #1241756
			# If the date is greater than the current time, we suppose
			# that the log is not from this year but from the year before
			if time.mktime(date) > time.time():
				date[0] -= 1
		unixTime = time.mktime(date)
		return unixTime
