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

import os, sys, time, re

class LogReader:
	""" Reads a log file and reports information about IP that make password
		failure, bad user or anything else that is considered as doubtful login
		attempt.	
	"""
	
	def __init__(self, logSys, logPath, timeregex, timepattern, failregex, findTime = 3600):
		self.logPath = logPath
		self.timeregex = timeregex
		self.timepattern = timepattern
		self.failregex = failregex
		self.findTime = findTime
		self.ignoreIpList = []
		self.lastModTime = 0
		self.logSys = logSys
		
	def setName(self, name):
		""" Sets the name of the log reader.
		"""
		self.name = name
		
	def getName(self):
		""" Gets the name of the log reader.
		"""
		return self.name
	
	def addIgnoreIP(self, ip):
		""" Adds an IP to the ignore list.
		"""
		self.logSys.debug("Add "+ip+" to ignore list")
		self.ignoreIpList.append(ip)
		
	def inIgnoreIPList(self, ip):
		""" Checks if IP is in the ignore list.
		"""
		return ip in self.ignoreIpList
	
	def openLogFile(self):
		""" Opens the log file specified on init.
		"""
		try:
			fileHandler = open(self.logPath)
		except OSError:
			self.logSys.error("Unable to open "+self.logPath)
			sys.exit(-1)
		return fileHandler
		
	def isModified(self):
		""" Checks if the log file has been modified using os.stat().
		"""
		try:
			logStats = os.stat(self.logPath)
		except OSError:
			self.logSys.error("Unable to get stat on "+self.logPath)
			sys.exit(-1)
		
		if self.lastModTime == logStats.st_mtime:
			return False
		else:
			self.logSys.debug(self.logPath+" has been modified")
			self.lastModTime = logStats.st_mtime
			return True
	
	def getFailures(self):
		""" Gets all the failure in the log file which are
			newer than time.time()-self.findTime.
			
			Returns a dict with the IP, the number of failure
			and the latest failure time.
		"""
		ipList = dict()
		logFile = self.openLogFile()
		for line in logFile.readlines():
			value = self.findFailure(line)
			if value:
				ip = value[0]
				unixTime = value[1]
				if unixTime < time.time()-self.findTime:
					continue
				if self.inIgnoreIPList(ip):
					self.logSys.debug("Ignore "+ip)
					continue
				self.logSys.debug("Found "+ip)
				if ipList.has_key(ip):
					ipList[ip] = (ipList[ip][0]+1, unixTime)
				else:
					ipList[ip] = (1, unixTime)
		logFile.close()
		return ipList

	def findFailure(self, line):
		""" Finds the failure in line. Uses the failregex pattern
			to find it and timeregex in order to find the logging
			time.
			
			Returns a dict with IP and timestamp.
		"""
		match = self.matchLine(self.failregex, line)
		if match:
			timeMatch = self.matchLine(self.timeregex, match.string)
			if timeMatch:
				date = self.getUnixTime(timeMatch.group())
				ipMatch = self.matchAddress(match.string)
				if ipMatch:
					ip = ipMatch.group()
					return [ip, date]
		return None
		
	def getUnixTime(self, value):
		""" Returns the Unix timestamp of the given value.
			Pattern should describe the date construction of
			value.
		"""
		date = list(time.strptime(value, self.timepattern))
		if date[0] < 2000:
			date[0] = time.gmtime()[0]
		unixTime = time.mktime(date)
		return unixTime
	
	def matchLine(self, pattern, line):
		""" Checks if the line contains a pattern.
			
			Return a match object.
		"""
		return re.search(pattern, line)
		
	def matchAddress(self, line):
		""" Return a match on the IP address present in
			line.		
		"""
		return self.matchLine("(?:\d{1,3}\.){3}\d{1,3}", line)
	