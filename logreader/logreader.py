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

import os, sys, time

from sshd import Sshd

class LogReader:
	""" Reads a log file and reports information about IP that make password
		failure, bad user or anything else that is considered as doubtful login
		attempt.	
	"""
	
	def __init__(self, logPath, logSys, findTime = 3600):
		self.logPath = logPath
		self.findTime = findTime
		self.ignoreIpList = []
		self.lastModTime = 0
		self.logSys = logSys
		self.parserList = ["Sshd"]
	
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
	
	def matchLine(self, line):
		""" Checks if the line contains a pattern. It does this for all
			classes specified in *parserList*. We use a singleton to avoid
			creating/destroying objects too much.
			
			Return a dict with the IP and number of retries.
		"""
		for i in self.parserList:
			match = eval(i).getInstance().parseLogLine(line)
			if match:
				return match
		return None
	
	def getFailInfo(self, findTime):
		""" Gets the failed login attempt. Returns a dict() which contains
			IP and the number of retries.
		"""
		ipList = dict()
		logFile = self.openLogFile()
		for line in logFile.readlines():
			match = self.matchLine(line)
			if match:
				ip = match[0]
				unixTime = match[1]
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
	
	def getPwdFailure(self):
		""" Executes the getFailInfo method. Not very usefull...
		"""
		failList = self.getFailInfo(self.findTime)
		return failList
