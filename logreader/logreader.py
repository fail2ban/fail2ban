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

import os, sys

class LogReader:
	
	def __init__(self, logPath, findTime = 3600):
		self.logPath = logPath
		self.findTime = findTime
		self.ignoreIpList = []
		self.lastModTime = 0
	
	def addIgnoreIP(self, ip):
		self.ignoreIpList.append(ip)
		
	def inIgnoreIPList(self, ip):
		return ip in self.ignoreIpList
	
	def openLogFile(self):
		try:
			fileHandler = open(self.logPath)
		except OSError:
			print "Unable to open", self.logPath
			sys.exit(-1)
		return fileHandler
		
	def isModified(self):
		try:
			logStats = os.stat(self.logPath)
		except OSError:
			print "Unable to get stat on", logPath
			sys.exit(-1)
		
		if self.lastModTime == logStats.st_mtime:
			return False
		else:
			print self.logPath, 'has been modified'
			self.lastModTime = logStats.st_mtime
			return True
	
	def getPwdFailure(self):
		failList = self.getFailInfo(self.findTime)
		return failList
