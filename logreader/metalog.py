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

import re, time

from logreader import LogReader

class Metalog(LogReader):
	
	def getFailInfo(self, findTime):
		ipList = dict()
		logFile = self.openLogFile()
		for line in logFile.readlines():
			match = self.parseLogLine(line)
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
	
	def parseLogLine(self, line):
		""" Match sshd failed password log
		"""
		if re.search("Failed password", line):
			matchIP = re.search("(?:\d{1,3}\.){3}\d{1,3}", line)
			if matchIP:
				date = list(time.strptime(line[0:15], "%b %d %H:%M:%S"))
				date[0] = time.gmtime()[0]
				unixTime = time.mktime(date)
				return [matchIP.group(), unixTime]
			else:
				return False
