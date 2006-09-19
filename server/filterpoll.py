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
# $Revision: 354 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 354 $"
__date__ = "$Date: 2006-09-13 23:31:22 +0200 (Wed, 13 Sep 2006) $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

from failmanager import FailManager
from failmanager import FailManagerEmpty
from failticket import FailTicket
from datedetector import DateDetector
from filter import Filter

import time, logging, os

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.filter")

##
# Log reader class.
#
# This class reads a log file and detects login failures or anything else
# that matches a given regular expression. This class is instanciated by
# a Jail object.

class FilterPoll(Filter):

	##
	# Constructor.
	#
	# Initialize the filter object with default values.
	# @param jail the jail object
	
	def __init__(self, jail):
		Filter.__init__(self, jail)
		
		self.__file404Cnt = dict()
		
		logSys.info("Created FilterPoll")

	##
	# Add a log file path
	#
	# @param path log file path

	def addLogPath(self, path):
		try:
			self.getLogPath().index(path)
			logSys.error(path + " already exists")
		except ValueError:
			self.getLogPath().append(path)
			# Initialize default values
			self.lastDate[path] = 0
			self.lastModTime[path] = 0
			self.lastPos[path] = 0
			self.__file404Cnt[path] = 0
			logSys.info("Added logfile = %s" % path)
	
	##
	# Delete a log path
	#
	# @param path the log file to delete
	
	def delLogPath(self, path):
		try:
			self.getLogPath().remove(path)
			del self.lastDate[path]
			del self.lastModTime[path]
			del self.lastPos[path]
			del self.__file404Cnt[path]
			logSys.info("Removed logfile = %s" % path)
		except ValueError:
			logSys.error(path + " is not monitored")

	
	##
	# Main loop.
	#
	# This function is the main loop of the thread. It checks if the
	# file has been modified and looks for failures.
	# @return True when the thread exits nicely

	def run(self):
		self.setActive(True)
		while self.isActive():
			if not self.getIdle():
				# Get file modification
				for file in self.getLogPath():
					if self.isModified(file):
						self.getFailures(file)
						prevModified = True

				if self.modified:
					try:
						ticket = self.failManager.toBan()
						self.jail.putFailTicket(ticket)
					except FailManagerEmpty:
						self.failManager.cleanup(time.time())
					self.dateDetector.sortTemplate()
					prevModified = False
				time.sleep(self.getSleepTime())
			else:
				time.sleep(self.getSleepTime())
		logSys.debug(self.jail.getName() + ": filter terminated")
		return True

	##
	# Checks if the log file has been modified.
	#
	# Checks if the log file has been modified using os.stat().
	# @return True if log file has been modified
	
	def isModified(self, filename):
		try:
			logStats = os.stat(filename)
			self.__file404Cnt[filename] = 0
			if self.lastModTime[filename] == logStats.st_mtime:
				return False
			else:
				logSys.debug(filename + " has been modified")
				self.lastModTime[filename] = logStats.st_mtime
				return True
		except OSError:
			logSys.error("Unable to get stat on " + filename)
			self.__file404Cnt[filename] = self.__file404Cnt[filename] + 1
			if self.__file404Cnt[filename] > 2:
				logSys.warn("Too much read error. Set the jail idle")
				self.jail.setIdle(True)
				self.__file404Cnt[filename] = 0
			return False
