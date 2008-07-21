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
# $Revision: 696 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 696 $"
__date__ = "$Date: 2008-05-19 23:05:32 +0200 (Mon, 19 May 2008) $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

from failmanager import FailManagerEmpty
from filter import FileFilter
from mytime import MyTime

import time, logging, os

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.filter")

##
# Log reader class.
#
# This class reads a log file and detects login failures or anything else
# that matches a given regular expression. This class is instanciated by
# a Jail object.

class FilterPoll(FileFilter):

	##
	# Constructor.
	#
	# Initialize the filter object with default values.
	# @param jail the jail object
	
	def __init__(self, jail):
		FileFilter.__init__(self, jail)
		self.__modified = False
		## The time of the last modification of the file.
		self.__lastModTime = dict()
		self.__file404Cnt = dict()
		logSys.debug("Created FilterPoll")

	##
	# Add a log file path
	#
	# @param path log file path

	def addLogPath(self, path, tail = False):
		if self.containsLogPath(path):
			logSys.error(path + " already exists")
		else:
			self.__lastModTime[path] = 0
			self.__file404Cnt[path] = 0
			FileFilter.addLogPath(self, path, tail)
			logSys.info("Added logfile = %s" % path)	
	
	##
	# Delete a log path
	#
	# @param path the log file to delete
	
	def delLogPath(self, path):
		if not self.containsLogPath(path):
			logSys.error(path + " is not monitored")
		else:
			del self.__lastModTime[path]
			del self.__file404Cnt[path]
			FileFilter.delLogPath(self, path)
			logSys.info("Removed logfile = %s" % path)
	
	##
	# Main loop.
	#
	# This function is the main loop of the thread. It checks if the
	# file has been modified and looks for failures.
	# @return True when the thread exits nicely

	def run(self):
		self.setActive(True)
		while self._isActive():
			if not self.getIdle():
				# Get file modification
				for container in self.getLogPath():
					if self.isModified(container.getFileName()):
						self.getFailures(container.getFileName())
						self.__modified = True

				if self.__modified:
					try:
						while True:
							ticket = self.failManager.toBan()
							self.jail.putFailTicket(ticket)
					except FailManagerEmpty:
						self.failManager.cleanup(MyTime.time())
					self.dateDetector.sortTemplate()
					self.__modified = False
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
			if self.__lastModTime[filename] == logStats.st_mtime:
				return False
			else:
				logSys.debug(filename + " has been modified")
				self.__lastModTime[filename] = logStats.st_mtime
				return True
		except OSError:
			logSys.error("Unable to get stat on " + filename)
			self.__file404Cnt[filename] = self.__file404Cnt[filename] + 1
			if self.__file404Cnt[filename] > 2:
				logSys.warn("Too much read error. Set the jail idle")
				self.jail.setIdle(True)
				self.__file404Cnt[filename] = 0
			return False
