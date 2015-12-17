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

# Author: Cyril Jaquier, Yaroslav Halchenko
#

__author__ = "Cyril Jaquier, Yaroslav Halchenko"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier; 2012 Yaroslav Halchenko"
__license__ = "GPL"

import os
import time

from .failmanager import FailManagerEmpty
from .filter import FileFilter
from .mytime import MyTime
from ..helpers import getLogger

# Gets the instance of the logger.
logSys = getLogger(__name__)


##
# Log reader class.
#
# This class reads a log file and detects login failures or anything else
# that matches a given regular expression. This class is instantiated by
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
		self.__prevStats = dict()
		self.__file404Cnt = dict()
		logSys.debug("Created FilterPoll")

	##
	# Add a log file path
	#
	# @param path log file path

	def _addLogPath(self, path):
		self.__prevStats[path] = (0, None, None)	 # mtime, ino, size
		self.__file404Cnt[path] = 0

	##
	# Delete a log path
	#
	# @param path the log file to delete

	def _delLogPath(self, path):
		del self.__prevStats[path]
		del self.__file404Cnt[path]

	##
	# Main loop.
	#
	# This function is the main loop of the thread. It checks if the
	# file has been modified and looks for failures.
	# @return True when the thread exits nicely

	def run(self):
		while self.active:
			if logSys.getEffectiveLevel() <= 6:
				logSys.log(6, "Woke up idle=%s with %d files monitored",
						   self.idle, len(self.getLogs()))
			if not self.idle:
				# Get file modification
				for container in self.getLogs():
					filename = container.getFileName()
					if self.isModified(filename):
						self.getFailures(filename)
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
				time.sleep(self.sleeptime)
			else:
				time.sleep(self.sleeptime)
		logSys.debug(
			(self.jail is not None and self.jail.name or "jailless") +
					 " filter terminated")
		return True

	##
	# Checks if the log file has been modified.
	#
	# Checks if the log file has been modified using os.stat().
	# @return True if log file has been modified

	def isModified(self, filename):
		try:
			logStats = os.stat(filename)
			stats = logStats.st_mtime, logStats.st_ino, logStats.st_size
			pstats = self.__prevStats[filename]
			self.__file404Cnt[filename] = 0
			if logSys.getEffectiveLevel() <= 7:
				# we do not want to waste time on strftime etc if not necessary
				dt = logStats.st_mtime - pstats[0]
				logSys.log(7, "Checking %s for being modified. Previous/current stats: %s / %s. dt: %s",
				           filename, pstats, stats, dt)
				# os.system("stat %s | grep Modify" % filename)
			if pstats == stats:
				return False
			else:
				logSys.debug("%s has been modified", filename)
				self.__prevStats[filename] = stats
				return True
		except OSError, e:
			logSys.error("Unable to get stat on %s because of: %s"
						 % (filename, e))
			self.__file404Cnt[filename] += 1
			if self.__file404Cnt[filename] > 2:
				logSys.warning("Too many errors. Setting the jail idle")
				if self.jail is not None:
					self.jail.idle = True
				else:
					logSys.warning("No jail is assigned to %s" % self)
				self.__file404Cnt[filename] = 0
			return False
