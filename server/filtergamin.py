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

import time, logging, gamin

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.filter")

##
# Log reader class.
#
# This class reads a log file and detects login failures or anything else
# that matches a given regular expression. This class is instanciated by
# a Jail object.

class FilterGamin(FileFilter):

	##
	# Constructor.
	#
	# Initialize the filter object with default values.
	# @param jail the jail object
	
	def __init__(self, jail):
		FileFilter.__init__(self, jail)
		self.__modified = False
		# Gamin monitor
		self.monitor = gamin.WatchMonitor()
		logSys.debug("Created FilterGamin")


	def callback(self, path, event):
		logSys.debug("Got event: " + `event` + " for " + path)
		if event in (gamin.GAMCreated, gamin.GAMChanged, gamin.GAMExists):
			logSys.debug("File changed: " + path)
			self.getFailures(path)
			self.__modified = True


	##
	# Add a log file path
	#
	# @param path log file path

	def addLogPath(self, path, tail = False):
		if self.containsLogPath(path):
			logSys.error(path + " already exists")
		else:
			self.monitor.watch_file(path, self.callback)
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
			self.monitor.stop_watch(path)
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
				# We cannot block here because we want to be able to
				# exit.
				if self.monitor.event_pending():
					self.monitor.handle_events()

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
		# Cleanup Gamin
		self.__cleanup()
		logSys.debug(self.jail.getName() + ": filter terminated")
		return True

	##
	# Desallocates the resources used by Gamin.

	def __cleanup(self):
		for path in self.getLogPath():
			self.monitor.stop_watch(path.getFileName())
		del self.monitor
