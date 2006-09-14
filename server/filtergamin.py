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

from failmanager import FailManager
from failmanager import FailManagerEmpty
from failticket import FailTicket
from datedetector import DateDetector
from filter import Filter

import time, logging, gamin

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.filter")

##
# Log reader class.
#
# This class reads a log file and detects login failures or anything else
# that matches a given regular expression. This class is instanciated by
# a Jail object.

class FilterGamin(Filter):

	##
	# Constructor.
	#
	# Initialize the filter object with default values.
	# @param jail the jail object
	
	def __init__(self, jail):
		Filter.__init__(self, jail)
		
		self.monitor = gamin.WatchMonitor()
		
		logSys.info("Created FilterGamin")


	def callback(self, path, event):
		logSys.debug("Got event: " + `event` + " for " + path)
		if event in (gamin.GAMCreated, gamin.GAMChanged, gamin.GAMExists):
			logSys.debug("File changed: " + path)
			self.getFailures(path)
			self.modified = True


	##
	# Add a log file path
	#
	# @param path log file path

	def addLogPath(self, path):
		try:
			self.logPath.index(path)
			logSys.error(path + " already exists")
		except ValueError:
			self.monitor.watch_file(path, self.callback)
			self.logPath.append(path)
			# Initialize default values
			self.lastDate[path] = 0
			self.lastModTime[path] = 0
			self.lastPos[path] = 0
			logSys.info("Added logfile = %s" % path)
	
	##
	# Delete a log path
	#
	# @param path the log file to delete
	
	def delLogPath(self, path):
		try:
			self.monitor.stop_watch(path)
			self.logPath.remove(path)
			del self.lastDate[path]
			del self.lastModTime[path]
			del self.lastPos[path]
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
			if not self.isIdle:
				# We cannot block here because we want to be able to
				# exit.
				if self.monitor.event_pending():
					self.monitor.handle_events()

				if self.modified:
					try:
						ticket = self.failManager.toBan()
						self.jail.putFailTicket(ticket)
					except FailManagerEmpty:
						self.failManager.cleanup(time.time())
					self.dateDetector.sortTemplate()
					self.modified = False
				time.sleep(self.sleepTime)
			else:
				time.sleep(self.sleepTime)
		logSys.debug(self.jail.getName() + ": filter terminated")
		return True
