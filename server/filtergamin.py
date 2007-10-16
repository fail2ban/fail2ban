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
# $Revision: 418 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 418 $"
__date__ = "$Date: 2006-10-19 00:30:57 +0200 (Thu, 19 Oct 2006) $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

from failmanager import FailManagerEmpty
from filter import Filter
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

class FilterGamin(Filter):

	##
	# Constructor.
	#
	# Initialize the filter object with default values.
	# @param jail the jail object
	
	def __init__(self, jail):
		Filter.__init__(self, jail)
		# Gamin monitor
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
		if self.containsLogPath(path):
			logSys.error(path + " already exists")
		else:
			self.monitor.watch_file(path, self.callback)
			Filter.addLogPath(self, path)
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
			Filter.delLogPath(self, path)
			logSys.info("Removed logfile = %s" % path)
		
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
				# We cannot block here because we want to be able to
				# exit.
				if self.monitor.event_pending():
					self.monitor.handle_events()

				if self.modified:
					try:
						ticket = self.failManager.toBan()
						self.jail.putFailTicket(ticket)
					except FailManagerEmpty:
						self.failManager.cleanup(MyTime.time())
					self.dateDetector.sortTemplate()
					self.modified = False
				time.sleep(self.getSleepTime())
			else:
				time.sleep(self.getSleepTime())
		logSys.debug(self.jail.getName() + ": filter terminated")
		return True
