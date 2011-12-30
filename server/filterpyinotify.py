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
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

# Author: Cyril Jaquier
#
# $Revision$

__author__ = "Cyril Jaquier"
__version__ = "$Revision$"
__date__ = "$Date$"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

from failmanager import FailManagerEmpty
from filter import FileFilter
from mytime import MyTime

import time, logging, pyinotify

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.filter")

##
# Log reader class.
#
# This class reads a log file and detects login failures or anything else
# that matches a given regular expression. This class is instantiated by
# a Jail object.

class FilterPyinotify(FileFilter):
	##
	# Constructor.
	#
	# Initialize the filter object with default values.
	# @param jail the jail object

	def __init__(self, jail):
		FileFilter.__init__(self, jail)
		self.__modified = False
		# Pyinotify watch manager
		self.monitor = pyinotify.WatchManager()
		logSys.debug("Created FilterPyinotify")


	def callback(self, path):
		self.getFailures(path)
		try:
			while True:
				ticket = self.failManager.toBan()
				self.jail.putFailTicket(ticket)
		except FailManagerEmpty:
			self.failManager.cleanup(MyTime.time())
		self.dateDetector.sortTemplate()
		self.__modified = False

	##
	# Add a log file path
	#
	# @param path log file path

	def addLogPath(self, path, tail=False):
		if self.containsLogPath(path):
			logSys.error(path + " already exists")
		else:
			wd = self.monitor.add_watch(path, pyinotify.IN_MODIFY)
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
		self.notifier = pyinotify.ThreadedNotifier(self.monitor,
			ProcessPyinotify(self))
		self.notifier.start()
		while self._isActive():
			if not self.getIdle():
				self.notifier.process_events()
				# Convert sleep seconds to millis
				if self.notifier.check_events():
					self.notifier.read_events()
			else:
				time.sleep(self.getSleepTime())
		# Cleanup pyinotify
		self.__cleanup()
		logSys.debug(self.jail.getName() + ": filter terminated")
		return True

	##
	# Call super.stop() and then stop the 'Notifier'

	def stop(self):
		# Call super to set __isRunning
		super(FilterPyinotify, self).stop()
		# Now stop the Notifier, otherwise we're deadlocked
		self.notifier.stop()

	##
	# Deallocates the resources used by pyinotify.

	def __cleanup(self):
		del self.notifier
		del self.monitor


class ProcessPyinotify(pyinotify.ProcessEvent):
	def __init__(self, FileFilter, **kargs):
		super(ProcessPyinotify, self).__init__(**kargs)
		self.__FileFilter = FileFilter
		pass

	# just need default, since using mask on watch to limit events
	def process_default(self, event):
		logSys.debug("PYINOTIFY: Callback for Event: %s" % event)
		self.__FileFilter.callback(event.pathname)
