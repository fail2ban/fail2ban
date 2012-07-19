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

# Original author: Cyril Jaquier

__author__ = "Cyril Jaquier, Lee Clemens, Yaroslav Halchenko"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier, 2011-2012 Lee Clemens, 2012 Yaroslav Halchenko"
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
		self.__monitor = pyinotify.WatchManager()
		self.__watches = dict()
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
			wd = self.__monitor.add_watch(path, pyinotify.IN_MODIFY)
			self.__watches.update(wd)
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
			wdInt = self.__watches[path]
			wd = self.__monitor.rm_watch(wdInt)
			if wd[wdInt]:
				del self.__watches[path]
				FileFilter.delLogPath(self, path)
				logSys.info("Removed logfile = %s" % path)
			else:
				logSys.error("Failed to remove watch on path: %s", path)

	##
	# Main loop.
	#
	# Since all detection is offloaded to pyinotifier -- no manual
	# loop is necessary

	def run(self):
		self.setActive(True)
		self.__notifier = pyinotify.ThreadedNotifier(self.__monitor,
			ProcessPyinotify(self))
		self.__notifier.start()
		logSys.debug("pyinotifier started for %s." % self.jail.getName())
		# TODO: verify that there is nothing really to be done for
		#       idle jails
		return True

	##
	# Call super.stop() and then stop the 'Notifier'

	def stop(self):
		super(FilterPyinotify, self).stop()

		# Stop the notifier thread
		self.__notifier.stop()
		self.__notifier.join()			# to not exit before notifier does
		self.__cleanup()				# for pedantic ones

	##
	# Deallocates the resources used by pyinotify.

	def __cleanup(self):
		self.__notifier = None
		self.__monitor = None


class ProcessPyinotify(pyinotify.ProcessEvent):
	def __init__(self, FileFilter, **kargs):
		#super(ProcessPyinotify, self).__init__(**kargs)
		# for some reason root class _ProcessEvent is old-style (is
		# not derived from object), so to play safe let's avoid super
		# for now, and call superclass directly
		pyinotify.ProcessEvent.__init__(self, **kargs)
		self.__FileFilter = FileFilter
		pass

	# just need default, since using mask on watch to limit events
	def process_default(self, event):
		logSys.debug("Callback for Event: %s" % event)
		self.__FileFilter.callback(event.pathname)
