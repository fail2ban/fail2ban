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

__author__ = "Cyril Jaquier, Yaroslav Halchenko"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier, 2012 Yaroslav Halchenko"
__license__ = "GPL"

import fcntl
import time

import gamin

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
		fd = self.monitor.get_fd()
		flags = fcntl.fcntl(fd, fcntl.F_GETFD)
		fcntl.fcntl(fd, fcntl.F_SETFD, flags|fcntl.FD_CLOEXEC)
		logSys.debug("Created FilterGamin")

	def callback(self, path, event):
		logSys.debug("Got event: " + repr(event) + " for " + path)
		if event in (gamin.GAMCreated, gamin.GAMChanged, gamin.GAMExists):
			logSys.debug("File changed: " + path)
			self.__modified = True

		self._process_file(path)

	def _process_file(self, path):
		"""Process a given file

		TODO -- RF:
		this is a common logic and must be shared/provided by FileFilter
		"""
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

	def _addLogPath(self, path):
		self.monitor.watch_file(path, self.callback)

	##
	# Delete a log path
	#
	# @param path the log file to delete

	def _delLogPath(self, path):
		self.monitor.stop_watch(path)

	##
	# Main loop.
	#
	# This function is the main loop of the thread. It checks if the
	# file has been modified and looks for failures.
	# @return True when the thread exits nicely

	def run(self):
		# Gamin needs a loop to collect and dispatch events
		while self.active:
			if not self.idle:
				# We cannot block here because we want to be able to
				# exit.
				if self.monitor.event_pending():
					self.monitor.handle_events()
			time.sleep(self.sleeptime)
		logSys.debug(self.jail.name + ": filter terminated")
		return True

	def stop(self):
		super(FilterGamin, self).stop()
		self.__cleanup()

	##
	# Desallocates the resources used by Gamin.

	def __cleanup(self):
		for log in self.getLogs():
			self.monitor.stop_watch(log.getFileName())
		del self.monitor
