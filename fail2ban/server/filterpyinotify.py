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

import logging
from distutils.version import LooseVersion
from os.path import dirname, sep as pathsep

import pyinotify

from .failmanager import FailManagerEmpty
from .filter import FileFilter
from .mytime import MyTime
from ..helpers import getLogger


if not hasattr(pyinotify, '__version__') \
  or LooseVersion(pyinotify.__version__) < '0.8.3':
  raise ImportError("Fail2Ban requires pyinotify >= 0.8.3")

# Verify that pyinotify is functional on this system
# Even though imports -- might be dysfunctional, e.g. as on kfreebsd
try:
	manager = pyinotify.WatchManager()
	del manager
except Exception, e:
	raise ImportError("Pyinotify is probably not functional on this system: %s"
					  % str(e))

# Gets the instance of the logger.
logSys = getLogger(__name__)


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

	def callback(self, event, origin=''):
		logSys.debug("%sCallback for Event: %s", origin, event)
		path = event.pathname
		if event.mask & ( pyinotify.IN_CREATE | pyinotify.IN_MOVED_TO ):
			# skip directories altogether
			if event.mask & pyinotify.IN_ISDIR:
				logSys.debug("Ignoring creation of directory %s", path)
				return
			# check if that is a file we care about
			if not path in self.__watches:
				logSys.debug("Ignoring creation of %s we do not monitor", path)
				return
			else:
				# we need to substitute the watcher with a new one, so first
				# remove old one
				self._delFileWatcher(path)
				# place a new one
				self._addFileWatcher(path)

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

	def _addFileWatcher(self, path):
		wd = self.__monitor.add_watch(path, pyinotify.IN_MODIFY)
		self.__watches.update(wd)
		logSys.debug("Added file watcher for %s", path)

	def _delFileWatcher(self, path):
		wdInt = self.__watches[path]
		wd = self.__monitor.rm_watch(wdInt)
		if wd[wdInt]:
			del self.__watches[path]
			logSys.debug("Removed file watcher for %s", path)
			return True
		else:
			return False

	##
	# Add a log file path
	#
	# @param path log file path

	def _addLogPath(self, path):
		path_dir = dirname(path)
		if not (path_dir in self.__watches):
			# we need to watch also  the directory for IN_CREATE
			self.__watches.update(
				self.__monitor.add_watch(path_dir, pyinotify.IN_CREATE | pyinotify.IN_MOVED_TO))
			logSys.debug("Added monitor for the parent directory %s", path_dir)

		self._addFileWatcher(path)
		self._process_file(path)

    ##
	# Delete a log path
	#
	# @param path the log file to delete

	def _delLogPath(self, path):
		if not self._delFileWatcher(path):
			logSys.error("Failed to remove watch on path: %s", path)

		path_dir = dirname(path)
		if not len([k for k in self.__watches
					if k.startswith(path_dir + pathsep)]):
			# Remove watches for the directory
			# since there is no other monitored file under this directory
			wdInt = self.__watches.pop(path_dir)
			self.__monitor.rm_watch(wdInt)
			logSys.debug("Removed monitor for the parent directory %s", path_dir)

	##
	# Main loop.
	#
	# Since all detection is offloaded to pyinotifier -- no manual
	# loop is necessary

	def run(self):
		self.__notifier = pyinotify.ThreadedNotifier(self.__monitor,
			ProcessPyinotify(self))
		self.__notifier.start()
		logSys.debug("pyinotifier started for %s.", self.jail.name)
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
		try:
			self.__FileFilter.callback(event, origin='Default ')
		except Exception as e:
			logSys.error("Error in FilterPyinotify callback: %s",
				e, exc_info=logSys.getEffectiveLevel() <= logging.DEBUG)
