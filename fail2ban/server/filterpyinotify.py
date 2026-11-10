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

import os
from os.path import dirname

from .filternotify import FileNotifyFilter, _dirPrefix
from .utils import Utils
from ..helpers import getLogger

# pyinotify may have dependency to asyncore, so import it after helper to ensure 
# we've a path to compat folder:
import pyinotify

# Verify that pyinotify is functional on this system
# Even though imports -- might be dysfunctional, e.g. as on kfreebsd
try:
	manager = pyinotify.WatchManager()
	del manager
except Exception as e: # pragma: no cover
	raise ImportError("Pyinotify is probably not functional on this system: %s"
					  % str(e))

# Gets the instance of the logger.
logSys = getLogger(__name__)

# Override pyinotify default logger/init-handler:
def _pyinotify_logger_init(): # pragma: no cover
	return logSys
pyinotify._logger_init = _pyinotify_logger_init
pyinotify.log = logSys

##
# Log reader class.
#
# This class reads a log file and detects login failures or anything else
# that matches a given regular expression. This class is instantiated by
# a Jail object.

class FilterPyinotify(FileNotifyFilter):

	_monitorName = 'pyinotifier'

	##
	# Constructor.
	#
	# Initialize the filter object with default values.
	# @param jail the jail object

	def __init__(self, jail):
		FileNotifyFilter.__init__(self, jail)
		# Pyinotify watch manager
		self.__monitor = pyinotify.WatchManager()
		self.__notifier = None
		logSys.debug("Created FilterPyinotify")

	def callback(self, event, origin=''):
		logSys.log(4, "[%s] %sCallback for Event: %s", self.jailName, origin, event)
		path = event.pathname
		reason = (event.maskname, event.pathname)
		# check watching of this path:
		isWF = False
		isWD = path in self._watchDirs
		if not isWD and path in self._watchFiles:
			isWF = True
		assumeNoDir = False
		if event.mask & ( pyinotify.IN_CREATE | pyinotify.IN_MOVED_TO ):
			# skip directories altogether
			if event.mask & pyinotify.IN_ISDIR:
				logSys.debug("Ignoring creation of directory %s", path)
				return
			# check if that is a file we care about
			if not isWF:
				logSys.debug("Ignoring creation of %s we do not monitor", path)
				return
			self._refreshFileWatcher(path)
		elif event.mask & (pyinotify.IN_IGNORED | pyinotify.IN_MOVE_SELF | pyinotify.IN_DELETE_SELF):
			assumeNoDir = event.mask & (pyinotify.IN_MOVE_SELF | pyinotify.IN_DELETE_SELF)
			# fix pyinotify behavior with '-unknown-path' (if target not watched also):
			if (assumeNoDir and 
					path.endswith('-unknown-path') and not isWF and not isWD
			):
				path = path[:-len('-unknown-path')]
				isWD = path in self._watchDirs
			# watch was removed for some reasons (log-rotate?):
			if isWD and (assumeNoDir or not os.path.isdir(path)):
				self._dirLost(path, reason)
			elif not isWF: # pragma: no cover (assume too sporadic)
				self._subDirsLost(path, reason, assumeNoDir)
		if isWF and not os.path.isfile(path):
			self._addPending(path, reason)
			return
		# do nothing if idle:
		if self.idle: # pragma: no cover (too sporadic to get idle in callback)
			return
		# be sure we process a file:
		if not isWF:
			logSys.debug("Ignoring event (%s) of %s we do not monitor", event.maskname, path)
			return
		self._process_file(path)

	def _refreshFileWatcher(self, path):
		# we need to substitute the watcher with a new one, so first
		# remove old one and then place a new one
		self._delFileWatcher(path)
		self._addFileWatcher(path)

	def _refreshDirWatcher(self, path_dir):
		self._delDirWatcher(path_dir)
		self._addDirWatcher(path_dir)

	def _addFileWatcher(self, path):
		# we need to watch also the directory for IN_CREATE
		self._addDirWatcher(dirname(path))
		# add file watcher:
		wd = self.__monitor.add_watch(path, pyinotify.IN_MODIFY)
		self._watchFiles.update(wd)
		logSys.debug("Added file watcher for %s", path)

	def _delWatch(self, wdInt):
		m = self.__monitor
		try:
			if m.get_path(wdInt) is not None:
				wd = m.rm_watch(wdInt, quiet=False)
				return True
		except pyinotify.WatchManagerError as e:
			if m.get_path(wdInt) is not None and not str(e).endswith("(EINVAL)"): # prama: no cover
				logSys.debug("Remove watch causes: %s", e)
				raise e
		return False

	def _delFileWatcher(self, path):
		try:
			wdInt = self._watchFiles.pop(path)
			if not self._delWatch(wdInt):
				logSys.debug("Non-existing file watcher %r for file %s", wdInt, path)
			logSys.debug("Removed file watcher for %s", path)
			return True
		except KeyError: # pragma: no cover
			pass
		return False

	def _addDirWatcher(self, path_dir):
		# Add watch for the directory:
		if path_dir not in self._watchDirs:
			# note: IN_ISDIR is an output flag only (set in events by kernel), it must not be
			# specified in the mask, since some systems reject it with EINVAL (e. g. FreeBSD 15+,
			# with native inotify), so the directory would be not monitored at all (gh-4250);
			# IN_ONLYDIR (input flag) to watch the path only if it is a directory;
			# IN_DELETE and IN_MOVED_FROM to notice removal of watched files in the directory, since
			# not all systems send IN_IGNORED for the watch of a removed file (e. g. FreeBSD):
			self._watchDirs.update(
				self.__monitor.add_watch(path_dir, pyinotify.IN_CREATE |
					pyinotify.IN_MOVED_TO | pyinotify.IN_DELETE | pyinotify.IN_MOVED_FROM |
					pyinotify.IN_MOVE_SELF | pyinotify.IN_DELETE_SELF | pyinotify.IN_ONLYDIR))
			logSys.debug("Added monitor for the parent directory %s", path_dir)

	def _delDirWatcher(self, path_dir):
		# Remove watches for the directory:
		try:
			wdInt = self._watchDirs.pop(path_dir)
			if not self._delWatch(wdInt): # pragma: no cover
				logSys.debug("Non-existing file watcher %r for directory %s", wdInt, path_dir)
			logSys.debug("Removed monitor for the parent directory %s", path_dir)
		except KeyError: # pragma: no cover
			pass

	##
	# Delete a log path
	#
	# @param path the log file to delete

	def _delLogPath(self, path):
		super(FilterPyinotify, self)._delLogPath(path)
		path_dir = dirname(path)
		prefix = _dirPrefix(path_dir)
		for k in list(self._watchFiles):
			if k.startswith(prefix):
				path_dir = None
				break
		if path_dir:
			# Remove watches for the directory
			# since there is no other monitored file under this directory
			self._delPending(path_dir)
			self._delDirWatcher(path_dir)

	def _startMonitor(self):
		prcevent = pyinotify.ProcessEvent()
		prcevent.process_default = self._handleEvent
		# timeout for pyinotify must be set in milliseconds (fail2ban time values are
		# floats contain seconds):
		self.__notifier = pyinotify.Notifier(self.__monitor,
			prcevent, timeout=self._maxWaitTime * 1000)

	def _waitEvents(self):
		# default pyinotify handling using Notifier:
		self.__notifier.process_events()

		# wait for events / timeout:
		def __check_events():
			return (
				not self.active
				or bool(self.__notifier.check_events(timeout=self._maxWaitTime * 1000))
				or (self._pendingMinTime and self._pending)
			)
		wres = Utils.wait_for(__check_events, min(self.sleeptime, self._pendingMinTime))
		if wres and self.active and not isinstance(wres, dict):
			self.__notifier.read_events()

	##
	# Clean-up: then stop the 'Notifier'

	def afterStop(self):
		try:
			if self.__notifier: # stop the notifier
				self.__notifier.stop()
				self.__notifier = None
		except AttributeError: # pragma: no cover
			if self.__notifier: raise

	##
	# Deallocates the resources used by pyinotify.

	def _cleanup(self):
		if self.__notifier:
			if Utils.wait_for(lambda: not self.__notifier, self.sleeptime * 10):
				self.__notifier = None
				self.__monitor = None
