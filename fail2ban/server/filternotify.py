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

"""Common base of the file backends driven by file system notifications
(`pyinotify`, `watchdog`).

It provides the handling of pending (absent) files and directories, e. g. by
log rotation, the main loop, and the adding and removing of log paths. The
backends implement the monitor specific parts.
"""

__author__ = "Cyril Jaquier, Lee Clemens, Yaroslav Halchenko, Fail2Ban Developers"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier, 2011-2012 Lee Clemens, 2012 Yaroslav Halchenko, 2026 Fail2Ban Developers"
__license__ = "GPL"

import logging
import os
from os.path import sep as pathsep

from .filter import FileFilter
from .mytime import time
from .utils import Utils
from ..helpers import getLogger

# Gets the instance of the logger.
logSys = getLogger(__name__)


def _dirPrefix(path_dir):
	"""Returns the prefix of all paths below the directory."""
	return path_dir if path_dir.endswith(pathsep) else path_dir + pathsep


class FileNotifyFilter(FileFilter):
	"""Base of the log reader classes using file system notifications.

	Subclasses implement:
	  - `_startMonitor()` - start the monitor (invoked in the filter thread),
	  - `_waitEvents()` - wait for events (up to `_maxWaitTime`) and process them
	    via `_handleEvent`,
	  - `callback(event, origin)` - handle a single event,
	  - `_addFileWatcher(path)`, `_delFileWatcher(path)` - start and stop the
	    monitoring of a log file (including its directory),
	  - `_refreshFileWatcher(path)`, `_refreshDirWatcher(path_dir)` - renew the
	    monitoring of a (re)appeared file or directory,
	and may overwrite `_wakeup()` (interrupt the waiting for events), `_dirLost()`,
	`_cleanup()` and `afterStop()`.
	"""

	# name of the monitor for log messages:
	_monitorName = None

	def __init__(self, jail, **kwargs):
		FileFilter.__init__(self, jail, **kwargs)
		# monitored files and watched directories: path -> backend specific value:
		self._watchFiles = dict()
		self._watchDirs = dict()
		# pending (absent) files and directories: path -> [retard time, isDir]:
		self._pending = dict()
		self._pendingChkTime = 0
		self._pendingMinTime = 60

	def _process_file(self, path):
		"""Process a given file"""
		if not self.idle:
			self.getFailures(path)

	def _handleEvent(self, event):
		"""Invokes the callback for an event (the errors are logged and counted)."""
		try:
			self.callback(event, origin='Default ')
		except Exception as e: # pragma: no cover
			logSys.error("Error in %s callback: %s", self.__class__.__name__,
				e, exc_info=logSys.getEffectiveLevel() <= logging.DEBUG)
			# incr common error counter:
			self.commonError()
		self.ticks += 1

	##
	# Pending files and directories (absent, e. g. by log rotation).

	def _addPending(self, path, reason, isDir=False):
		if path not in self._pending:
			self._pending[path] = [Utils.DEFAULT_SLEEP_INTERVAL, isDir]
			self._pendingMinTime = 0
			logSys.log(logging.MSG, "Log absence detected (possibly rotation) for %s, reason: %s of %s",
				path, *reason)

	def _delPending(self, path):
		try:
			del self._pending[path]
		except KeyError: pass

	def getPendingPaths(self):
		return list(self._pending.keys())

	def _checkPending(self):
		if not self._pending:
			self._pendingMinTime = 60
			return
		ntm = time.time()
		if ntm < self._pendingChkTime + self._pendingMinTime:
			return
		found = {}
		minTime = 60
		for path, (retardTM, isDir) in list(self._pending.items()):
			if ntm - self._pendingChkTime < retardTM:
				if minTime > retardTM: minTime = retardTM
				continue
			chkpath = os.path.isdir if isDir else os.path.isfile
			if not chkpath(path): # not found - prolong for next time
				if retardTM < 60: retardTM *= 2
				if minTime > retardTM: minTime = retardTM
				try:
					self._pending[path][0] = retardTM
				except KeyError: pass
				continue
			logSys.log(logging.MSG, "Log presence detected for %s %s",
				"directory" if isDir else "file", path)
			found[path] = isDir
		self._pendingChkTime = time.time()
		self._pendingMinTime = minTime
		# process now because we've missed it in monitoring:
		for path, isDir in found.items():
			self._delPending(path)
			if isDir:
				self._dirFound(path)
				continue
			# isDir is None for initial processing only (monitor is up-to-date):
			if isDir is not None:
				self._refreshFileWatcher(path)
			# process (possibly no old events for it from watcher):
			self._process_file(path)

	def _dirFound(self, path_dir):
		"""Directory (re)appeared: refresh its watcher and process the files below it."""
		self._delPending(path_dir)
		self._refreshDirWatcher(path_dir)
		prefix = _dirPrefix(path_dir)
		for logpath in list(self._watchFiles):
			if logpath.startswith(prefix):
				# if still no file - add to pending, otherwise refresh and process:
				if not os.path.isfile(logpath):
					self._addPending(logpath, ('FROM_PARDIR', path_dir))
				else:
					self._refreshFileWatcher(logpath)
					self._process_file(logpath)

	def _dirLost(self, path_dir, reason):
		"""Directory removed or moved away: wait for it."""
		self._addPending(path_dir, reason, isDir=True)

	def _subDirsLost(self, path, reason, assumeNoDir=False):
		"""Directory removed or moved away: handle the watched directories below it."""
		prefix = _dirPrefix(path)
		for path_dir in list(self._watchDirs):
			if path_dir.startswith(prefix) and (assumeNoDir or not os.path.isdir(path_dir)):
				self._dirLost(path_dir, reason)

	##
	# Add a log file path
	#
	# @param path log file path

	def _addLogPath(self, path):
		self._addFileWatcher(path)
		# retard until filter gets started, isDir=None signals special case: process file only (don't need to refresh monitor):
		self._addPending(path, ('INITIAL', path), isDir=None)
		# notify (wake up if in waiting):
		if self.active:
			self._wakeup()

	##
	# Delete a log path
	#
	# @param path the log file to delete

	def _delLogPath(self, path):
		self._delPending(path)
		if not self._delFileWatcher(path): # pragma: no cover
			logSys.error("Failed to remove watch on path: %s", path)

	def _wakeup(self):
		"""Signals the main loop to check the pending files soon."""
		self._pendingMinTime = 0

	@property
	def _maxWaitTime(self):
		# max 0.5 sec (additionally regards pending check time):
		return min(self.sleeptime, 0.5, self._pendingMinTime)

	##
	# Main loop.

	def run(self):
		self._startMonitor()
		logSys.debug("[%s] filter started (%s)", self.jailName, self._monitorName)
		while self.active:
			try:

				# slow check events while idle:
				if self.idle:
					if Utils.wait_for(lambda: not self.active or not self.idle,
						min(self.sleeptime * 10, self._pendingMinTime),
						min(self.sleeptime, self._pendingMinTime)
					):
						if not self.active: break

				# wait for events / timeout and process them:
				self._waitEvents()
				if not self.active: break

				self.ticks += 1

				# check pending files/dirs (logrotate ready):
				if self.idle:
					continue
				self._checkPending()
				if self.ticks % 10 == 0:
					self.performSvc()

			except Exception as e: # pragma: no cover
				if not self.active: # if not active - error by stop...
					break
				logSys.error("Caught unhandled exception in main cycle: %r", e,
					exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)
				# incr common error counter:
				self.commonError("unhandled", e)

		logSys.debug("[%s] filter exited (%s)", self.jailName, self._monitorName)
		self.done()

		return True

	def _cleanup(self):
		"""Releases the resources of the monitor (invoked in join)."""
		pass

	##
	# Wait for exit with cleanup.

	def join(self):
		self.join = lambda *args: 0
		self._cleanup()
		super(FileNotifyFilter, self).join()
		logSys.debug("[%s] filter terminated (%s)", self.jailName, self._monitorName)
