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
import os
from os.path import dirname, sep as pathsep

import pyinotify

from .failmanager import FailManagerEmpty
from .filter import FileFilter
from .mytime import MyTime, time
from .utils import Utils
from ..helpers import getLogger


if not hasattr(pyinotify, '__version__') \
  or LooseVersion(pyinotify.__version__) < '0.8.3': # pragma: no cover
  raise ImportError("Fail2Ban requires pyinotify >= 0.8.3")

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
		self.__notifier = None
		self.__watchFiles = dict()
		self.__watchDirs = dict()
		self.__pending = dict()
		self.__pendingChkTime = 0
		self.__pendingMinTime = 60
		logSys.debug("Created FilterPyinotify")

	def callback(self, event, origin=''):
		logSys.log(7, "[%s] %sCallback for Event: %s", self.jailName, origin, event)
		path = event.pathname
		# check watching of this path:
		isWF = False
		isWD = path in self.__watchDirs
		if not isWD and path in self.__watchFiles:
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
			self._refreshWatcher(path)
		elif event.mask & (pyinotify.IN_IGNORED | pyinotify.IN_MOVE_SELF | pyinotify.IN_DELETE_SELF):
			assumeNoDir = event.mask & (pyinotify.IN_MOVE_SELF | pyinotify.IN_DELETE_SELF)
			# fix pyinotify behavior with '-unknown-path' (if target not watched also):
			if (assumeNoDir and 
					path.endswith('-unknown-path') and not isWF and not isWD
			):
				path = path[:-len('-unknown-path')]
				isWD = path in self.__watchDirs
			# watch was removed for some reasons (log-rotate?):
			if isWD and (assumeNoDir or not os.path.isdir(path)):
				self._addPending(path, event, isDir=True)
			elif not isWF: # pragma: no cover (assume too sporadic)
				for logpath in self.__watchDirs:
					if logpath.startswith(path + pathsep) and (assumeNoDir or not os.path.isdir(logpath)):
						self._addPending(logpath, event, isDir=True)
		if isWF and not os.path.isfile(path):
			self._addPending(path, event)
			return
		# do nothing if idle:
		if self.idle: # pragma: no cover (too sporadic to get idle in callback)
			return
		# be sure we process a file:
		if not isWF:
			logSys.debug("Ignoring event (%s) of %s we do not monitor", event.maskname, path)
			return
		self._process_file(path)

	def _process_file(self, path):
		"""Process a given file

		TODO -- RF:
		this is a common logic and must be shared/provided by FileFilter
		"""
		if not self.idle:
			self.getFailures(path)
			self.performBan()
			self.__modified = False

	def _addPending(self, path, reason, isDir=False):
		if path not in self.__pending:
			self.__pending[path] = [Utils.DEFAULT_SLEEP_INTERVAL, isDir];
			self.__pendingMinTime = 0
			if isinstance(reason, pyinotify.Event):
				reason = [reason.maskname, reason.pathname]
			logSys.log(logging.MSG, "Log absence detected (possibly rotation) for %s, reason: %s of %s",
				path, *reason)

	def _delPending(self, path):
		try:
			del self.__pending[path]
		except KeyError: pass

	def getPendingPaths(self):
		return self.__pending.keys()

	def _checkPending(self):
		if not self.__pending:
			return
		ntm = time.time()
		if ntm < self.__pendingChkTime + self.__pendingMinTime:
			return
		found = {}
		minTime = 60
		for path, (retardTM, isDir) in self.__pending.iteritems():
			if ntm - self.__pendingChkTime < retardTM:
				if minTime > retardTM: minTime = retardTM
				continue
			chkpath = os.path.isdir if isDir else os.path.isfile
			if not chkpath(path): # not found - prolong for next time
				if retardTM < 60: retardTM *= 2
				if minTime > retardTM: minTime = retardTM
				self.__pending[path][0] = retardTM
				continue
			logSys.log(logging.MSG, "Log presence detected for %s %s", 
				"directory" if isDir else "file", path)
			found[path] = isDir
		self.__pendingChkTime = time.time()
		self.__pendingMinTime = minTime
		# process now because we've missed it in monitoring:
		for path, isDir in found.iteritems():
			self._delPending(path)
			# refresh monitoring of this:
			self._refreshWatcher(path, isDir=isDir)
			if isDir:
				# check all files belong to this dir:
				for logpath in self.__watchFiles:
					if logpath.startswith(path + pathsep):
						# if still no file - add to pending, otherwise refresh and process:
						if not os.path.isfile(logpath):
							self._addPending(logpath, ('FROM_PARDIR', path))
						else:
							self._refreshWatcher(logpath)
							self._process_file(logpath)
			else:
				# process (possibly no old events for it from watcher):
				self._process_file(path)

	def _refreshWatcher(self, oldPath, newPath=None, isDir=False):
		if not newPath: newPath = oldPath
		# we need to substitute the watcher with a new one, so first
		# remove old one and then place a new one
		if not isDir:
			self._delFileWatcher(oldPath)
			self._addFileWatcher(newPath)
		else:
			self._delDirWatcher(oldPath)
			self._addDirWatcher(newPath)

	def _addFileWatcher(self, path):
		# we need to watch also the directory for IN_CREATE
		self._addDirWatcher(dirname(path))
		# add file watcher:
		wd = self.__monitor.add_watch(path, pyinotify.IN_MODIFY)
		self.__watchFiles.update(wd)
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
			wdInt = self.__watchFiles.pop(path)
			if not self._delWatch(wdInt):
				logSys.debug("Non-existing file watcher %r for file %s", wdInt, path)
			logSys.debug("Removed file watcher for %s", path)
			return True
		except KeyError: # pragma: no cover
			pass
		return False

	def _addDirWatcher(self, path_dir):
		# Add watch for the directory:
		if path_dir not in self.__watchDirs:
			self.__watchDirs.update(
				self.__monitor.add_watch(path_dir, pyinotify.IN_CREATE | 
					pyinotify.IN_MOVED_TO | pyinotify.IN_MOVE_SELF |
					pyinotify.IN_DELETE_SELF | pyinotify.IN_ISDIR))
			logSys.debug("Added monitor for the parent directory %s", path_dir)

	def _delDirWatcher(self, path_dir):
		# Remove watches for the directory:
		try:
			wdInt = self.__watchDirs.pop(path_dir)
			if not self._delWatch(wdInt): # pragma: no cover
				logSys.debug("Non-existing file watcher %r for directory %s", wdInt, path_dir)
			logSys.debug("Removed monitor for the parent directory %s", path_dir)
		except KeyError: # pragma: no cover
			pass

	##
	# Add a log file path
	#
	# @param path log file path

	def _addLogPath(self, path):
		self._addFileWatcher(path)
		self._process_file(path)

    ##
	# Delete a log path
	#
	# @param path the log file to delete

	def _delLogPath(self, path):
		if not self._delFileWatcher(path): # pragma: no cover
			logSys.error("Failed to remove watch on path: %s", path)
		self._delPending(path)

		path_dir = dirname(path)
		for k in self.__watchFiles:
			if k.startswith(path_dir + pathsep):
				path_dir = None
				break
		if path_dir:
			# Remove watches for the directory
			# since there is no other monitored file under this directory
			self._delDirWatcher(path_dir)
			self._delPending(path_dir)

	# pyinotify.ProcessEvent default handler:
	def __process_default(self, event):
		try:
			self.callback(event, origin='Default ')
		except Exception as e: # pragma: no cover
			logSys.error("Error in FilterPyinotify callback: %s",
				e, exc_info=logSys.getEffectiveLevel() <= logging.DEBUG)
			# incr common error counter:
			self.commonError()
		self.ticks += 1

	@property
	def __notify_maxtout(self):
		# timeout for pyinotify must be set in milliseconds (fail2ban time values are 
		# floats contain seconds), max 0.5 sec (additionally regards pending check time)
		return min(self.sleeptime, 0.5, self.__pendingMinTime) * 1000

	##
	# Main loop.
	#
	# Since all detection is offloaded to pyinotifier -- no manual
	# loop is necessary

	def run(self):
		prcevent = pyinotify.ProcessEvent()
		prcevent.process_default = self.__process_default
		self.__notifier = pyinotify.Notifier(self.__monitor,
			prcevent, timeout=self.__notify_maxtout)
		logSys.debug("[%s] filter started (pyinotifier)", self.jailName)
		while self.active:
			try:

				# slow check events while idle:
				if self.idle:
					if Utils.wait_for(lambda: not self.active or not self.idle,
						min(self.sleeptime * 10, self.__pendingMinTime), 
						min(self.sleeptime, self.__pendingMinTime)
					):
						if not self.active: break

				# default pyinotify handling using Notifier:
				self.__notifier.process_events()

				# wait for events / timeout:
				notify_maxtout = self.__notify_maxtout
				def __check_events():
					return not self.active or self.__notifier.check_events(timeout=notify_maxtout)
				if Utils.wait_for(__check_events, min(self.sleeptime, self.__pendingMinTime)):
					if not self.active: break
					self.__notifier.read_events()

				# check pending files/dirs (logrotate ready):
				if not self.idle:
					self._checkPending()

			except Exception as e: # pragma: no cover
				if not self.active: # if not active - error by stop...
					break
				logSys.error("Caught unhandled exception in main cycle: %r", e,
					exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)
				# incr common error counter:
				self.commonError()
			
			self.ticks += 1

		logSys.debug("[%s] filter exited (pyinotifier)", self.jailName)
		self.__notifier = None

		return True

	##
	# Call super.stop() and then stop the 'Notifier'

	def stop(self):
		# stop filter thread:
		super(FilterPyinotify, self).stop()
		try:
			if self.__notifier: # stop the notifier
				self.__notifier.stop()
		except AttributeError: # pragma: no cover
			if self.__notifier: raise

	##
	# Wait for exit with cleanup.

	def join(self):
		self.join = lambda *args: 0
		self.__cleanup()
		super(FilterPyinotify, self).join()
		logSys.debug("[%s] filter terminated (pyinotifier)", self.jailName)

	##
	# Deallocates the resources used by pyinotify.

	def __cleanup(self):
		if self.__notifier:
			if Utils.wait_for(lambda: not self.__notifier, self.sleeptime * 10):
				self.__notifier = None
				self.__monitor = None
