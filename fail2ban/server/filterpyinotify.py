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
		self.__watchFiles = dict()
		self.__watchDirs = dict()
		self.__pending = dict()
		self.__pendingChkTime = 0
		self.__pendingNextTime = 0
		logSys.debug("Created FilterPyinotify")

	def callback(self, event, origin=''):
		logSys.log(7, "[%s] %sCallback for Event: %s", self.jailName, origin, event)
		path = event.pathname
		# check watching of this path:
		isWF = isWD = False
		if path in self.__watchDirs:
			isWD = True
		elif path in self.__watchFiles:
			isWF = True
		# fix pyinotify behavior with '-unknown-path' (if target not watched also):
		if (event.mask & pyinotify.IN_MOVE_SELF and 
				path.endswith('-unknown-path') and not isWF and not isWD
		):
			path = path[:-len('-unknown-path')]
			isWD = path in self.__watchDirs
		assumeNoDir = False
		if event.mask & ( pyinotify.IN_CREATE | pyinotify.IN_MOVED_TO ):
			# refresh watched dir (may be expected):
			if isWD:
				self._refreshWatcher(path, isDir=True)
				return
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
			# watch was removed for some reasons (log-rotate?):
			assumeNoDir = event.mask & (pyinotify.IN_MOVE_SELF | pyinotify.IN_DELETE_SELF)
			if isWD and (assumeNoDir or not os.path.isdir(path)):
				self._addPending(path, event, isDir=True)
			elif not isWF:
				for logpath in self.__watchDirs:
					if logpath.startswith(path + pathsep) and (assumeNoDir or not os.path.isdir(logpath)):
						self._addPending(logpath, event, isDir=True)
		if isWF and not os.path.isfile(path):
			self._addPending(path, event)
			return
		# do nothing if idle:
		if self.idle:
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
		self.getFailures(path)
		try:
			while True:
				ticket = self.failManager.toBan()
				self.jail.putFailTicket(ticket)
		except FailManagerEmpty:
			self.failManager.cleanup(MyTime.time())
		self.__modified = False

	def _addPending(self, path, reason, isDir=False):
		if path not in self.__pending:
			self.__pending[path] = [self.sleeptime / 10, isDir];
			self.__pendingNextTime = 0
			if isinstance(reason, pyinotify.Event):
				reason = [reason.maskname, reason.pathname]
			logSys.log(logging.MSG, "Log absence detected (possibly rotation) for %s, reason: %s of %s",
				path, *reason)

	def _delPending(self, path):
		try:
			del self.__pending[path]
		except KeyError: pass

	def _checkPending(self):
		if self.__pending:
			ntm = time.time()
			if ntm > self.__pendingNextTime:
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
				for path in found:
					try:
						del self.__pending[path]
					except KeyError: pass
				self.__pendingChkTime = time.time()
				self.__pendingNextTime = self.__pendingChkTime + minTime
				# process now because we'he missed it in monitoring:
				for path, isDir in found.iteritems():
					self._refreshWatcher(path, isDir=isDir)
					if isDir:
						for logpath in self.__watchFiles:
							if logpath.startswith(path + pathsep):
								if not os.path.isfile(logpath):
									self._addPending(logpath, ['FROM_PARDIR', path])
								else:
									self._refreshWatcher(logpath)
									self._process_file(logpath)
					else:
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

	def _delFileWatcher(self, path):
		try:
			wdInt = self.__watchFiles.pop(path)
			wd = self.__monitor.rm_watch(wdInt)
			if wd[wdInt]:
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
			self.__monitor.rm_watch(wdInt)
		except KeyError: # pragma: no cover
			pass
		logSys.debug("Removed monitor for the parent directory %s", path_dir)

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
		if not self._delFileWatcher(path):
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
		except Exception as e:
			logSys.error("Error in FilterPyinotify callback: %s",
				e, exc_info=logSys.getEffectiveLevel() <= logging.DEBUG)
		self.ticks += 1

	# slow check events while idle:
	def __check_events(self, *args, **kwargs):
		if self.idle:
			if Utils.wait_for(lambda: not self.active or not self.idle,
				self.sleeptime * 10, self.sleeptime
			):
				pass

		# check pending files/dirs (logrotate ready):
		if not self.idle:
			self._checkPending()

		self.ticks += 1
		return pyinotify.ThreadedNotifier.check_events(self.__notifier, *args, **kwargs)

	##
	# Main loop.
	#
	# Since all detection is offloaded to pyinotifier -- no manual
	# loop is necessary

	def run(self):
		prcevent = pyinotify.ProcessEvent()
		prcevent.process_default = self.__process_default
		## timeout for pyinotify must be set in milliseconds (our time values are floats contain seconds)
		self.__notifier = pyinotify.ThreadedNotifier(self.__monitor,
			prcevent, timeout=self.sleeptime * 1000)
		self.__notifier.check_events = self.__check_events
		self.__notifier.start()
		logSys.debug("[%s] filter started (pyinotifier)", self.jailName)
		return True

	##
	# Call super.stop() and then stop the 'Notifier'

	def stop(self):
		super(FilterPyinotify, self).stop()
		# Stop the notifier thread
		self.__notifier.stop()
		self.__notifier.stop = lambda *args: 0; # prevent dual stop

	##
	# Wait for exit with cleanup.

	def join(self):
		self.__cleanup()
		super(FilterPyinotify, self).join()
		logSys.debug("[%s] filter terminated (pyinotifier)", self.jailName)

	##
	# Deallocates the resources used by pyinotify.

	def __cleanup(self):
		if self.__notifier:
			self.__notifier.join()			# to not exit before notifier does
			self.__notifier = None
		self.__monitor = None
