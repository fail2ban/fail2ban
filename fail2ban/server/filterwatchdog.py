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

"""File monitoring backend based on the `watchdog` module.

In contrast to the `pyinotify` backend (inotify only), watchdog provides native
file system notifications on several platforms: inotify (Linux, FreeBSD 15+),
kqueue (other BSD), FSEvents (macOS) and ReadDirectoryChangesW (Windows).

Only the parent directories of the monitored log files are watched (non
recursively); events are filtered against the set of monitored files.
Symlinked log files are supported by additionally watching the directory of
the link target.
The parents of these directories are watched as well, because watchdog does
not report a move of the watched directory itself: the watcher of the parent
notifies about removal, move and (re)creation of the directory.

The observer of watchdog dispatches events in its own thread, so they are
handed over via a queue and processed in the filter thread (run loop), which
keeps the processing of failures single-threaded like in other backends.
"""

__author__ = "Fail2Ban Developers"
__copyright__ = "Copyright (c) 2026 Fail2Ban Developers"
__license__ = "GPL"

import logging
import os
import queue
from os.path import dirname, realpath, sep as pathsep

from .filter import FileFilter
from .mytime import time
from .utils import Utils
from ..helpers import getLogger

# Platform specific observers of watchdog may fail with other errors than ImportError
# (e. g. AttributeError for missing kqueue constants of module select); convert them
# to ImportError, so backend 'auto' can continue with the next backend:
try:
	from watchdog.events import (
		EVENT_TYPE_CREATED, EVENT_TYPE_DELETED, EVENT_TYPE_MODIFIED, EVENT_TYPE_MOVED,
		FileSystemEventHandler)
	from watchdog.observers import Observer
	from watchdog.observers.polling import PollingObserver
except ImportError: # pragma: no cover
	raise
except Exception as e: # pragma: no cover
	raise ImportError("Watchdog is probably not functional on this system: %r" % e)

# Watchdog falls back to a polling observer if no native API is available on
# this platform; it makes no sense to use it instead of the fail2ban polling
# backend, so signal to try the next backend:
if issubclass(Observer, PollingObserver): # pragma: no cover
	raise ImportError("Watchdog has no native file system observer on this platform")

# Gets the instance of the logger.
logSys = getLogger(__name__)

# Sentinel to wake up the run loop (e. g. new log path, stop):
_WAKEUP = object()


class _EventBridge(FileSystemEventHandler):
	"""Hands over events from the watchdog observer thread to the filter thread."""

	def __init__(self, events):
		super(_EventBridge, self).__init__()
		self._events = events

	def dispatch(self, event):
		# directory modifications are irrelevant (the changed entries generate own events):
		if event.is_directory and event.event_type == EVENT_TYPE_MODIFIED:
			return
		self._events.put(event)


class FilterWatchdog(FileFilter):
	"""Log reader class using watchdog to detect modifications of the log files."""

	def __init__(self, jail, **kwargs):
		FileFilter.__init__(self, jail, **kwargs)
		self.__events = queue.Queue()
		self.__handler = _EventBridge(self.__events)
		self.__observer = None
		# monitored files: path -> real path (target of symlink or the path itself):
		self.__watchFiles = dict()
		# real path -> set of monitored paths (to map events of symlink targets):
		self.__realFiles = dict()
		# watched directories: path -> ObservedWatch or None (not scheduled)
		self.__watchDirs = dict()
		self.__pending = dict()
		self.__pendingChkTime = 0
		self.__pendingMinTime = 60
		logSys.debug("Created FilterWatchdog")

	def _wakeup(self):
		self.__events.put(_WAKEUP)

	##
	# Event handling (filter thread).

	def _monitoredPaths(self, path):
		"""Returns the monitored log paths an event path refers to."""
		if path in self.__watchFiles:
			return (path,)
		return tuple(self.__realFiles.get(path, ()))

	def callback(self, event, origin=''):
		logSys.log(4, "[%s] %sCallback for Event: %s", self.jailName, origin, event)
		evtype = event.event_type
		paths = [(event.src_path, evtype)]
		if evtype == EVENT_TYPE_MOVED:
			# moved = deleted source + created destination:
			paths = [(event.src_path, EVENT_TYPE_DELETED)]
			if event.dest_path:
				paths.append((event.dest_path, EVENT_TYPE_CREATED))
		for path, evtype in paths:
			if not path:
				continue
			path = os.fsdecode(path)
			if path in self.__watchDirs:
				# watched directory itself (event from its own watcher or the watcher of its parent):
				if not os.path.isdir(path):
					# removed or moved away:
					self._dirLost(path, (evtype, path))
				elif evtype in (EVENT_TYPE_CREATED, EVENT_TYPE_DELETED):
					# (re)created or moved in (or obsolete removal, since it exists again):
					self._dirFound(path)
				continue
			if event.is_directory:
				# a directory containing watched directories may be removed or moved:
				if evtype == EVENT_TYPE_DELETED:
					for wdir in list(self.__watchDirs):
						if wdir.startswith(path + pathsep) and not os.path.isdir(wdir):
							self._dirLost(wdir, (evtype, path))
				else:
					logSys.log(5, "Ignoring event (%s) of directory %s", evtype, path)
				continue
			logpaths = self._monitoredPaths(path)
			if not logpaths:
				logSys.log(5, "Ignoring event (%s) of %s we do not monitor", evtype, path)
				continue
			for logpath in logpaths:
				self._processEvent(logpath, evtype, path)

	def _processEvent(self, logpath, evtype, path):
		if not os.path.isfile(logpath):
			self._addPending(logpath, (evtype, path))
			return
		if evtype == EVENT_TYPE_CREATED:
			# (re)created - the target of symlink may be changed:
			self._refreshFileWatcher(logpath)
		elif evtype not in (EVENT_TYPE_MODIFIED, EVENT_TYPE_DELETED):
			# opened, closed, attrib, etc:
			return
		self._process_file(logpath)

	def _process_file(self, path):
		"""Process a given file"""
		if not self.idle:
			self.getFailures(path)

	##
	# Pending files and directories (absent, e. g. by log-rotation).

	def _addPending(self, path, reason, isDir=False):
		if path not in self.__pending:
			self.__pending[path] = [Utils.DEFAULT_SLEEP_INTERVAL, isDir]
			self.__pendingMinTime = 0
			logSys.log(logging.MSG, "Log absence detected (possibly rotation) for %s, reason: %s of %s",
				path, *reason)

	def _delPending(self, path):
		try:
			del self.__pending[path]
		except KeyError: pass

	def getPendingPaths(self):
		return list(self.__pending.keys())

	def _checkPending(self):
		if not self.__pending:
			self.__pendingMinTime = 60
			return
		ntm = time.time()
		if ntm < self.__pendingChkTime + self.__pendingMinTime:
			return
		found = {}
		minTime = 60
		for path, (retardTM, isDir) in list(self.__pending.items()):
			if ntm - self.__pendingChkTime < retardTM:
				if minTime > retardTM: minTime = retardTM
				continue
			chkpath = os.path.isdir if isDir else os.path.isfile
			if not chkpath(path): # not found - prolong for next time
				if retardTM < 60: retardTM *= 2
				if minTime > retardTM: minTime = retardTM
				try:
					self.__pending[path][0] = retardTM
				except KeyError: pass
				continue
			logSys.log(logging.MSG, "Log presence detected for %s %s",
				"directory" if isDir else "file", path)
			found[path] = isDir
		self.__pendingChkTime = time.time()
		self.__pendingMinTime = minTime
		# process now because we've missed it in monitoring:
		for path, isDir in found.items():
			self._delPending(path)
			if isDir:
				self._dirFound(path)
			else:
				# isDir is None for initial processing only (monitor is up-to-date):
				if isDir is not None:
					self._refreshFileWatcher(path)
				# process (possibly no old events for it from watcher):
				self._process_file(path)

	def _dirFound(self, path_dir):
		"""Directory (re)appeared: refresh its watcher and process the files below it."""
		self._delPending(path_dir)
		self._refreshDirWatcher(path_dir)
		prefix = path_dir if path_dir.endswith(pathsep) else path_dir + pathsep
		for logpath in list(self.__watchFiles):
			if logpath.startswith(prefix):
				# if still no file - add to pending, otherwise refresh and process:
				if not os.path.isfile(logpath):
					self._addPending(logpath, ('FROM_PARDIR', path_dir))
				else:
					self._refreshFileWatcher(logpath)
					self._process_file(logpath)

	def _dirLost(self, path_dir, reason):
		"""Directory removed or moved away: stop its watcher and wait for it."""
		# watchdog stops the emitter of a removed directory, but keeps it registered
		# (and would follow a moved directory), so unschedule it here:
		watch = self.__watchDirs.get(path_dir)
		if watch is not None:
			self.__watchDirs[path_dir] = None
			self._unschedule(watch)
		self._addPending(path_dir, reason, isDir=True)

	##
	# Watchers.

	def _neededDirs(self):
		dirs = set()
		for path, real in self.__watchFiles.items():
			dirs.add(dirname(path))
			dirs.add(dirname(real))
		# watch the parents too, to get notified about removal, move or (re)creation
		# of these directories (watchdog does not report a move of the watched directory itself):
		for path_dir in list(dirs):
			parent = dirname(path_dir)
			if parent != path_dir:
				dirs.add(parent)
		return dirs

	def _syncDirWatchers(self):
		"""Adds or removes directory watchers according to the monitored files."""
		needed = self._neededDirs()
		for path_dir in list(self.__watchDirs):
			if path_dir not in needed:
				self._delPending(path_dir)
				self._delDirWatcher(path_dir)
		for path_dir in needed:
			if path_dir not in self.__watchDirs:
				self._addDirWatcher(path_dir)

	def _addDirWatcher(self, path_dir):
		watch = None
		observer = self.__observer
		# schedule only if observer is running (otherwise it'd be scheduled on start):
		if observer is not None:
			if os.path.isdir(path_dir):
				try:
					watch = observer.schedule(self.__handler, path_dir, recursive=False)
				except OSError as e:
					logSys.debug("Unable to monitor directory %s: %s", path_dir, e)
			if watch is None:
				# wait for it (the watcher of its parent notifies if it gets created):
				self._addPending(path_dir, ('NOT_FOUND', path_dir), isDir=True)
		self.__watchDirs[path_dir] = watch
		if watch is not None:
			logSys.debug("Added monitor for the directory %s", path_dir)

	def _delDirWatcher(self, path_dir):
		try:
			watch = self.__watchDirs.pop(path_dir)
		except KeyError: # pragma: no cover
			return False
		self._unschedule(watch)
		logSys.debug("Removed monitor for the directory %s", path_dir)
		return True

	def _unschedule(self, watch):
		if watch is None or self.__observer is None:
			return
		try:
			self.__observer.unschedule(watch)
		except (KeyError, OSError) as e: # pragma: no cover - already removed
			logSys.debug("Remove watch causes: %r", e)

	def _refreshDirWatcher(self, path_dir):
		if path_dir in self.__watchDirs:
			self._delDirWatcher(path_dir)
		self._addDirWatcher(path_dir)

	def _addFileWatcher(self, path):
		real = realpath(path)
		self.__watchFiles[path] = real
		if real != path:
			self.__realFiles.setdefault(real, set()).add(path)
		self._syncDirWatchers()
		logSys.debug("Added file watcher for %s", path)

	def _delFileWatcher(self, path):
		try:
			real = self.__watchFiles.pop(path)
		except KeyError: # pragma: no cover
			return False
		paths = self.__realFiles.get(real)
		if paths is not None:
			paths.discard(path)
			if not paths:
				del self.__realFiles[real]
		self._syncDirWatchers()
		logSys.debug("Removed file watcher for %s", path)
		return True

	def _refreshFileWatcher(self, path):
		"""Refreshes the file watcher (target of symlink may be changed)."""
		real = self.__watchFiles.get(path)
		if real is not None and real != realpath(path):
			self._delFileWatcher(path)
			self._addFileWatcher(path)

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

	@property
	def __maxtout(self):
		# max 0.5 sec (additionally regards pending check time):
		return min(self.sleeptime, 0.5, self.__pendingMinTime)

	def __processEvents(self, timeout):
		"""Waits for events up to timeout and processes all available events."""
		try:
			event = self.__events.get(timeout=timeout) if timeout > 0 else self.__events.get_nowait()
		except queue.Empty:
			return
		while True:
			if event is not _WAKEUP:
				try:
					self.callback(event, origin='Default ')
				except Exception as e: # pragma: no cover
					logSys.error("Error in FilterWatchdog callback: %s",
						e, exc_info=logSys.getEffectiveLevel() <= logging.DEBUG)
					# incr common error counter:
					self.commonError()
				self.ticks += 1
			if not self.active:
				return
			try:
				event = self.__events.get_nowait()
			except queue.Empty:
				return

	def __startObserver(self):
		self.__observer = Observer()
		self.__observer.start()
		# schedule watchers registered before start:
		for path_dir in list(self.__watchDirs):
			self._refreshDirWatcher(path_dir)

	##
	# Main loop.

	def run(self):
		self.__startObserver()
		logSys.debug("[%s] filter started (watchdog %s)", self.jailName,
			self.__observer.__class__.__name__)
		while self.active:
			try:

				# slow check events while idle:
				if self.idle:
					if Utils.wait_for(lambda: not self.active or not self.idle,
						min(self.sleeptime * 10, self.__pendingMinTime),
						min(self.sleeptime, self.__pendingMinTime)
					):
						if not self.active: break

				# wait for events / timeout and process them:
				self.__processEvents(self.__maxtout)
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

		logSys.debug("[%s] filter exited (watchdog)", self.jailName)
		self.done()

		return True

	##
	# Clean-up: stop monitoring and the observer.

	def afterStop(self):
		super(FilterWatchdog, self).afterStop()
		observer, self.__observer = self.__observer, None
		if observer is not None:
			try:
				observer.stop()
				observer.join(self.sleeptime * 10)
			except RuntimeError: # pragma: no cover - not started
				pass
		self._wakeup()

	##
	# Wait for exit with cleanup.

	def join(self):
		self.join = lambda *args: 0
		super(FilterWatchdog, self).join()
		logSys.debug("[%s] filter terminated (watchdog)", self.jailName)
