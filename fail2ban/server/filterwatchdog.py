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

import os
import queue
from os.path import dirname, realpath

from .filternotify import FileNotifyFilter
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


class FilterWatchdog(FileNotifyFilter):
	"""Log reader class using watchdog to detect modifications of the log files."""

	_monitorName = 'watchdog'

	def __init__(self, jail, **kwargs):
		FileNotifyFilter.__init__(self, jail, **kwargs)
		self.__events = queue.Queue()
		self.__handler = _EventBridge(self.__events)
		self.__observer = None
		# monitored files (self._watchFiles): path -> real path (target of symlink or the path itself);
		# watched directories (self._watchDirs): path -> ObservedWatch or None (not scheduled);
		# real path -> set of monitored paths (to map events of symlink targets):
		self.__realFiles = dict()
		logSys.debug("Created FilterWatchdog")

	def _wakeup(self):
		self.__events.put(_WAKEUP)

	##
	# Event handling (filter thread).

	def _monitoredPaths(self, path):
		"""Returns the monitored log paths an event path refers to."""
		if path in self._watchFiles:
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
			if path in self._watchDirs:
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
					self._subDirsLost(path, (evtype, path))
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

	##
	# Watchers.

	def _dirLost(self, path_dir, reason):
		"""Directory removed or moved away: stop its watcher and wait for it."""
		# watchdog stops the emitter of a removed directory, but keeps it registered
		# (and would follow a moved directory), so unschedule it here:
		watch = self._watchDirs.get(path_dir)
		if watch is not None:
			self._watchDirs[path_dir] = None
			self._unschedule(watch)
		super(FilterWatchdog, self)._dirLost(path_dir, reason)

	def _neededDirs(self):
		dirs = set()
		for path, real in self._watchFiles.items():
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
		for path_dir in list(self._watchDirs):
			if path_dir not in needed:
				self._delPending(path_dir)
				self._delDirWatcher(path_dir)
		for path_dir in needed:
			if path_dir not in self._watchDirs:
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
		self._watchDirs[path_dir] = watch
		if watch is not None:
			logSys.debug("Added monitor for the directory %s", path_dir)

	def _delDirWatcher(self, path_dir):
		try:
			watch = self._watchDirs.pop(path_dir)
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
		if path_dir in self._watchDirs:
			self._delDirWatcher(path_dir)
		self._addDirWatcher(path_dir)

	def _addFileWatcher(self, path):
		real = realpath(path)
		self._watchFiles[path] = real
		if real != path:
			self.__realFiles.setdefault(real, set()).add(path)
		self._syncDirWatchers()
		logSys.debug("Added file watcher for %s", path)

	def _delFileWatcher(self, path):
		try:
			real = self._watchFiles.pop(path)
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
		real = self._watchFiles.get(path)
		if real is not None and real != realpath(path):
			self._delFileWatcher(path)
			self._addFileWatcher(path)

	def _waitEvents(self):
		"""Waits for events (up to max wait time) and processes all available events."""
		timeout = self._maxWaitTime
		try:
			event = self.__events.get(timeout=timeout) if timeout > 0 else self.__events.get_nowait()
		except queue.Empty:
			return
		while True:
			if event is not _WAKEUP:
				self._handleEvent(event)
			if not self.active:
				return
			try:
				event = self.__events.get_nowait()
			except queue.Empty:
				return

	def _startMonitor(self):
		self.__observer = Observer()
		self.__observer.start()
		logSys.debug("[%s] watchdog observer: %s", self.jailName,
			self.__observer.__class__.__name__)
		# schedule watchers registered before start:
		for path_dir in list(self._watchDirs):
			self._refreshDirWatcher(path_dir)

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
