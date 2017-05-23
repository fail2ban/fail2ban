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

# Author: Cyril Jaquier
# 

__author__ = "Cyril Jaquier"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import threading
from threading import Lock, RLock
import logging
import logging.handlers
import os
import signal
import stat
import sys

from .jails import Jails
from .filter import FileFilter, JournalFilter
from .transmitter import Transmitter
from .asyncserver import AsyncServer, AsyncServerException
from .. import version
from ..helpers import getLogger, str2LogLevel, getVerbosityFormat, excepthook

# Gets the instance of the logger.
logSys = getLogger(__name__)

DEF_SYSLOGSOCKET = "auto"
DEF_LOGLEVEL = "INFO"
DEF_LOGTARGET = "STDOUT"

try:
	from .database import Fail2BanDb
except ImportError: # pragma: no cover
	# Dont print error here, as database may not even be used
	Fail2BanDb = None


def _thread_name():
	return threading.current_thread().__class__.__name__


class Server:
	
	def __init__(self, daemon=False):
		self.__loggingLock = Lock()
		self.__lock = RLock()
		self.__jails = Jails()
		self.__db = None
		self.__daemon = daemon
		self.__transm = Transmitter(self)
		self.__reload_state = {}
		#self.__asyncServer = AsyncServer(self.__transm)
		self.__asyncServer = None
		self.__logLevel = None
		self.__logTarget = None
		self.__verbose = None
		self.__syslogSocket = None
		self.__autoSyslogSocketPaths = {
			'Darwin':  '/var/run/syslog',
			'FreeBSD': '/var/run/log',
			'Linux': '/dev/log',
		}
		self.__prev_signals = {}

	def __sigTERMhandler(self, signum, frame): # pragma: no cover - indirect tested
		logSys.debug("Caught signal %d. Exiting", signum)
		self.quit()
	
	def __sigUSR1handler(self, signum, fname): # pragma: no cover - indirect tested
		logSys.debug("Caught signal %d. Flushing logs", signum)
		self.flushLogs()

	def _rebindSignal(self, s, new):
		"""Bind new signal handler while storing old one in _prev_signals"""
		self.__prev_signals[s] = signal.getsignal(s)
		signal.signal(s, new)

	def start(self, sock, pidfile, force=False, conf={}):
		# First set the mask to only allow access to owner
		os.umask(0077)
		# Second daemonize before logging etc, because it will close all handles:
		if self.__daemon: # pragma: no cover
			logSys.info("Starting in daemon mode")
			ret = self.__createDaemon()
			# If forked parent - return here (parent process will configure server later):
			if ret is None:
				return False
			# If error:
			if not ret[0]:
				err = "Could not create daemon %s", ret[1:]
				logSys.error(err)
				raise ServerInitializationError(err)
			# We are daemon.
		
		# Set all logging parameters (or use default if not specified):
		self.__verbose = conf.get("verbose", None)
		self.setSyslogSocket(conf.get("syslogsocket", 
			self.__syslogSocket if self.__syslogSocket is not None else DEF_SYSLOGSOCKET))
		self.setLogLevel(conf.get("loglevel", 
			self.__logLevel if self.__logLevel is not None else DEF_LOGLEVEL))
		self.setLogTarget(conf.get("logtarget", 
			self.__logTarget if self.__logTarget is not None else DEF_LOGTARGET))

		logSys.info("-"*50)
		logSys.info("Starting Fail2ban v%s", version.version)
		
		if self.__daemon: # pragma: no cover
			logSys.info("Daemon started")

		# Install signal handlers
		if _thread_name() == '_MainThread':
			for s in (signal.SIGTERM, signal.SIGINT):
				self._rebindSignal(s, self.__sigTERMhandler)
			self._rebindSignal(signal.SIGUSR1, self.__sigUSR1handler)

		# Ensure unhandled exceptions are logged
		sys.excepthook = excepthook

		# Creates a PID file.
		try:
			logSys.debug("Creating PID file %s", pidfile)
			pidFile = open(pidfile, 'w')
			pidFile.write("%s\n" % os.getpid())
			pidFile.close()
		except (OSError, IOError) as e: # pragma: no cover
			logSys.error("Unable to create PID file: %s", e)
		
		# Start the communication
		logSys.debug("Starting communication")
		try:
			self.__asyncServer = AsyncServer(self.__transm)
			self.__asyncServer.onstart = conf.get('onstart')
			self.__asyncServer.start(sock, force)
		except AsyncServerException as e:
			logSys.error("Could not start server: %s", e)
		# Removes the PID file.
		try:
			logSys.debug("Remove PID file %s", pidfile)
			os.remove(pidfile)
		except (OSError, IOError) as e: # pragma: no cover
			logSys.error("Unable to remove PID file: %s", e)
		logSys.info("Exiting Fail2ban")
	
	def quit(self):
		# Stop communication first because if jail's unban action
		# tries to communicate via fail2ban-client we get a lockup
		# among threads.  So the simplest resolution is to stop all
		# communications first (which should be ok anyways since we
		# are exiting)
		# See https://github.com/fail2ban/fail2ban/issues/7
		if self.__asyncServer is not None:
			self.__asyncServer.stop()
			self.__asyncServer = None

		# Now stop all the jails
		self.stopAllJail()

		# Explicit close database (server can leave in a thread, 
		# so delayed GC can prevent commiting changes)
		if self.__db:
			self.__db.close()
			self.__db = None

		# Only now shutdown the logging.
		if self.__logTarget is not None:
			with self.__loggingLock:
				logging.shutdown()

		# Restore default signal handlers:
		if _thread_name() == '_MainThread':
			for s, sh in self.__prev_signals.iteritems():
				signal.signal(s, sh)

		# Prevent to call quit twice:
		self.quit = lambda: False

	def addJail(self, name, backend):
		addflg = True
		if self.__reload_state.get(name) and self.__jails.exists(name):
			jail = self.__jails[name]
			# if backend switch - restart instead of reload:
			if jail.backend == backend:
				addflg = False
				logSys.info("Reload jail %r", name)
				# prevent to reload the same jail twice (temporary keep it in state, needed to commit reload):
				self.__reload_state[name] = None
			else:
				logSys.info("Restart jail %r (reason: %r != %r)", name, jail.backend, backend)
				self.delJail(name, stop=True)
				# prevent to start the same jail twice (no reload more - restart):
				del self.__reload_state[name]
		if addflg:
			self.__jails.add(name, backend, self.__db)
		if self.__db is not None:
			self.__db.addJail(self.__jails[name])
		
	def delJail(self, name, stop=True, join=True):
		jail = self.__jails[name]
		if join or jail.isAlive():
			jail.stop(stop=stop, join=join)
		if join:
			if self.__db is not None:
				self.__db.delJail(jail)
			del self.__jails[name]

	def startJail(self, name):
		with self.__lock:
			jail = self.__jails[name]
			if not jail.isAlive():
				jail.start()
			elif name in self.__reload_state:
				logSys.info("Jail %r reloaded", name)
				del self.__reload_state[name]
			if jail.idle:
				jail.idle = False
	
	def stopJail(self, name):
		with self.__lock:
			self.delJail(name, stop=True)
	
	def stopAllJail(self):
		logSys.info("Stopping all jails")
		with self.__lock:
			# 1st stop all jails (signal and stop actions/filter thread):
			for name in self.__jails.keys():
				self.delJail(name, stop=True, join=False)
			# 2nd wait for end and delete jails:
			for name in self.__jails.keys():
				self.delJail(name, stop=False, join=True)

	def reloadJails(self, name, opts, begin):
		if begin:
			# begin reload:
			if self.__reload_state and (name == '--all' or self.__reload_state.get(name)): # pragma: no cover
				raise ValueError('Reload already in progress')
			logSys.info("Reload " + (("jail %s" % name) if name != '--all' else "all jails"))
			with self.__lock:
				# if single jail:
				if name != '--all':
					jail = None
					# test jail exists (throws exception if not):
					if "--if-exists" not in opts or self.__jails.exists(name):
						jail = self.__jails[name]
					if jail:
						# first unban all ips (will be not restored after (re)start):
						if "--unban" in opts:
							self.setUnbanIP(name)
						# stop if expected:
						if "--restart" in opts:
							self.stopJail(name)
				else:
					# first unban all ips (will be not restored after (re)start):
					if "--unban" in opts:
						self.setUnbanIP()
					# stop if expected:
					if "--restart" in opts:
						self.stopAllJail()
				# first set all affected jail(s) to idle and reset filter regex and other lists/dicts:
				for jn, jail in self.__jails.iteritems():
					if name == '--all' or jn == name:
						jail.idle = True
						self.__reload_state[jn] = jail
						jail.filter.reload(begin=True)
						jail.actions.reload(begin=True)
				pass
		else:
			# end reload, all affected (or new) jails have already all new parameters (via stream) and (re)started:
			with self.__lock:
				deljails = []
				for jn, jail in self.__jails.iteritems():
					# still in reload state:
					if jn in self.__reload_state:
						# remove jails that are not reloaded (untouched, so not in new configuration)
						deljails.append(jn)
					else:
						# commit (reload was finished):
						jail.filter.reload(begin=False)
						jail.actions.reload(begin=False)
				for jn in deljails:
					self.delJail(jn)
			self.__reload_state = {}
			logSys.info("Reload finished.")

	def setIdleJail(self, name, value):
		self.__jails[name].idle = value
		return True

	def getIdleJail(self, name):
		return self.__jails[name].idle
	
	# Filter
	def setIgnoreSelf(self, name, value):
		self.__jails[name].filter.ignoreSelf = value
	
	def getIgnoreSelf(self, name):
		return self.__jails[name].filter.ignoreSelf

	def addIgnoreIP(self, name, ip):
		self.__jails[name].filter.addIgnoreIP(ip)
	
	def delIgnoreIP(self, name, ip):
		self.__jails[name].filter.delIgnoreIP(ip)
	
	def getIgnoreIP(self, name):
		return self.__jails[name].filter.getIgnoreIP()
	
	def addLogPath(self, name, fileName, tail=False):
		filter_ = self.__jails[name].filter
		if isinstance(filter_, FileFilter):
			filter_.addLogPath(fileName, tail)
	
	def delLogPath(self, name, fileName):
		filter_ = self.__jails[name].filter
		if isinstance(filter_, FileFilter):
			filter_.delLogPath(fileName)
	
	def getLogPath(self, name):
		filter_ = self.__jails[name].filter
		if isinstance(filter_, FileFilter):
			return filter_.getLogPaths()
		else: # pragma: systemd no cover
			logSys.info("Jail %s is not a FileFilter instance" % name)
			return []
	
	def addJournalMatch(self, name, match): # pragma: systemd no cover
		filter_ = self.__jails[name].filter
		if isinstance(filter_, JournalFilter):
			filter_.addJournalMatch(match)
	
	def delJournalMatch(self, name, match): # pragma: systemd no cover
		filter_ = self.__jails[name].filter
		if isinstance(filter_, JournalFilter):
			filter_.delJournalMatch(match)
	
	def getJournalMatch(self, name): # pragma: systemd no cover
		filter_ = self.__jails[name].filter
		if isinstance(filter_, JournalFilter):
			return filter_.getJournalMatch()
		else:
			logSys.info("Jail %s is not a JournalFilter instance" % name)
			return []
	
	def setLogEncoding(self, name, encoding):
		filter_ = self.__jails[name].filter
		filter_.setLogEncoding(encoding)
	
	def getLogEncoding(self, name):
		filter_ = self.__jails[name].filter
		return filter_.getLogEncoding()
	
	def setFindTime(self, name, value):
		self.__jails[name].filter.setFindTime(value)
	
	def getFindTime(self, name):
		return self.__jails[name].filter.getFindTime()

	def setDatePattern(self, name, pattern):
		self.__jails[name].filter.setDatePattern(pattern)

	def getDatePattern(self, name):
		return self.__jails[name].filter.getDatePattern()

	def setLogTimeZone(self, name, tz):
		self.__jails[name].filter.setLogTimeZone(tz)

	def getLogTimeZone(self, name):
		return self.__jails[name].filter.getLogTimeZone()

	def setIgnoreCommand(self, name, value):
		self.__jails[name].filter.setIgnoreCommand(value)

	def getIgnoreCommand(self, name):
		return self.__jails[name].filter.getIgnoreCommand()

	def setPrefRegex(self, name, value):
		flt = self.__jails[name].filter
		logSys.debug("  prefregex: %r", value)
		flt.prefRegex = value

	def getPrefRegex(self, name):
		return self.__jails[name].filter.prefRegex
	
	def addFailRegex(self, name, value, multiple=False):
		flt = self.__jails[name].filter
		if not multiple: value = (value,)
		for value in value:
			logSys.debug("  failregex: %r", value)
			flt.addFailRegex(value)
	
	def delFailRegex(self, name, index=None):
		self.__jails[name].filter.delFailRegex(index)
	
	def getFailRegex(self, name):
		return self.__jails[name].filter.getFailRegex()
	
	def addIgnoreRegex(self, name, value, multiple=False):
		flt = self.__jails[name].filter
		if not multiple: value = (value,)
		for value in value:
			logSys.debug("  ignoreregex: %r", value)
			flt.addIgnoreRegex(value)
	
	def delIgnoreRegex(self, name, index):
		self.__jails[name].filter.delIgnoreRegex(index)
	
	def getIgnoreRegex(self, name):
		return self.__jails[name].filter.getIgnoreRegex()
	
	def setUseDns(self, name, value):
		self.__jails[name].filter.setUseDns(value)
	
	def getUseDns(self, name):
		return self.__jails[name].filter.getUseDns()
	
	def setMaxRetry(self, name, value):
		self.__jails[name].filter.setMaxRetry(value)
	
	def getMaxRetry(self, name):
		return self.__jails[name].filter.getMaxRetry()
	
	def setMaxLines(self, name, value):
		self.__jails[name].filter.setMaxLines(value)
	
	def getMaxLines(self, name):
		return self.__jails[name].filter.getMaxLines()
	
	# Action
	def addAction(self, name, value, *args):
		## create (or reload) jail action:
		self.__jails[name].actions.add(value, *args, 
			reload=name in self.__reload_state)
	
	def getActions(self, name):
		return self.__jails[name].actions
	
	def delAction(self, name, value):
		del self.__jails[name].actions[value]
	
	def getAction(self, name, value):
		return self.__jails[name].actions[value]
	
	def setBanTime(self, name, value):
		self.__jails[name].actions.setBanTime(value)
	
	def setBanIP(self, name, value):
		return self.__jails[name].filter.addBannedIP(value)
		
	def setUnbanIP(self, name=None, value=None):
		if name is not None:
			# in all jails:
			jails = [self.__jails[name]]
		else:
			# single jail:
			jails = self.__jails.values()
		# unban given or all (if value is None):
		cnt = 0
		for jail in jails:
			cnt += jail.actions.removeBannedIP(value, ifexists=(name is None))
		if value and not cnt:
			logSys.info("%s is not banned", value)
		return cnt
		
	def getBanTime(self, name):
		return self.__jails[name].actions.getBanTime()
	
	def isStarted(self):
		return self.__asyncServer is not None and self.__asyncServer.isActive()

	def isAlive(self, jailnum=None):
		if jailnum is not None and len(self.__jails) != jailnum:
			return 0
		for jail in self.__jails.values():
			if not jail.isAlive():
				return 0
		return 1

	# Status
	def status(self):
		try:
			self.__lock.acquire()
			jails = list(self.__jails)
			jails.sort()
			jailList = ", ".join(jails)
			ret = [("Number of jail", len(self.__jails)),
				   ("Jail list", jailList)]
			return ret
		finally:
			self.__lock.release()
	
	def statusJail(self, name, flavor="basic"):
		return self.__jails[name].status(flavor=flavor)

	# Logging
	
	##
	# Set the logging level.
	#
	# CRITICAL
	# ERROR
	# WARNING
	# NOTICE
	# INFO
	# DEBUG
	# @param value the level
	
	def setLogLevel(self, value):
		value = value.upper()
		with self.__loggingLock:
			if self.__logLevel == value:
				return
			ll = str2LogLevel(value)
			# don't change real log-level if running from the test cases:
			getLogger("fail2ban").setLevel(
				ll if DEF_LOGTARGET != "INHERITED" or ll < logging.DEBUG else DEF_LOGLEVEL)
			self.__logLevel = value
	
	##
	# Get the logging level.
	#
	# @see setLogLevel
	# @return the log level
	
	def getLogLevel(self):
		with self.__loggingLock:
			return self.__logLevel

	##
	# Sets the logging target.
	#
	# target can be a file, SYSLOG, STDOUT or STDERR.
	# @param target the logging target
	
	def setLogTarget(self, target):
		# check reserved targets in uppercase, don't change target, because it can be file:
		systarget = target.upper()
		with self.__loggingLock:
			# don't set new handlers if already the same
			# or if "INHERITED" (foreground worker of the test cases, to prevent stop logging):
			if self.__logTarget == target:
				return True
			if systarget == "INHERITED":
				self.__logTarget = target
				return True
			# set a format which is simpler for console use
			fmt = "%(asctime)s %(name)-24s[%(process)d]: %(levelname)-7s %(message)s"
			if systarget == "SYSLOG":
				# Syslog daemons already add date to the message.
				fmt = "%(name)s[%(process)d]: %(levelname)s %(message)s"
				facility = logging.handlers.SysLogHandler.LOG_DAEMON
				if self.__syslogSocket == "auto":
					import platform
					self.__syslogSocket = self.__autoSyslogSocketPaths.get(
						platform.system())
				if self.__syslogSocket is not None\
						and os.path.exists(self.__syslogSocket)\
						and stat.S_ISSOCK(os.stat(
								self.__syslogSocket).st_mode):
					hdlr = logging.handlers.SysLogHandler(
						self.__syslogSocket, facility=facility)
				else:
					logSys.error(
						"Syslog socket file: %s does not exists"
						" or is not a socket" % self.__syslogSocket)
					return False
			elif systarget == "STDOUT":
				hdlr = logging.StreamHandler(sys.stdout)
			elif systarget == "STDERR":
				hdlr = logging.StreamHandler(sys.stderr)
			else:
				# Target should be a file
				try:
					open(target, "a").close()
					hdlr = logging.handlers.RotatingFileHandler(target)
				except IOError:
					logSys.error("Unable to log to %r", target)
					logSys.info("Logging to previous target %r", self.__logTarget)
					return False
			# Removes previous handlers -- in reverse order since removeHandler
			# alter the list in-place and that can confuses the iterable
			logger = getLogger("fail2ban")
			for handler in logger.handlers[::-1]:
				# Remove the handler.
				logger.removeHandler(handler)
				# And try to close -- it might be closed already
				try:
					handler.flush()
					handler.close()
				except (ValueError, KeyError):  # pragma: no cover
					# Is known to be thrown after logging was shutdown once
					# with older Pythons -- seems to be safe to ignore there
					# At least it was still failing on 2.6.2-0ubuntu1 (jaunty)
					if (2, 6, 3) <= sys.version_info < (3,) or \
							(3, 2) <= sys.version_info:
						raise
			# detailed format by deep log levels (as DEBUG=10):
			if logger.getEffectiveLevel() <= logging.DEBUG: # pragma: no cover
				if self.__verbose is None:
					self.__verbose = logging.DEBUG - logger.getEffectiveLevel() + 1
			if self.__verbose is not None and self.__verbose > 2: # pragma: no cover
				fmt = getVerbosityFormat(self.__verbose-1)
			# tell the handler to use this format
			hdlr.setFormatter(logging.Formatter(fmt))
			logger.addHandler(hdlr)
			# Does not display this message at startup.
			if self.__logTarget is not None:
				logSys.info("Start Fail2ban v%s", version.version)
				logSys.info(
					"Changed logging target to %s for Fail2ban v%s"
					% ((target
						if target != "SYSLOG"
						else "%s (%s)"
							 % (target, self.__syslogSocket)),
					   version.version))
			# Sets the logging target.
			self.__logTarget = target
			return True

	##
	# Sets the syslog socket.
	#
	# syslogsocket is the full path to the syslog socket
	# @param syslogsocket the syslog socket path
	def setSyslogSocket(self, syslogsocket):
		with self.__loggingLock:
			if self.__syslogSocket == syslogsocket:
				return True
			self.__syslogSocket = syslogsocket
		# Conditionally reload, logtarget depends on socket path when SYSLOG
		return self.__logTarget != "SYSLOG"\
			   or self.setLogTarget(self.__logTarget)

	def getLogTarget(self):
		with self.__loggingLock:
			return self.__logTarget

	def getSyslogSocket(self):
		with self.__loggingLock:
			return self.__syslogSocket

	def flushLogs(self):
		if self.__logTarget not in ['STDERR', 'STDOUT', 'SYSLOG']:
			for handler in getLogger("fail2ban").handlers:
				try:
					handler.doRollover()
					logSys.info("rollover performed on %s" % self.__logTarget)
				except AttributeError:
					handler.flush()
					logSys.info("flush performed on %s" % self.__logTarget)
			return "rolled over"
		else:
			for handler in getLogger("fail2ban").handlers:
				handler.flush()
				logSys.info("flush performed on %s" % self.__logTarget)
			return "flushed"
			
	def setDatabase(self, filename):
		# if not changed - nothing to do
		if self.__db and self.__db.filename == filename:
			return
		if not self.__db and filename.lower() == 'none':
			return
		if len(self.__jails) != 0:
			raise RuntimeError(
				"Cannot change database when there are jails present")
		if filename.lower() == "none":
			self.__db = None
		else:
			if Fail2BanDb is not None:
				self.__db = Fail2BanDb(filename)
				self.__db.delAllJails()
			else: # pragma: no cover
				logSys.error(
					"Unable to import fail2ban database module as sqlite "
					"is not available.")
	
	def getDatabase(self):
		return self.__db

	def __createDaemon(self): # pragma: no cover
		""" Detach a process from the controlling terminal and run it in the
			background as a daemon.
		
			http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/278731
		"""
	
		# When the first child terminates, all processes in the second child
		# are sent a SIGHUP, so it's ignored.

		# We need to set this in the parent process, so it gets inherited by the
		# child process, and this makes sure that it is effect even if the parent
		# terminates quickly.
		self._rebindSignal(signal.SIGHUP, signal.SIG_IGN)

		try:
			# Fork a child process so the parent can exit.  This will return control
			# to the command line or shell.  This is required so that the new process
			# is guaranteed not to be a process group leader.  We have this guarantee
			# because the process GID of the parent is inherited by the child, but
			# the child gets a new PID, making it impossible for its PID to equal its
			# PGID.
			pid = os.fork()
		except OSError as e:
			return (False, (e.errno, e.strerror))	 # ERROR (return a tuple)
		
		if pid == 0:	   # The first child.
	
			# Next we call os.setsid() to become the session leader of this new
			# session.  The process also becomes the process group leader of the
			# new process group.  Since a controlling terminal is associated with a
			# session, and this new session has not yet acquired a controlling
			# terminal our process now has no controlling terminal.  This shouldn't
			# fail, since we're guaranteed that the child is not a process group
			# leader.
			os.setsid()
		
			try:
				# Fork a second child to prevent zombies.  Since the first child is
				# a session leader without a controlling terminal, it's possible for
				# it to acquire one by opening a terminal in the future.  This second
				# fork guarantees that the child is no longer a session leader, thus
				# preventing the daemon from ever acquiring a controlling terminal.
				pid = os.fork()		# Fork a second child.
			except OSError as e:
				return (False, (e.errno, e.strerror))  # ERROR (return a tuple)
		
			if (pid == 0):	  # The second child.
				# Ensure that the daemon doesn't keep any directory in use.  Failure
				# to do this could make a filesystem unmountable.
				os.chdir("/")
			else:
				os._exit(0)	  # Exit parent (the first child) of the second child.
		else:
			# Signal to exit, parent of the first child.
			return None
	
		# Close all open files.  Try the system configuration variable, SC_OPEN_MAX,
		# for the maximum number of open files to close.  If it doesn't exist, use
		# the default value (configurable).
		try:
			maxfd = os.sysconf("SC_OPEN_MAX")
		except (AttributeError, ValueError):
			maxfd = 256	   # default maximum
	
		# urandom should not be closed in Python 3.4.0. Fixed in 3.4.1
		# http://bugs.python.org/issue21207
		if sys.version_info[0:3] == (3, 4, 0): # pragma: no cover
			urandom_fd = os.open("/dev/urandom", os.O_RDONLY)
			for fd in range(0, maxfd):
				try:
					if not os.path.sameopenfile(urandom_fd, fd):
						os.close(fd)
				except OSError:   # ERROR (ignore)
					pass
			os.close(urandom_fd)
		else:
			os.closerange(0, maxfd)
	
		# Redirect the standard file descriptors to /dev/null.
		os.open("/dev/null", os.O_RDONLY)	# standard input (0)
		os.open("/dev/null", os.O_RDWR)		# standard output (1)
		os.open("/dev/null", os.O_RDWR)		# standard error (2)
		return (True,)


class ServerInitializationError(Exception):
	pass
