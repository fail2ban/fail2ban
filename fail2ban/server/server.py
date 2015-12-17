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
from ..helpers import getLogger, excepthook

# Gets the instance of the logger.
logSys = getLogger(__name__)

try:
	from .database import Fail2BanDb
except ImportError:
	# Dont print error here, as database may not even be used
	Fail2BanDb = None


class Server:
	
	def __init__(self, daemon = False):
		self.__loggingLock = Lock()
		self.__lock = RLock()
		self.__jails = Jails()
		self.__db = None
		self.__daemon = daemon
		self.__transm = Transmitter(self)
		self.__asyncServer = AsyncServer(self.__transm)
		self.__logLevel = None
		self.__logTarget = None
		self.__syslogSocket = None
		self.__autoSyslogSocketPaths = {
			'Darwin':  '/var/run/syslog',
			'FreeBSD': '/var/run/log',
			'Linux': '/dev/log',
		}
		self.setSyslogSocket("auto")
		# Set logging level
		self.setLogLevel("INFO")
		self.setLogTarget("STDOUT")

	def __sigTERMhandler(self, signum, frame):
		logSys.debug("Caught signal %d. Exiting" % signum)
		self.quit()
	
	def __sigUSR1handler(self, signum, fname):
		logSys.debug("Caught signal %d. Flushing logs" % signum)
		self.flushLogs()

	def start(self, sock, pidfile, force = False):
		logSys.info("Starting Fail2ban v" + version.version)
		
		# Install signal handlers
		signal.signal(signal.SIGTERM, self.__sigTERMhandler)
		signal.signal(signal.SIGINT, self.__sigTERMhandler)
		signal.signal(signal.SIGUSR1, self.__sigUSR1handler)
		
		# Ensure unhandled exceptions are logged
		sys.excepthook = excepthook

		# First set the mask to only allow access to owner
		os.umask(0077)
		if self.__daemon: # pragma: no cover
			logSys.info("Starting in daemon mode")
			ret = self.__createDaemon()
			if ret:
				logSys.info("Daemon started")
			else:
				logSys.error("Could not create daemon")
				raise ServerInitializationError("Could not create daemon")
		
		# Creates a PID file.
		try:
			logSys.debug("Creating PID file %s" % pidfile)
			pidFile = open(pidfile, 'w')
			pidFile.write("%s\n" % os.getpid())
			pidFile.close()
		except IOError, e:
			logSys.error("Unable to create PID file: %s" % e)
		
		# Start the communication
		logSys.debug("Starting communication")
		try:
			self.__asyncServer.start(sock, force)
		except AsyncServerException, e:
			logSys.error("Could not start server: %s", e)
		# Removes the PID file.
		try:
			logSys.debug("Remove PID file %s" % pidfile)
			os.remove(pidfile)
		except OSError, e:
			logSys.error("Unable to remove PID file: %s" % e)
		logSys.info("Exiting Fail2ban")
	
	def quit(self):
		# Stop communication first because if jail's unban action
		# tries to communicate via fail2ban-client we get a lockup
		# among threads.  So the simplest resolution is to stop all
		# communications first (which should be ok anyways since we
		# are exiting)
		# See https://github.com/fail2ban/fail2ban/issues/7
		self.__asyncServer.stop()

		# Now stop all the jails
		self.stopAllJail()

		# Only now shutdown the logging.
		try:
			self.__loggingLock.acquire()
			logging.shutdown()
		finally:
			self.__loggingLock.release()

	def addJail(self, name, backend):
		self.__jails.add(name, backend, self.__db)
		if self.__db is not None:
			self.__db.addJail(self.__jails[name])
		
	def delJail(self, name):
		if self.__db is not None:
			self.__db.delJail(self.__jails[name])
		del self.__jails[name]

	def startJail(self, name):
		try:
			self.__lock.acquire()
			if not self.__jails[name].is_alive():
				self.__jails[name].start()
		finally:
			self.__lock.release()
	
	def stopJail(self, name):
		logSys.debug("Stopping jail %s" % name)
		try:
			self.__lock.acquire()
			if self.__jails[name].is_alive():
				self.__jails[name].stop()
				self.delJail(name)
		finally:
			self.__lock.release()
	
	def stopAllJail(self):
		logSys.info("Stopping all jails")
		try:
			self.__lock.acquire()
			for jail in self.__jails.keys():
				self.stopJail(jail)
		finally:
			self.__lock.release()

	def setIdleJail(self, name, value):
		self.__jails[name].idle = value
		return True

	def getIdleJail(self, name):
		return self.__jails[name].idle
	
	# Filter
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
			return [m.getFileName()
					for m in filter_.getLogs()]
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
		if isinstance(filter_, FileFilter):
			filter_.setLogEncoding(encoding)
	
	def getLogEncoding(self, name):
		filter_ = self.__jails[name].filter
		if isinstance(filter_, FileFilter):
			return filter_.getLogEncoding()
	
	def setFindTime(self, name, value):
		self.__jails[name].filter.setFindTime(value)
	
	def getFindTime(self, name):
		return self.__jails[name].filter.getFindTime()

	def setDatePattern(self, name, pattern):
		self.__jails[name].filter.setDatePattern(pattern)

	def getDatePattern(self, name):
		return self.__jails[name].filter.getDatePattern()

	def setIgnoreCommand(self, name, value):
		self.__jails[name].filter.setIgnoreCommand(value)

	def getIgnoreCommand(self, name):
		return self.__jails[name].filter.getIgnoreCommand()

	def addFailRegex(self, name, value):
		self.__jails[name].filter.addFailRegex(value)
	
	def delFailRegex(self, name, index):
		self.__jails[name].filter.delFailRegex(index)
	
	def getFailRegex(self, name):
		return self.__jails[name].filter.getFailRegex()
	
	def addIgnoreRegex(self, name, value):
		self.__jails[name].filter.addIgnoreRegex(value)
	
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
		self.__jails[name].actions.add(value, *args)
	
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
		
	def setUnbanIP(self, name, value):
		self.__jails[name].actions.removeBannedIP(value)
		
	def getBanTime(self, name):
		return self.__jails[name].actions.getBanTime()
	
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
		try:
			self.__loggingLock.acquire()
			getLogger("fail2ban").setLevel(
				getattr(logging, value.upper()))
		except AttributeError:
			raise ValueError("Invalid log level")
		else:
			self.__logLevel = value.upper()
		finally:
			self.__loggingLock.release()
	
	##
	# Get the logging level.
	#
	# @see setLogLevel
	# @return the log level
	
	def getLogLevel(self):
		try:
			self.__loggingLock.acquire()
			return self.__logLevel
		finally:
			self.__loggingLock.release()

	##
	# Sets the logging target.
	#
	# target can be a file, SYSLOG, STDOUT or STDERR.
	# @param target the logging target
	
	def setLogTarget(self, target):
		try:
			self.__loggingLock.acquire()
			# set a format which is simpler for console use
			formatter = logging.Formatter("%(asctime)s %(name)-24s[%(process)d]: %(levelname)-7s %(message)s")
			if target == "SYSLOG":
				# Syslog daemons already add date to the message.
				formatter = logging.Formatter("%(name)s[%(process)d]: %(levelname)s %(message)s")
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
			elif target == "STDOUT":
				hdlr = logging.StreamHandler(sys.stdout)
			elif target == "STDERR":
				hdlr = logging.StreamHandler(sys.stderr)
			else:
				# Target should be a file
				try:
					open(target, "a").close()
					hdlr = logging.handlers.RotatingFileHandler(target)
				except IOError:
					logSys.error("Unable to log to " + target)
					logSys.info("Logging to previous target " + self.__logTarget)
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
				except (ValueError, KeyError): # pragma: no cover
					# Is known to be thrown after logging was shutdown once
					# with older Pythons -- seems to be safe to ignore there
					# At least it was still failing on 2.6.2-0ubuntu1 (jaunty)
					if (2,6,3) <= sys.version_info < (3,) or \
							(3,2) <= sys.version_info:
						raise
			# tell the handler to use this format
			hdlr.setFormatter(formatter)
			logger.addHandler(hdlr)
			# Does not display this message at startup.
			if not self.__logTarget is None:
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
		finally:
			self.__loggingLock.release()

	##
	# Sets the syslog socket.
	#
	# syslogsocket is the full path to the syslog socket
	# @param syslogsocket the syslog socket path
	def setSyslogSocket(self, syslogsocket):
		self.__syslogSocket = syslogsocket
		# Conditionally reload, logtarget depends on socket path when SYSLOG
		return self.__logTarget != "SYSLOG"\
			   or self.setLogTarget(self.__logTarget)

	def getLogTarget(self):
		try:
			self.__loggingLock.acquire()
			return self.__logTarget
		finally:
			self.__loggingLock.release()

	def getSyslogSocket(self):
		try:
			self.__loggingLock.acquire()
			return self.__syslogSocket
		finally:
			self.__loggingLock.release()

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
			else:
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
		signal.signal(signal.SIGHUP, signal.SIG_IGN)
		
		try:
			# Fork a child process so the parent can exit.  This will return control
			# to the command line or shell.  This is required so that the new process
			# is guaranteed not to be a process group leader.  We have this guarantee
			# because the process GID of the parent is inherited by the child, but
			# the child gets a new PID, making it impossible for its PID to equal its
			# PGID.
			pid = os.fork()
		except OSError, e:
			return((e.errno, e.strerror))	 # ERROR (return a tuple)
		
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
			except OSError, e:
				return((e.errno, e.strerror))  # ERROR (return a tuple)
		
			if (pid == 0):	  # The second child.
				# Ensure that the daemon doesn't keep any directory in use.  Failure
				# to do this could make a filesystem unmountable.
				os.chdir("/")
			else:
				os._exit(0)	  # Exit parent (the first child) of the second child.
		else:
			os._exit(0)		 # Exit parent of the first child.
		
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
		return True


class ServerInitializationError(Exception):
	pass
