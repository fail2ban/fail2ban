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
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

# Author: Cyril Jaquier
# 
# $Revision: 748 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 748 $"
__date__ = "$Date: 2009-08-31 16:14:02 +0200 (Mon, 31 Aug 2009) $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

from threading import Lock, RLock
from jails import Jails
from transmitter import Transmitter
from asyncserver import AsyncServer
from asyncserver import AsyncServerException
from common import version
import logging, logging.handlers, sys, os, signal

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.server")

class Server:
	
	PID_FILE = "/var/run/fail2ban/fail2ban.pid"

	def __init__(self, daemon = False):
		self.__loggingLock = Lock()
		self.__lock = RLock()
		self.__jails = Jails()
		self.__daemon = daemon
		self.__transm = Transmitter(self)
		self.__asyncServer = AsyncServer(self.__transm)
		self.__logLevel = None
		self.__logTarget = None
		# Set logging level
		self.setLogLevel(3)
		self.setLogTarget("STDOUT")
	
	def __sigTERMhandler(self, signum, frame):
		logSys.debug("Caught signal %d. Exiting" % signum)
		self.quit()
	
	def start(self, sock, force = False):
		logSys.info("Starting Fail2ban v" + version.version)
		
		# Install signal handlers
		signal.signal(signal.SIGTERM, self.__sigTERMhandler)
		signal.signal(signal.SIGINT, self.__sigTERMhandler)
		
		# First set the mask to only allow access to owner
		os.umask(0077)
		if self.__daemon:
			logSys.info("Starting in daemon mode")
			ret = self.__createDaemon()
			if ret:
				logSys.info("Daemon started")
			else:
				logSys.error("Could not create daemon")
				raise ServerInitializationError("Could not create daemon")
		
		# Creates a PID file.
		try:
			logSys.debug("Creating PID file %s" % Server.PID_FILE)
			pidFile = open(Server.PID_FILE, 'w')
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
			logSys.debug("Remove PID file %s" % Server.PID_FILE)
			os.remove(Server.PID_FILE)
		except OSError, e:
			logSys.error("Unable to remove PID file: %s" % e)
		logSys.info("Exiting Fail2ban")
		# Shutdowns the logging.
		try:
			self.__loggingLock.acquire()
			logging.shutdown()
		finally:
			self.__loggingLock.release()
	
	def quit(self):
		self.stopAllJail()
		# Stop communication
		self.__asyncServer.stop()
	
	def addJail(self, name, backend):
		self.__jails.add(name, backend)
		
	def delJail(self, name):
		self.__jails.remove(name)
	
	def startJail(self, name):
		try:
			self.__lock.acquire()
			if not self.isAlive(name):
				self.__jails.get(name).start()
		finally:
			self.__lock.release()
	
	def stopJail(self, name):
		try:
			self.__lock.acquire()
			if self.isAlive(name):
				self.__jails.get(name).stop()
				self.delJail(name)
		finally:
			self.__lock.release()
	
	def stopAllJail(self):
		try:
			self.__lock.acquire()
			for jail in self.__jails.getAll():
				self.stopJail(jail)
		finally:
			self.__lock.release()
	
	def isAlive(self, name):
		return self.__jails.get(name).isAlive()
	
	def setIdleJail(self, name, value):
		self.__jails.get(name).setIdle(value)
		return True

	def getIdleJail(self, name):
		return self.__jails.get(name).getIdle()
	
	# Filter
	def addIgnoreIP(self, name, ip):
		self.__jails.getFilter(name).addIgnoreIP(ip)
	
	def delIgnoreIP(self, name, ip):
		self.__jails.getFilter(name).delIgnoreIP(ip)
	
	def getIgnoreIP(self, name):
		return self.__jails.getFilter(name).getIgnoreIP()
	
	def addLogPath(self, name, fileName):
		self.__jails.getFilter(name).addLogPath(fileName, True)
	
	def delLogPath(self, name, fileName):
		self.__jails.getFilter(name).delLogPath(fileName)
	
	def getLogPath(self, name):
		return [m.getFileName()
				for m in self.__jails.getFilter(name).getLogPath()]
	
	def setFindTime(self, name, value):
		self.__jails.getFilter(name).setFindTime(value)
	
	def getFindTime(self, name):
		return self.__jails.getFilter(name).getFindTime()

	def addFailRegex(self, name, value):
		self.__jails.getFilter(name).addFailRegex(value)
	
	def delFailRegex(self, name, index):
		self.__jails.getFilter(name).delFailRegex(index)
	
	def getFailRegex(self, name):
		return self.__jails.getFilter(name).getFailRegex()
	
	def addIgnoreRegex(self, name, value):
		self.__jails.getFilter(name).addIgnoreRegex(value)
	
	def delIgnoreRegex(self, name, index):
		self.__jails.getFilter(name).delIgnoreRegex(index)
	
	def getIgnoreRegex(self, name):
		return self.__jails.getFilter(name).getIgnoreRegex()
	
	def setMaxRetry(self, name, value):
		self.__jails.getFilter(name).setMaxRetry(value)
	
	def getMaxRetry(self, name):
		return self.__jails.getFilter(name).getMaxRetry()
	
	# Action
	def addAction(self, name, value):
		self.__jails.getAction(name).addAction(value)
	
	def getLastAction(self, name):
		return self.__jails.getAction(name).getLastAction()
	
	def delAction(self, name, value):
		self.__jails.getAction(name).delAction(value)
	
	def setCInfo(self, name, action, key, value):
		self.__jails.getAction(name).getAction(action).setCInfo(key, value)
	
	def getCInfo(self, name, action, key):
		return self.__jails.getAction(name).getAction(action).getCInfo(key)
	
	def delCInfo(self, name, action, key):
		self.__jails.getAction(name).getAction(action).delCInfo(key)
	
	def setBanTime(self, name, value):
		self.__jails.getAction(name).setBanTime(value)
	
	def setBanIP(self, name, value):
		return self.__jails.getFilter(name).addBannedIP(value)
		
	def getBanTime(self, name):
		return self.__jails.getAction(name).getBanTime()
	
	def setActionStart(self, name, action, value):
		self.__jails.getAction(name).getAction(action).setActionStart(value)
	
	def getActionStart(self, name, action):
		return self.__jails.getAction(name).getAction(action).getActionStart()
		
	def setActionStop(self, name, action, value):
		self.__jails.getAction(name).getAction(action).setActionStop(value)
	
	def getActionStop(self, name, action):
		return self.__jails.getAction(name).getAction(action).getActionStop()
	
	def setActionCheck(self, name, action, value):
		self.__jails.getAction(name).getAction(action).setActionCheck(value)
	
	def getActionCheck(self, name, action):
		return self.__jails.getAction(name).getAction(action).getActionCheck()
	
	def setActionBan(self, name, action, value):
		self.__jails.getAction(name).getAction(action).setActionBan(value)
	
	def getActionBan(self, name, action):
		return self.__jails.getAction(name).getAction(action).getActionBan()
	
	def setActionUnban(self, name, action, value):
		self.__jails.getAction(name).getAction(action).setActionUnban(value)
	
	def getActionUnban(self, name, action):
		return self.__jails.getAction(name).getAction(action).getActionUnban()
		
	# Status
	def status(self):
		try:
			self.__lock.acquire()
			jailList = ''
			for jail in self.__jails.getAll():
				jailList += jail + ', '
			length = len(jailList)
			if not length == 0:
				jailList = jailList[:length-2]
			ret = [("Number of jail", self.__jails.size()), 
				   ("Jail list", jailList)]
			return ret
		finally:
			self.__lock.release()
	
	def statusJail(self, name):
		return self.__jails.get(name).getStatus()
	
	# Logging
	
	##
	# Set the logging level.
	#
	# Incrementing the value gives more messages.
	# 0 = FATAL
	# 1 = ERROR
	# 2 = WARNING
	# 3 = INFO
	# 4 = DEBUG
	# @param value the level
	
	def setLogLevel(self, value):
		try:
			self.__loggingLock.acquire()
			self.__logLevel = value
			logLevel = logging.DEBUG
			if value == 0:
				logLevel = logging.FATAL
			elif value == 1:
				logLevel = logging.ERROR
			elif value == 2:
				logLevel = logging.WARNING
			elif value == 3:
				logLevel = logging.INFO
			logging.getLogger("fail2ban").setLevel(logLevel)
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
			formatter = logging.Formatter("%(asctime)s %(name)-16s: %(levelname)-6s %(message)s")
			if target == "SYSLOG":
				# Syslog daemons already add date to the message.
				formatter = logging.Formatter("%(name)-16s: %(levelname)-6s %(message)s")
				facility = logging.handlers.SysLogHandler.LOG_DAEMON
				hdlr = logging.handlers.SysLogHandler("/dev/log", 
													  facility = facility)
			elif target == "STDOUT":
				hdlr = logging.StreamHandler(sys.stdout)
			elif target == "STDERR":
				hdlr = logging.StreamHandler(sys.stderr)
			else:
				# Target should be a file
				try:
					open(target, "a").close()
					hdlr = logging.FileHandler(target)
				except IOError:
					logSys.error("Unable to log to " + target)
					logSys.info("Logging to previous target " + self.__logTarget)
					return False
			# Removes previous handlers
			for handler in logging.getLogger("fail2ban").handlers:
				# Closes the handler.
				logging.getLogger("fail2ban").removeHandler(handler)
				handler.close()
			# tell the handler to use this format
			hdlr.setFormatter(formatter)
			logging.getLogger("fail2ban").addHandler(hdlr)
			# Does not display this message at startup.
			if not self.__logTarget == None:
				logSys.info("Changed logging target to %s for Fail2ban v%s" %
						(target, version.version))
			# Sets the logging target.
			self.__logTarget = target
			return True
		finally:
			self.__loggingLock.release()
	
	def getLogTarget(self):
		try:
			self.__loggingLock.acquire()
			return self.__logTarget
		finally:
			self.__loggingLock.release()
	
	def __createDaemon(self):
		""" Detach a process from the controlling terminal and run it in the
			background as a daemon.
		
			http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/278731
		"""
	
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
		
			# When the first child terminates, all processes in the second child
			# are sent a SIGHUP, so it's ignored.
			signal.signal(signal.SIGHUP, signal.SIG_IGN)
		
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
	
		for fd in range(0, maxfd):
			try:
				os.close(fd)
			except OSError:   # ERROR (ignore)
				pass
	
		# Redirect the standard file descriptors to /dev/null.
		os.open("/dev/null", os.O_RDONLY)	# standard input (0)
		os.open("/dev/null", os.O_RDWR)		# standard output (1)
		os.open("/dev/null", os.O_RDWR)		# standard error (2)
		return True


class ServerInitializationError(Exception):
	pass
