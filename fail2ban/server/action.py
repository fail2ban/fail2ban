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
# $Revision$

__author__ = "Cyril Jaquier"
__version__ = "$Revision$"
__date__ = "$Date$"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import logging, os, subprocess, time, signal
import threading
#from subprocess import call

# Gets the instance of the logger.
logSys = logging.getLogger(__name__)

# Create a lock for running system commands
_cmd_lock = threading.Lock()

# Some hints on common abnormal exit codes
_RETCODE_HINTS = {
	127: '"Command not found".  Make sure that all commands in %(realCmd)r '
	        'are in the PATH of fail2ban-server process '
			'(grep -a PATH= /proc/`pidof -x fail2ban-server`/environ). '
			'You may want to start '
			'"fail2ban-server -f" separately, initiate it with '
			'"fail2ban-client reload" in another shell session and observe if '
			'additional informative error messages appear in the terminals.'
	}

# Dictionary to lookup signal name from number
signame = dict((num, name)
	for name, num in signal.__dict__.iteritems() if name.startswith("SIG"))

##
# Execute commands.
#
# This class reads the failures from the Jail queue and decide if an
# action has to be taken. A BanManager take care of the banned IP
# addresses.

class Action:
	
	def __init__(self, name):
		self.__name = name
		self.__timeout = 60
		self.__cInfo = dict()
		## Command executed in order to initialize the system.
		self.__actionStart = ''
		## Command executed when an IP address gets banned.
		self.__actionBan = ''
		## Command executed when an IP address gets removed.
		self.__actionUnban = ''
		## Command executed in order to check requirements.
		self.__actionCheck = ''
		## Command executed in order to stop the system.
		self.__actionStop = ''
		logSys.debug("Created Action")
	
	##
	# Sets the action name.
	#
	# @param name the name of the action
	
	def setName(self, name):
		self.__name = name
	
	##
	# Returns the action name.
	#
	# @return the name of the action
	
	def getName(self):
		return self.__name
	
	##
	# Sets the timeout period for commands.
	#
	# @param timeout timeout period in seconds
	
	def setTimeout(self, timeout):
		self.__timeout = int(timeout)
		logSys.debug("Set action %s timeout = %i" % (self.__name, timeout))
	
	##
	# Returns the action timeout period for commands.
	#
	# @return the timeout period in seconds
	
	def getTimeout(self):
		return self.__timeout
	
	##
	# Sets a "CInfo".
	#
	# CInfo are statically defined properties. They can be definied by
	# the user and are used to set e-mail addresses, port, host or
	# anything that should not change during the life of the server.
	#
	# @param key the property name
	# @param value the property value
	
	def setCInfo(self, key, value):
		self.__cInfo[key] = value
	
	##
	# Returns a "CInfo".
	#
	# @param key the property name
	
	def getCInfo(self, key):
		return self.__cInfo[key]
	
	##
	# Removes a "CInfo".
	#
	# @param key the property name
	
	def delCInfo(self, key):
		del self.__cInfo[key]
	
	##
	# Set the "start" command.
	#
	# @param value the command
		
	def setActionStart(self, value):
		self.__actionStart = value
		logSys.debug("Set actionStart = %s" % value)
	
	##
	# Get the "start" command.
	#
	# @return the command
	
	def getActionStart(self):
		return self.__actionStart
	
	##
	# Executes the action "start" command.
	#
	# Replaces the tags in the action command with value of "cInfo"
	# and executes the resulting command.
	#
	# @return True if the command succeeded
	
	def execActionStart(self):
		startCmd = Action.replaceTag(self.__actionStart, self.__cInfo)
		return Action.executeCmd(startCmd, self.__timeout)
	
	##
	# Set the "ban" command.
	#
	# @param value the command
	
	def setActionBan(self, value):
		self.__actionBan = value
		logSys.debug("Set actionBan = %s" % value)
	
	##
	# Get the "ban" command.
	#
	# @return the command
	
	def getActionBan(self):
		return self.__actionBan
	
	##
	# Executes the action "ban" command.
	#
	# @return True if the command succeeded
	
	def execActionBan(self, aInfo):
		return self.__processCmd(self.__actionBan, aInfo)
	
	##
	# Set the "unban" command.
	#
	# @param value the command
	
	def setActionUnban(self, value):
		self.__actionUnban = value
		logSys.debug("Set actionUnban = %s" % value)
	
	##
	# Get the "unban" command.
	#
	# @return the command
	
	def getActionUnban(self):
		return self.__actionUnban
	
	##
	# Executes the action "unban" command.
	#
	# @return True if the command succeeded
	
	def execActionUnban(self, aInfo):
		return self.__processCmd(self.__actionUnban, aInfo)
	
	##
	# Set the "check" command.
	#
	# @param value the command
	
	def setActionCheck(self, value):
		self.__actionCheck = value
		logSys.debug("Set actionCheck = %s" % value)
	
	##
	# Get the "check" command.
	#
	# @return the command
	
	def getActionCheck(self):
		return self.__actionCheck
	
	##
	# Set the "stop" command.
	#
	# @param value the command
	
	def setActionStop(self, value):
		self.__actionStop = value
		logSys.debug("Set actionStop = %s" % value)
	
	##
	# Get the "stop" command.
	#
	# @return the command
	
	def getActionStop(self):
		return self.__actionStop
	
	##
	# Executes the action "stop" command.
	#
	# Replaces the tags in the action command with value of "cInfo"
	# and executes the resulting command.
	#
	# @return True if the command succeeded
	
	def execActionStop(self):
		stopCmd = Action.replaceTag(self.__actionStop, self.__cInfo)
		return Action.executeCmd(stopCmd, self.__timeout)

	def escapeTag(tag):
		for c in '\\#&;`|*?~<>^()[]{}$\n\'"':
			if c in tag:
				tag = tag.replace(c, '\\' + c)
		return tag
	escapeTag = staticmethod(escapeTag)

	##
	# Replaces tags in query with property values in aInfo.
	#
	# @param query the query string with tags
	# @param aInfo the properties
	# @return a string
	
	#@staticmethod
	def replaceTag(query, aInfo):
		""" Replace tags in query
		"""
		string = query
		for tag, value in aInfo.iteritems():
			value = str(value)			  # assure string
			if tag == 'matches':
				# That one needs to be escaped since its content is
				# out of our control
				value = Action.escapeTag(value)
			string = string.replace('<' + tag + '>', value)
		# New line
		string = string.replace("<br>", '\n')
		return string
	replaceTag = staticmethod(replaceTag)
	
	##
	# Executes a command with preliminary checks and substitutions.
	#
	# Before executing any commands, executes the "check" command first
	# in order to check if pre-requirements are met. If this check fails,
	# it tries to restore a sane environment before executing the real
	# command.
	# Replaces "aInfo" and "cInfo" in the query too.
	#
	# @param cmd The command to execute
	# @param aInfo Dynamic properties
	# @return True if the command succeeded
	
	def __processCmd(self, cmd, aInfo = None):
		""" Executes an OS command.
		"""
		if cmd == "":
			logSys.debug("Nothing to do")
			return True
		
		checkCmd = Action.replaceTag(self.__actionCheck, self.__cInfo)
		if not Action.executeCmd(checkCmd, self.__timeout):
			logSys.error("Invariant check failed. Trying to restore a sane" +
						 " environment")
			self.execActionStop()
			self.execActionStart()
			if not Action.executeCmd(checkCmd, self.__timeout):
				logSys.fatal("Unable to restore environment")
				return False

		# Replace tags
		if not aInfo == None:
			realCmd = Action.replaceTag(cmd, aInfo)
		else:
			realCmd = cmd
		
		# Replace static fields
		realCmd = Action.replaceTag(realCmd, self.__cInfo)
		
		return Action.executeCmd(realCmd, self.__timeout)

	##
	# Executes a command.
	#
	# We need a shell here because commands are mainly shell script. They
	# contain pipe, redirection, etc.
	# 
	# @todo Force the use of bash!?
	# @todo Kill the command after a given timeout
	#
	# @param realCmd the command to execute
	# @return True if the command succeeded

	#@staticmethod
	def executeCmd(realCmd, timeout=60):
		logSys.debug(realCmd)
		_cmd_lock.acquire()
		try: # Try wrapped within another try needed for python version < 2.5
			try:
				popen = subprocess.Popen(realCmd, shell=True)
				stime = time.time()
				retcode = popen.poll()
				while time.time() - stime <= timeout and retcode is None:
					time.sleep(0.1)
					retcode = popen.poll()
				if retcode is None:
					logSys.error("%s timed out after %i seconds." %
						(realCmd, timeout))
					os.kill(popen.pid, signal.SIGTERM) # Terminate the process
					time.sleep(0.1)
					retcode = popen.poll()
					if retcode is None: # Still going...
						os.kill(popen.pid, signal.SIGKILL) # Kill the process
						time.sleep(0.1)
						retcode = popen.poll()
			except OSError, e:
				logSys.error("%s failed with %s" % (realCmd, e))
				return False
		finally:
			_cmd_lock.release()

		if retcode == 0:
			logSys.debug("%s returned successfully" % realCmd)
			return True
		elif retcode is None:
			logSys.error("Unable to kill PID %i: %s" % (popen.pid, realCmd))
		elif retcode < 0:
			logSys.error("%s killed with %s" %
				(realCmd, signame.get(-retcode, "signal %i" % -retcode)))
		else:
			msg = _RETCODE_HINTS.get(retcode, None)
			logSys.error("%s returned %i" % (realCmd, retcode))
			if msg:
				logSys.info("HINT on %i: %s"
							% (retcode, msg % locals()))
		return False
	executeCmd = staticmethod(executeCmd)
	
