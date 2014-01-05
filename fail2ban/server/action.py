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

__author__ = "Cyril Jaquier and Fail2Ban Contributors"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier, 2011-2012 Yaroslav Halchenko"
__license__ = "GPL"

import logging, os, subprocess, time, signal, tempfile
import threading, re
from abc import ABCMeta
from collections import MutableMapping
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

class CallingMap(MutableMapping):
	def __init__(self, *args, **kwargs):
		self.data = dict(*args, **kwargs)
	def __getitem__(self, key):
		value = self.data[key]
		if callable(value):
			return value()
		else:
			return value
	def __setitem__(self, key, value):
		self.data[key] = value
	def __delitem__(self, key):
		del self.data[key]
	def __iter__(self):
		return iter(self.data)
	def __len__(self):
		return len(self.data)

##
# Execute commands.
#
# This class reads the failures from the Jail queue and decide if an
# action has to be taken. A BanManager take care of the banned IP
# addresses.

class ActionBase(object):
	__metaclass__ = ABCMeta

	@classmethod
	def __subclasshook__(cls, C):
		required = (
			"getName",
			"execActionStart",
			"execActionStop",
			"execActionBan",
			"execActionUnban",
			)
		for method in required:
			if not callable(getattr(C, method, None)):
				return False
		return True

	def __init__(self, jail, name):
		self._jail = jail
		self._name = name
		self._logSys = logging.getLogger(
			'%s.%s' % (__name__, self.__class__.__name__))

	@property
	def jail(self):
		return self._jail

	@property
	def logSys(self):
		return self._logSys
	
	##
	# Returns the action name.
	#
	# @return the name of the action
	
	def getName(self):
		return self._name

	name = property(getName)
	
	def execActionStart(self):
		pass

	def execActionBan(self, aInfo):
		pass

	def execActionUnban(self, aInfo):
		pass

	def execActionStop(self):
		pass

class CommandAction(ActionBase):
	
	def __init__(self, name):
		super(CommandAction, self).__init__(None, name)
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
	
	@classmethod
	def __subclasshook__(cls, C):
		return NotImplemented # Standard checks
			
	##
	# Sets the timeout period for commands.
	#
	# @param timeout timeout period in seconds
	
	def setTimeout(self, timeout):
		self.__timeout = int(timeout)
		logSys.debug("Set action %s timeout = %i" % (self.getName(), timeout))
	
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
		if self.__cInfo:
			if not self.substituteRecursiveTags(self.__cInfo):
				logSys.error("Cinfo/definitions contain self referencing definitions and cannot be resolved")
				return False
		startCmd = self.replaceTag(self.__actionStart, self.__cInfo)
		return self.executeCmd(startCmd, self.__timeout)
	
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
		stopCmd = self.replaceTag(self.__actionStop, self.__cInfo)
		return self.executeCmd(stopCmd, self.__timeout)

	##
	# Sort out tag definitions within other tags
	#
	# so:		becomes:
	# a = 3		a = 3
	# b = <a>_3	b = 3_3
	# @param	tags, a dictionary
	# @returns	tags altered or False if there is a recursive definition
	@staticmethod
	def substituteRecursiveTags(tags):
		t = re.compile(r'<([^ >]+)>')
		for tag, value in tags.iteritems():
			value = str(value)
			m = t.search(value)
			done = []
			#logSys.log(5, 'TAG: %s, value: %s' % (tag, value))
			while m:
				found_tag = m.group(1)
				#logSys.log(5, 'found: %s' % found_tag)
				if found_tag == tag or found_tag in done:
					# recursive definitions are bad
					#logSys.log(5, 'recursion fail')
					return False
				else:
					if tags.has_key(found_tag):
						value = value[0:m.start()] + tags[found_tag] + value[m.end():]
						#logSys.log(5, 'value now: %s' % value)
						done.append(found_tag)
						m = t.search(value, m.start())
					else:
						# Missing tags are ok so we just continue on searching.
						# cInfo can contain aInfo elements like <HOST> and valid shell
						# constructs like <STDIN>.
						m = t.search(value, m.start() + 1)
			#logSys.log(5, 'TAG: %s, newvalue: %s' % (tag, value))
			tags[tag] = value
		return tags

	@staticmethod
	def escapeTag(tag):
		for c in '\\#&;`|*?~<>^()[]{}$\'"':
			if c in tag:
				tag = tag.replace(c, '\\' + c)
		return tag

	##
	# Replaces tags in query with property values in aInfo.
	#
	# @param query the query string with tags
	# @param aInfo the properties
	# @return a string
	
	@classmethod
	def replaceTag(cls, query, aInfo):
		""" Replace tags in query
		"""
		string = query
		for tag in aInfo:
			if "<%s>" % tag in query:
				value = str(aInfo[tag])			  # assure string
				if tag.endswith('matches'):
					# That one needs to be escaped since its content is
					# out of our control
					value = cls.escapeTag(value)
				string = string.replace('<' + tag + '>', value)
		# New line
		string = string.replace("<br>", '\n')
		return string
	
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
		
		checkCmd = self.replaceTag(self.__actionCheck, self.__cInfo)
		if not self.executeCmd(checkCmd, self.__timeout):
			logSys.error("Invariant check failed. Trying to restore a sane" +
						 " environment")
			self.execActionStop()
			self.execActionStart()
			if not self.executeCmd(checkCmd, self.__timeout):
				logSys.fatal("Unable to restore environment")
				return False

		# Replace tags
		if not aInfo is None:
			realCmd = self.replaceTag(cmd, aInfo)
		else:
			realCmd = cmd
		
		# Replace static fields
		realCmd = self.replaceTag(realCmd, self.__cInfo)
		
		return self.executeCmd(realCmd, self.__timeout)

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

	@staticmethod
	def executeCmd(realCmd, timeout=60):
		logSys.debug(realCmd)
		if not realCmd:
			logSys.debug("Nothing to do")
			return True
		
		_cmd_lock.acquire()
		try: # Try wrapped within another try needed for python version < 2.5
			stdout = tempfile.TemporaryFile(suffix=".stdout", prefix="fai2ban_")
			stderr = tempfile.TemporaryFile(suffix=".stderr", prefix="fai2ban_")
			try:
				popen = subprocess.Popen(
					realCmd, stdout=stdout, stderr=stderr, shell=True)
				stime = time.time()
				retcode = popen.poll()
				while time.time() - stime <= timeout and retcode is None:
					time.sleep(0.1)
					retcode = popen.poll()
				if retcode is None:
					logSys.error("%s -- timed out after %i seconds." %
						(realCmd, timeout))
					os.kill(popen.pid, signal.SIGTERM) # Terminate the process
					time.sleep(0.1)
					retcode = popen.poll()
					if retcode is None: # Still going...
						os.kill(popen.pid, signal.SIGKILL) # Kill the process
						time.sleep(0.1)
						retcode = popen.poll()
			except OSError, e:
				logSys.error("%s -- failed with %s" % (realCmd, e))
				return False
		finally:
			_cmd_lock.release()

		std_level = retcode == 0 and logging.DEBUG or logging.ERROR
		if std_level >= logSys.getEffectiveLevel():
			stdout.seek(0)
			logSys.log(std_level, "%s -- stdout: %r" % (realCmd, stdout.read()))
			stderr.seek(0)
			logSys.log(std_level, "%s -- stderr: %r" % (realCmd, stderr.read()))
		stdout.close()
		stderr.close()

		if retcode == 0:
			logSys.debug("%s -- returned successfully" % realCmd)
			return True
		elif retcode is None:
			logSys.error("%s -- unable to kill PID %i" % (realCmd, popen.pid))
		elif retcode < 0:
			logSys.error("%s -- killed with %s" %
				(realCmd, signame.get(-retcode, "signal %i" % -retcode)))
		else:
			msg = _RETCODE_HINTS.get(retcode, None)
			logSys.error("%s -- returned %i" % (realCmd, retcode))
			if msg:
				logSys.info("HINT on %i: %s"
							% (retcode, msg % locals()))
		return False
	
