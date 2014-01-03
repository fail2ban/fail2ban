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
	"""Calling Map behaves similar to a standard python dictionary,
	with the exception that any values which are callable, are called
	and the result of the callable is returned.
	No error handling is in place, such that any errors raised in the
	callable will raised as usual.
	Actual dictionary is stored in property `data`, and can be accessed
	to obtain original callable values.
	"""
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

class ActionBase(object):
	"""Action Base is a base definition of what methods need to be in
	place to create a python based action for fail2ban. This class can
	be inherited from to ease implementation, but is not required as
	long as the following required methods/properties are implemented:
		- __init__(jail, actionname)
		- start()
		- stop()
		- ban(aInfo)
		- unban(aInfo)
		- actionname
	"""
	__metaclass__ = ABCMeta

	@classmethod
	def __subclasshook__(cls, C):
		required = (
			"start",
			"stop",
			"ban",
			"unban",
			)
		for method in required:
			if not callable(getattr(C, method, None)):
				return False
		return True

	def __init__(self, jail, actionname):
		"""Should initialise the action class with `jail` being the Jail
		object the action belongs to, `actionname` being the name assigned
		to the action, and `kwargs` being all other args that have been
		specified with jail.conf or on the fail2ban-client.
		"""
		self._jail = jail
		self._actionname = actionname
		self._logSys = logging.getLogger(
			'%s.%s' % (__name__, self.__class__.__name__))

	@property
	def actionname(self):
		"""The name of the action, which should not change in the
		lifetime of the action."""
		return self._actionname

	def start(self):
		"""Executed when the jail/action starts."""
		pass

	def stop(self):
		"""Executed when the jail/action stops or action is deleted.
		"""
		pass

	def ban(self, aInfo):
		"""Executed when a ban occurs. `aInfo` is a dictionary which
		includes information in relation to the ban.
		"""
		pass

	def unban(self, aInfo):
		"""Executed when a ban expires. `aInfo` as per execActionBan.
		"""
		pass

class CommandAction(ActionBase):
	"""A Fail2Ban action which executes commands with Python's
	subprocess module. This is the default type of action which
	Fail2Ban uses.
	"""
	
	def __init__(self, jail, actionname):
		super(CommandAction, self).__init__(jail, actionname)
		self.timeout = 60
		## Command executed in order to initialize the system.
		self.actionstart = ''
		## Command executed when an IP address gets banned.
		self.actionban = ''
		## Command executed when an IP address gets removed.
		self.actionunban = ''
		## Command executed in order to check requirements.
		self.actioncheck = ''
		## Command executed in order to stop the system.
		self.actionstop = ''
		self._logSys.debug("Created %s" % self.__class__)
	
	@classmethod
	def __subclasshook__(cls, C):
		return NotImplemented # Standard checks

	@property
	def timeout(self):
		"""Timeout period in seconds for execution of commands
		"""
		return self._timeout
	@timeout.setter
	def timeout(self, timeout):
		self._timeout = int(timeout)
		self._logSys.debug("Set action %s timeout = %i" %
			(self.actionname, self.timeout))

	@property
	def _properties(self):
		return dict(
			(key, getattr(self, key))
			for key in dir(self)
			if not key.startswith("_") and not callable(getattr(self, key)))

	@property
	def actionstart(self):
		"""The command executed on start of the jail/action.
		"""
		return self._actionstart
	@actionstart.setter
	def actionstart(self, value):
		self._actionstart = value
		self._logSys.debug("Set actionstart = %s" % value)

	def start(self):
		"""Executes the "actionstart" command.
		Replace the tags in the action command with actions properties
		and executes the resulting command.
		"""
		if (self._properties and
			not self.substituteRecursiveTags(self._properties)):
			self._logSys.error(
				"properties contain self referencing definitions "
				"and cannot be resolved")
			raise RuntimeError("Error starting action")
		startCmd = self.replaceTag(self.actionstart, self._properties)
		if not self.executeCmd(startCmd, self.timeout):
			raise RuntimeError("Error starting action")

	@property
	def actionban(self):
		"""The command used when a ban occurs.
		"""
		return self._actionban
	@actionban.setter
	def actionban(self, value):
		self._actionban = value
		self._logSys.debug("Set actionban = %s" % value)

	def ban(self, aInfo):
		"""Executes the "actionban" command.
		Replace the tags in the action command with actions properties
		and ban information, and executes the resulting command.
		"""
		if not self._processCmd(self.actionban, aInfo):
			raise RuntimeError("Error banning %(ip)s" % aInfo)

	@property
	def actionunban(self):
		"""The command used when an unban occurs.
		"""
		return self._actionunban
	@actionunban.setter
	def actionunban(self, value):
		self._actionunban = value
		self._logSys.debug("Set actionunban = %s" % value)

	def unban(self, aInfo):
		"""Executes the "actionunban" command.
		Replace the tags in the action command with actions properties
		and ban information, and executes the resulting command.
		"""
		if not self._processCmd(self.actionunban, aInfo):
			raise RuntimeError("Error unbanning %(ip)s" % aInfo)

	@property
	def actioncheck(self):
		"""The command used to check correct environment in place for
		ban action to take place.
		"""
		return self._actioncheck
	@actioncheck.setter
	def actioncheck(self, value):
		self._actioncheck = value
		self._logSys.debug("Set actioncheck = %s" % value)

	@property
	def actionstop(self):
		"""The command executed when the jail/actions stops.
		"""
		return self._actionstop
	@actionstop.setter
	def actionstop(self, value):
		self._actionstop = value
		self._logSys.debug("Set actionstop = %s" % value)

	def stop(self):
		"""Executes the "actionstop" command.
		Replace the tags in the action command with actions properties
		and executes the resulting command.
		"""
		stopCmd = self.replaceTag(self.actionstop, self._properties)
		if not self.executeCmd(stopCmd, self.timeout):
			raise RuntimeError("Error stopping action")

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
			while m:
				if m.group(1) == tag:
					# recursive definitions are bad
					return False
				else:
					if tags.has_key(m.group(1)):
						value = value[0:m.start()] + tags[m.group(1)] + value[m.end():]
						m = t.search(value, m.start())
					else:
						# Missing tags are ok so we just continue on searching.
						# cInfo can contain aInfo elements like <HOST> and valid shell
						# constructs like <STDIN>.
						m = t.search(value, m.start() + 1)
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
	
	def _processCmd(self, cmd, aInfo = None):
		""" Executes an OS command.
		"""
		if cmd == "":
			self._logSys.debug("Nothing to do")
			return True
		
		checkCmd = self.replaceTag(self.actioncheck, self._properties)
		if not self.executeCmd(checkCmd, self.timeout):
			self._logSys.error(
				"Invariant check failed. Trying to restore a sane environment")
			self.stop()
			self.start()
			if not self.executeCmd(checkCmd, self.timeout):
				self._logSys.fatal("Unable to restore environment")
				return False

		# Replace tags
		if not aInfo is None:
			realCmd = self.replaceTag(cmd, aInfo)
		else:
			realCmd = cmd
		
		# Replace static fields
		realCmd = self.replaceTag(realCmd, self._properties)
		
		return self.executeCmd(realCmd, self.timeout)

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
		raise RuntimeError("Command execution failed: %s" % realCmd)
	
