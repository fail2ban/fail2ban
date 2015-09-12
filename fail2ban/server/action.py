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

import logging
import os
import re
import signal
import subprocess
import tempfile
import threading
import time
from abc import ABCMeta
from collections import MutableMapping

from ..helpers import getLogger

# Gets the instance of the logger.
logSys = getLogger(__name__)

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
	"""A Mapping type which returns the result of callable values.

	`CallingMap` behaves similar to a standard python dictionary,
	with the exception that any values which are callable, are called
	and the result is returned as the value.
	No error handling is in place, such that any errors raised in the
	callable will raised as usual.
	Actual dictionary is stored in property `data`, and can be accessed
	to obtain original callable values.

	Attributes
	----------
	data : dict
		The dictionary data which can be accessed to obtain items uncalled
	"""

	def __init__(self, *args, **kwargs):
		self.data = dict(*args, **kwargs)

	def __repr__(self):
		return "%s(%r)" % (self.__class__.__name__, self.data)

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

	def copy(self):
		return self.__class__(self.data.copy())


class ActionBase(object):
	"""An abstract base class for actions in Fail2Ban.

	Action Base is a base definition of what methods need to be in
	place to create a Python based action for Fail2Ban. This class can
	be inherited from to ease implementation.
	Required methods:

	- __init__(jail, name)
	- start()
	- stop()
	- ban(aInfo)
	- unban(aInfo)

	Called when action is created, but before the jail/actions is
	started. This should carry out necessary methods to initialise
	the action but not "start" the action.

	Parameters
	----------
	jail : Jail
		The jail in which the action belongs to.
	name : str
		Name assigned to the action.

	Notes
	-----
	Any additional arguments specified in `jail.conf` or passed
	via `fail2ban-client` will be passed as keyword arguments.
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

	def __init__(self, jail, name):
		self._jail = jail
		self._name = name
		self._logSys = getLogger("fail2ban.%s" % self.__class__.__name__)

	def start(self):
		"""Executed when the jail/action is started.
		"""
		pass

	def stop(self):
		"""Executed when the jail/action is stopped.
		"""
		pass

	def ban(self, aInfo):
		"""Executed when a ban occurs.

		Parameters
		----------
		aInfo : dict
			Dictionary which includes information in relation to
			the ban.
		"""
		pass

	def unban(self, aInfo):
		"""Executed when a ban expires.

		Parameters
		----------
		aInfo : dict
			Dictionary which includes information in relation to
			the ban.
		"""
		pass


class CommandAction(ActionBase):
	"""A action which executes OS shell commands.

	This is the default type of action which Fail2Ban uses.

	Default sets all commands for actions as empty string, such
	no command is executed.

	Parameters
	----------
	jail : Jail
		The jail in which the action belongs to.
	name : str
		Name assigned to the action.

	Attributes
	----------
	actionban
	actionstart
	actionstop
	actionunban
	timeout
	"""

	_escapedTags = set(('matches', 'ipmatches', 'ipjailmatches'))

	def __init__(self, jail, name):
		super(CommandAction, self).__init__(jail, name)
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
		"""Time out period in seconds for execution of commands.
		"""
		return self._timeout

	@timeout.setter
	def timeout(self, timeout):
		self._timeout = int(timeout)
		self._logSys.debug("Set action %s timeout = %i" %
			(self._name, self.timeout))

	@property
	def _properties(self):
		"""A dictionary of the actions properties.

		This is used to subsitute "tags" in the commands.
		"""
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

		Replaces the tags in the action command with actions properties
		and ban information, and executes the resulting command.

		Parameters
		----------
		aInfo : dict
			Dictionary which includes information in relation to
			the ban.
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

		Replaces the tags in the action command with actions properties
		and ban information, and executes the resulting command.

		Parameters
		----------
		aInfo : dict
			Dictionary which includes information in relation to
			the ban.
		"""
		if not self._processCmd(self.actionunban, aInfo):
			raise RuntimeError("Error unbanning %(ip)s" % aInfo)

	@property
	def actioncheck(self):
		"""The command used to check the environment.

		This is used prior to a ban taking place to ensure the
		environment is appropriate. If this check fails, `stop` and
		`start` is executed prior to the check being called again.
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

		Replaces the tags in the action command with actions properties
		and executes the resulting command.
		"""
		stopCmd = self.replaceTag(self.actionstop, self._properties)
		if not self.executeCmd(stopCmd, self.timeout):
			raise RuntimeError("Error stopping action")

	@classmethod
	def substituteRecursiveTags(cls, tags):
		"""Sort out tag definitions within other tags.
		Since v.0.9.2 supports embedded interpolation (see test cases for examples).

		so:		becomes:
		a = 3		a = 3
		b = <a>_3	b = 3_3

		Parameters
		----------
		tags : dict
			Dictionary of tags(keys) and their values.

		Returns
		-------
		dict
			Dictionary of tags(keys) and their values, with tags
			within the values recursively replaced.
		"""
		t = re.compile(r'<([^ <>]+)>')
		# repeat substitution while embedded-recursive (repFlag is True)
		while True:
			repFlag = False
			# substitute each value:
			for tag in tags.iterkeys():
				if tag in cls._escapedTags:
					# Escaped so won't match
					continue
				value = str(tags[tag])
				# search and replace all tags within value, that can be interpolated using other tags:
				m = t.search(value)
				done = []
				#logSys.log(5, 'TAG: %s, value: %s' % (tag, value))
				while m:
					found_tag = m.group(1)
					#logSys.log(5, 'found: %s' % found_tag)
					if found_tag == tag or found_tag in done:
						# recursive definitions are bad
						#logSys.log(5, 'recursion fail tag: %s value: %s' % (tag, value) )
						return False
					if found_tag in cls._escapedTags or not found_tag in tags:
						# Escaped or missing tags - just continue on searching after end of match
						# Missing tags are ok - cInfo can contain aInfo elements like <HOST> and valid shell
						# constructs like <STDIN>.
						m = t.search(value, m.end())
						continue
					value = value.replace('<%s>' % found_tag , tags[found_tag])
					#logSys.log(5, 'value now: %s' % value)
					done.append(found_tag)
					m = t.search(value, m.start())
				#logSys.log(5, 'TAG: %s, newvalue: %s' % (tag, value))
				# was substituted?
				if tags[tag] != value:
					# check still contains any tag - should be repeated (possible embedded-recursive substitution):
					if t.search(value):
						repFlag = True
					tags[tag] = value
			if not repFlag:
				break
		return tags

	@staticmethod
	def escapeTag(value):
		"""Escape characters which may be used for command injection.

		Parameters
		----------
		value : str
			A string of which characters will be escaped.

		Returns
		-------
		str
			`value` with certain characters escaped.

		Notes
		-----
		The following characters are escaped::

			\\#&;`|*?~<>^()[]{}$'"

		"""
		for c in '\\#&;`|*?~<>^()[]{}$\'"':
			if c in value:
				value = value.replace(c, '\\' + c)
		return value

	@classmethod
	def replaceTag(cls, query, aInfo):
		"""Replaces tags in `query` with property values.

		Parameters
		----------
		query : str
			String with tags.
		aInfo : dict
			Tags(keys) and associated values for substitution in query.

		Returns
		-------
		str
			`query` string with tags replaced.
		"""
		string = query
		aInfo = cls.substituteRecursiveTags(aInfo)
		for tag in aInfo:
			if "<%s>" % tag in query:
				value = str(aInfo[tag])			  # assure string
				if tag in cls._escapedTags:
					# That one needs to be escaped since its content is
					# out of our control
					value = cls.escapeTag(value)
				string = string.replace('<' + tag + '>', value)
		# New line
		string = string.replace("<br>", '\n')
		return string

	def _processCmd(self, cmd, aInfo = None):
		"""Executes a command with preliminary checks and substitutions.

		Before executing any commands, executes the "check" command first
		in order to check if pre-requirements are met. If this check fails,
		it tries to restore a sane environment before executing the real
		command.

		Parameters
		----------
		cmd : str
			The command to execute.
		aInfo : dictionary
			Dynamic properties.

		Returns
		-------
		bool
			True if the command succeeded.
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
				self._logSys.critical("Unable to restore environment")
				return False

		# Replace tags
		if not aInfo is None:
			realCmd = self.replaceTag(cmd, aInfo)
		else:
			realCmd = cmd

		# Replace static fields
		realCmd = self.replaceTag(realCmd, self._properties)

		return self.executeCmd(realCmd, self.timeout)

	@staticmethod
	def executeCmd(realCmd, timeout=60):
		"""Executes a command.

		Parameters
		----------
		realCmd : str
			The command to execute.
		timeout : int
			The time out in seconds for the command.

		Returns
		-------
		bool
			True if the command succeeded.

		Raises
		------
		OSError
			If command fails to be executed.
		RuntimeError
			If command execution times out.
		"""
		logSys.debug(realCmd)
		if not realCmd:
			logSys.debug("Nothing to do")
			return True

		_cmd_lock.acquire()
		try:
			retcode = None  # to guarantee being defined upon early except
			stdout = tempfile.TemporaryFile(suffix=".stdout", prefix="fai2ban_")
			stderr = tempfile.TemporaryFile(suffix=".stderr", prefix="fai2ban_")

			popen = subprocess.Popen(
				realCmd, stdout=stdout, stderr=stderr, shell=True,
				preexec_fn=os.setsid  # so that killpg does not kill our process
			)
			stime = time.time()
			retcode = popen.poll()
			while time.time() - stime <= timeout and retcode is None:
				time.sleep(0.1)
				retcode = popen.poll()
			if retcode is None:
				logSys.error("%s -- timed out after %i seconds." %
				    (realCmd, timeout))
				pgid = os.getpgid(popen.pid)
				os.killpg(pgid, signal.SIGTERM)  # Terminate the process
				time.sleep(0.1)
				retcode = popen.poll()
				if retcode is None:  # Still going...
					os.killpg(pgid, signal.SIGKILL)  # Kill the process
					time.sleep(0.1)
					retcode = popen.poll()
		except OSError as e:
			logSys.error("%s -- failed with %s" % (realCmd, e))
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
		elif retcode < 0 or retcode > 128:
			# dash would return negative while bash 128 + n
			sigcode = -retcode if retcode < 0 else retcode - 128
			logSys.error("%s -- killed with %s (return code: %s)" %
				(realCmd, signame.get(sigcode, "signal %i" % sigcode), retcode))
		else:
			msg = _RETCODE_HINTS.get(retcode, None)
			logSys.error("%s -- returned %i" % (realCmd, retcode))
			if msg:
				logSys.info("HINT on %i: %s"
							% (retcode, msg % locals()))
		return False

