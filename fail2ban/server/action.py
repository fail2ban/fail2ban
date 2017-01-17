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

from .ipdns import asip
from .mytime import MyTime
from .utils import Utils
from ..helpers import getLogger

# Gets the instance of the logger.
logSys = getLogger(__name__)

# Create a lock for running system commands
_cmd_lock = threading.Lock()

# Todo: make it configurable resp. automatically set, ex.: `[ -f /proc/net/if_inet6 ] && echo 'yes' || echo 'no'`:
allowed_ipv6 = True

# max tag replacement count:
MAX_TAG_REPLACE_COUNT = 10

# compiled RE for tag name (replacement name) 
TAG_CRE = re.compile(r'<([^ <>]+)>')


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
	actioncheck
	actionreload
	actionrepair
	actionstart
	actionstop
	actionunban
	timeout
	"""

	_escapedTags = set(('matches', 'ipmatches', 'ipjailmatches'))

	def clearAllParams(self):
		""" Clear all lists/dicts parameters (used by reloading)
		"""
		self.__init = 1
		try:
			self.timeout = 60
			## Command executed in order to initialize the system.
			self.actionstart = ''
			## Command executed when ticket gets banned.
			self.actionban = ''
			## Command executed when ticket gets removed.
			self.actionunban = ''
			## Command executed in order to check requirements.
			self.actioncheck = ''
			## Command executed in order to restore sane environment in error case.
			self.actionrepair = ''
			## Command executed in order to stop the system.
			self.actionstop = ''
			## Command executed in case of reloading action.
			self.actionreload = ''
		finally:
			self.__init = 0

	def __init__(self, jail, name):
		super(CommandAction, self).__init__(jail, name)
		self.__init = 1
		self.__properties = None
		self.__substCache = {}
		self.clearAllParams()
		self._logSys.debug("Created %s" % self.__class__)

	@classmethod
	def __subclasshook__(cls, C):
		return NotImplemented # Standard checks

	def __setattr__(self, name, value):
		if not name.startswith('_') and not self.__init and not callable(value):
			# special case for some pasrameters:
			if name in ('timeout', 'bantime'):
				value = str(MyTime.str2seconds(value))
			# parameters changed - clear properties and substitution cache:
			self.__properties = None
			self.__substCache.clear()
			#self._logSys.debug("Set action %r %s = %r", self._name, name, value)
			self._logSys.debug("  Set %s = %r", name, value)
		# set:
		self.__dict__[name] = value

	@property
	def _properties(self):
		"""A dictionary of the actions properties.

		This is used to subsitute "tags" in the commands.
		"""
		# if we have a properties - return it:
		if self.__properties is not None:
			return self.__properties
		# otherwise retrieve:
		self.__properties = dict(
			(key, getattr(self, key))
			for key in dir(self)
			if not key.startswith("_") and not callable(getattr(self, key)))
		#
		return self.__properties

	@property
	def _substCache(self):
		return self.__substCache

	def _executeOperation(self, tag, operation):
		"""Executes the operation commands (like "actionstart", "actionstop", etc).

		Replace the tags in the action command with actions properties
		and executes the resulting command.
		"""
		# check valid tags in properties (raises ValueError if self recursion, etc.):
		res = True
		try:
			# common (resp. ipv4):
			startCmd = self.replaceTag(tag, self._properties, 
				conditional='family=inet4', cache=self.__substCache)
			if startCmd:
				res &= self.executeCmd(startCmd, self.timeout)
			# start ipv6 actions if available:
			if allowed_ipv6:
				startCmd6 = self.replaceTag(tag, self._properties, 
					conditional='family=inet6', cache=self.__substCache)
				if startCmd6 and startCmd6 != startCmd:
					res &= self.executeCmd(startCmd6, self.timeout)
			if not res:
				raise RuntimeError("Error %s action %s/%s" % (operation, self._jail, self._name,))
		except ValueError as e:
			raise RuntimeError("Error %s action %s/%s: %r" % (operation, self._jail, self._name, e))

	def start(self):
		"""Executes the "actionstart" command.

		Replace the tags in the action command with actions properties
		and executes the resulting command.
		"""
		return self._executeOperation('<actionstart>', 'starting')

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
		if not self._processCmd('<actionban>', aInfo):
			raise RuntimeError("Error banning %(ip)s" % aInfo)

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
		if not self._processCmd('<actionunban>', aInfo):
			raise RuntimeError("Error unbanning %(ip)s" % aInfo)

	def stop(self):
		"""Executes the "actionstop" command.

		Replaces the tags in the action command with actions properties
		and executes the resulting command.
		"""
		return self._executeOperation('<actionstop>', 'stopping')

	def reload(self, **kwargs):
		"""Executes the "actionreload" command.

		Parameters
		----------
		kwargs : dict
		  Currently unused, because CommandAction do not support initOpts

		Replaces the tags in the action command with actions properties
		and executes the resulting command.
		"""
		return self._executeOperation('<actionreload>', 'reloading')

	@classmethod
	def substituteRecursiveTags(cls, inptags, conditional='', ignore=()):
		"""Sort out tag definitions within other tags.
		Since v.0.9.2 supports embedded interpolation (see test cases for examples).

		so:		becomes:
		a = 3		a = 3
		b = <a>_3	b = 3_3

		Parameters
		----------
		inptags : dict
			Dictionary of tags(keys) and their values.

		Returns
		-------
		dict
			Dictionary of tags(keys) and their values, with tags
			within the values recursively replaced.
		"""
		# copy return tags dict to prevent modifying of inptags:
		tags = inptags.copy()
		t = TAG_CRE
		ignore = set(ignore)
		done = cls._escapedTags.copy() | ignore
		# repeat substitution while embedded-recursive (repFlag is True)
		while True:
			repFlag = False
			# substitute each value:
			for tag in tags.iterkeys():
				# ignore escaped or already done (or in ignore list):
				if tag in done: continue
				value = orgval = str(tags[tag])
				# search and replace all tags within value, that can be interpolated using other tags:
				m = t.search(value)
				refCounts = {}
				#logSys.log(5, 'TAG: %s, value: %s' % (tag, value))
				while m:
					found_tag = m.group(1)
					# don't replace tags that should be currently ignored (pre-replacement):
					if found_tag in ignore: 
						m = t.search(value, m.end())
						continue
					#logSys.log(5, 'found: %s' % found_tag)
					if found_tag == tag or refCounts.get(found_tag, 1) > MAX_TAG_REPLACE_COUNT:
						# recursive definitions are bad
						#logSys.log(5, 'recursion fail tag: %s value: %s' % (tag, value) )
						raise ValueError(
							"properties contain self referencing definitions "
							"and cannot be resolved, fail tag: %s, found: %s in %s, value: %s" % 
							(tag, found_tag, refCounts, value))
					repl = None
					if found_tag not in cls._escapedTags:
						repl = tags.get(found_tag + '?' + conditional)
						if repl is None:
							repl = tags.get(found_tag)
					if repl is None:
						# Escaped or missing tags - just continue on searching after end of match
						# Missing tags are ok - cInfo can contain aInfo elements like <HOST> and valid shell
						# constructs like <STDIN>.
						m = t.search(value, m.end())
						continue
					value = value.replace('<%s>' % found_tag, repl)
					#logSys.log(5, 'value now: %s' % value)
					# increment reference count:
					refCounts[found_tag] = refCounts.get(found_tag, 0) + 1
					# the next match for replace:
					m = t.search(value, m.start())
				#logSys.log(5, 'TAG: %s, newvalue: %s' % (tag, value))
				# was substituted?
				if orgval != value:
					# check still contains any tag - should be repeated (possible embedded-recursive substitution):
					if t.search(value):
						repFlag = True
					tags[tag] = value
				# no more sub tags (and no possible composite), add this tag to done set (just to be faster):
				if '<' not in value: done.add(tag)
			# stop interpolation, if no replacements anymore:
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
	def replaceTag(cls, query, aInfo, conditional='', cache=None):
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
		# use cache if allowed:
		if cache is not None:
			ckey = (query, conditional)
			string = cache.get(ckey)
			if string is not None:
				return string
		# replace:
		string = query
		aInfo = cls.substituteRecursiveTags(aInfo, conditional)
		for tag in aInfo:
			if "<%s>" % tag in query:
				value = aInfo.get(tag + '?' + conditional)
				if value is None:
					value = aInfo.get(tag)
				value = str(value)			  # assure string
				if tag in cls._escapedTags:
					# That one needs to be escaped since its content is
					# out of our control
					value = cls.escapeTag(value)
				string = string.replace('<' + tag + '>', value)
		# New line, space
		string = reduce(lambda s, kv: s.replace(*kv), (("<br>", '\n'), ("<sp>", " ")), string)
		# cache if properties:
		if cache is not None:
			cache[ckey] = string
		#
		return string

	def _processCmd(self, cmd, aInfo=None, conditional=''):
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

		# conditional corresponding family of the given ip:
		if conditional == '':
			conditional = 'family=inet4'
			if allowed_ipv6:
				try:
					ip = aInfo["ip"]
					if ip and asip(ip).isIPv6:
						conditional = 'family=inet6'
				except KeyError:
					pass

		checkCmd = self.replaceTag('<actioncheck>', self._properties, 
			conditional=conditional, cache=self.__substCache)
		if checkCmd:
			if not self.executeCmd(checkCmd, self.timeout):
				self._logSys.error(
					"Invariant check failed. Trying to restore a sane environment")
				# try to find repair command, if exists - exec it:
				repairCmd = self.replaceTag('<actionrepair>', self._properties, 
					conditional=conditional, cache=self.__substCache)
				if repairCmd:
					if not self.executeCmd(repairCmd, self.timeout):
						self._logSys.critical("Unable to restore environment")
						return False
				else:
					# no repair command, try to restart action...
					# [WARNING] TODO: be sure all banactions get a repair command, because
					#    otherwise stop/start will theoretically remove all the bans,
					#    but the tickets are still in BanManager, so in case of new failures
					#    it will not be banned, because "already banned" will happen.
					self.stop()
					self.start()
				if not self.executeCmd(checkCmd, self.timeout):
					self._logSys.critical("Unable to restore environment")
					return False

		# Replace static fields
		realCmd = self.replaceTag(cmd, self._properties, 
			conditional=conditional, cache=self.__substCache)

		# Replace tags
		if aInfo is not None:
			realCmd = self.replaceTag(realCmd, aInfo, conditional=conditional)
		else:
			realCmd = cmd

		return self.executeCmd(realCmd, self.timeout)

	@staticmethod
	def executeCmd(realCmd, timeout=60, **kwargs):
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
			return Utils.executeCmd(realCmd, timeout, shell=True, output=False, **kwargs)
		finally:
			_cmd_lock.release()
