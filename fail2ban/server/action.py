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

from .failregex import mapTag2Opt
from .ipdns import asip, DNSUtils
from .mytime import MyTime
from .utils import Utils
from ..helpers import getLogger, _merge_copy_dicts, uni_string, substituteRecursiveTags, TAG_CRE, MAX_TAG_REPLACE_COUNT

# Gets the instance of the logger.
logSys = getLogger(__name__)

# Create a lock for running system commands
_cmd_lock = threading.Lock()

# Todo: make it configurable resp. automatically set, ex.: `[ -f /proc/net/if_inet6 ] && echo 'yes' || echo 'no'`:
allowed_ipv6 = True

# capture groups from filter for map to ticket data:
FCUSTAG_CRE = re.compile(r'<F-([A-Z0-9_\-]+)>'); # currently uppercase only

CONDITIONAL_FAM_RE = re.compile(r"^(\w+)\?(family)=")

# Special tags:
DYN_REPL_TAGS = {
  # System-information:
	"fq-hostname":	lambda: str(DNSUtils.getHostname(fqdn=True)),
	"sh-hostname":	lambda: str(DNSUtils.getHostname(fqdn=False))
}
# New line, space
ADD_REPL_TAGS = {
  "br": "\n", 
  "sp": " "
}
ADD_REPL_TAGS.update(DYN_REPL_TAGS)


class CallingMap(MutableMapping, object):
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

	CM_REPR_ITEMS = ()

	# immutable=True saves content between actions, without interim copying (save original on demand, recoverable via reset)
	__slots__ = ('data', 'storage', 'immutable', '__org_data')
	def __init__(self, *args, **kwargs):
		self.storage = dict()
		self.immutable = True
		self.data = dict(*args, **kwargs)

	def reset(self, immutable=True):
		self.storage = dict()
		try:
			self.data = self.__org_data
		except AttributeError:
			pass
		self.immutable = immutable

	def _asrepr(self, calculated=False):
		# be sure it is suitable as string, so use str as checker:
		return "%s(%r)" % (self.__class__.__name__, self._asdict(calculated, str))

	__repr__ = _asrepr

	def _asdict(self, calculated=False, checker=None):
		d = dict(self.data, **self.storage)
		if not calculated:
			return dict((n,v) for n,v in d.iteritems() \
				if not callable(v) or n in self.CM_REPR_ITEMS)
		for n,v in d.items():
			if callable(v):
				try:
					# calculate:
					v = self.__getitem__(n)
					# convert if needed:
					if checker: checker(v)
					# store calculated:
					d[n] = v
				except: # can't calculate - just ignore it
					pass
		return d

	def getRawItem(self, key):
		try:
			value = self.storage[key]
		except KeyError:
			value = self.data[key]
		return value

	def __getitem__(self, key):
		try:
			value = self.storage[key]
		except KeyError:
			value = self.data[key]
		if callable(value):
			# check arguments can be supplied to callable (for backwards compatibility):
			value = value(self) if hasattr(value, '__code__') and value.__code__.co_argcount else value()
			self.storage[key] = value
		return value

	def __setitem__(self, key, value):
		# mutate to copy:
		if self.immutable:
			self.storage = self.storage.copy()
			self.__org_data = self.data
			self.data = self.data.copy()
			self.immutable = False
		self.storage[key] = value

	def __unavailable(self, key):
		raise KeyError("Key %r was deleted" % key)

	def __delitem__(self, key):
		# mutate to copy:
		if self.immutable:
			self.storage = self.storage.copy()
			self.__org_data = self.data
			self.data = self.data.copy()
			self.immutable = False
		try:
			del self.storage[key]
		except KeyError:
			pass
		del self.data[key]

	def __iter__(self):
		return iter(self.data)

	def __len__(self):
		return len(self.data)

	def copy(self): # pragma: no cover
		return self.__class__(_merge_copy_dicts(self.data, self.storage))


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

	def start(self): # pragma: no cover - abstract
		"""Executed when the jail/action is started.
		"""
		pass

	def stop(self): # pragma: no cover - abstract
		"""Executed when the jail/action is stopped.
		"""
		pass

	def ban(self, aInfo): # pragma: no cover - abstract
		"""Executed when a ban occurs.

		Parameters
		----------
		aInfo : dict
			Dictionary which includes information in relation to
			the ban.
		"""
		pass

	@property
	def _prolongable(self): # pragma: no cover - abstract
		return False

	def unban(self, aInfo): # pragma: no cover - abstract
		"""Executed when a ban expires.

		Parameters
		----------
		aInfo : dict
			Dictionary which includes information in relation to
			the ban.
		"""
		pass


WRAP_CMD_PARAMS = {
	'timeout': 'str2seconds',
	'bantime': 'ignore',
}

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
			## Command executed in order to flush all bans at once (e. g. by stop/shutdown the system).
			self.actionflush = ''
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
		self.__started = {}
		self.__substCache = {}
		self.clearAllParams()
		self._logSys.debug("Created %s" % self.__class__)

	@classmethod
	def __subclasshook__(cls, C):
		return NotImplemented # Standard checks

	def __setattr__(self, name, value):
		if not name.startswith('_') and not self.__init and not callable(value):
			# special case for some parameters:
			wrp = WRAP_CMD_PARAMS.get(name)
			if wrp == 'ignore': # ignore (filter) dynamic parameters
				return
			elif wrp == 'str2seconds':
				value = str(MyTime.str2seconds(value))
			# parameters changed - clear properties and substitution cache:
			self.__properties = None
			self.__substCache.clear()
			#self._logSys.debug("Set action %r %s = %r", self._name, name, value)
			self._logSys.debug("  Set %s = %r", name, value)
		# set:
		self.__dict__[name] = value

	def __delattr__(self, name):
		if not name.startswith('_'):
			# parameters changed - clear properties and substitution cache:
			self.__properties = None
			self.__substCache.clear()
			#self._logSys.debug("Unset action %r %s", self._name, name)
			self._logSys.debug("  Unset %s", name)
		# del:
		del self.__dict__[name]

	@property
	def _properties(self):
		"""A dictionary of the actions properties.

		This is used to substitute "tags" in the commands.
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

	def _getOperation(self, tag, family):
		return self.replaceTag(tag, self._properties,
			conditional=('family=' + family), cache=self.__substCache)

	def _executeOperation(self, tag, operation, family=[]):
		"""Executes the operation commands (like "actionstart", "actionstop", etc).

		Replace the tags in the action command with actions properties
		and executes the resulting command.
		"""
		# check valid tags in properties (raises ValueError if self recursion, etc.):
		res = True
		try:
			# common (resp. ipv4):
			startCmd = None
			if not family or 'inet4' in family:
				startCmd = self._getOperation(tag, 'inet4')
				if startCmd:
					res &= self.executeCmd(startCmd, self.timeout)
			# start ipv6 actions if available:
			if allowed_ipv6 and (not family or 'inet6' in family):
				startCmd6 = self._getOperation(tag, 'inet6')
				if startCmd6 and startCmd6 != startCmd:
					res &= self.executeCmd(startCmd6, self.timeout)
			if not res:
				raise RuntimeError("Error %s action %s/%s" % (operation, self._jail, self._name,))
		except ValueError as e:
			raise RuntimeError("Error %s action %s/%s: %r" % (operation, self._jail, self._name, e))

	COND_FAMILIES = ('inet4', 'inet6')

	@property
	def _startOnDemand(self):
		"""Checks the action depends on family (conditional)"""
		v = self._properties.get('actionstart_on_demand')
		if v is None:
			v = False
			for n in self._properties:
				if CONDITIONAL_FAM_RE.match(n):
					v = True
					break
		self._properties['actionstart_on_demand'] = v
		return v

	def start(self, family=[]):
		"""Executes the "actionstart" command.

		Replace the tags in the action command with actions properties
		and executes the resulting command.
		"""
		if not family:
			# check the action depends on family (conditional):
			if self._startOnDemand:
				return True
		elif self.__started.get(family): # pragma: no cover - normally unreachable
			return True
		return self._executeOperation('<actionstart>', 'starting', family=family)

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
		# if we should start the action on demand (conditional by family):
		if self._startOnDemand:
			family = aInfo.get('family')
			if not self.__started.get(family):
				self.start(family)
				self.__started[family] = 1
				# mark also another families as "started" (-1), if they are equal
				# (on demand, but the same for ipv4 and ipv6):
				cmd = self._getOperation('<actionstart>', family)
				for f in CommandAction.COND_FAMILIES:
					if f != family and not self.__started.get(f):
						if cmd == self._getOperation('<actionstart>', f):
							self.__started[f] = -1
		# ban:
		if not self._processCmd('<actionban>', aInfo):
			raise RuntimeError("Error banning %(ip)s" % aInfo)

	@property
	def _prolongable(self):
		return (hasattr(self, 'actionprolong') and self.actionprolong 
			and not str(self.actionprolong).isspace())
	
	def prolong(self, aInfo):
		"""Executes the "actionprolong" command.

		Replaces the tags in the action command with actions properties
		and ban information, and executes the resulting command.

		Parameters
		----------
		aInfo : dict
			Dictionary which includes information in relation to
			the ban.
		"""
		if not self._processCmd('<actionprolong>', aInfo):
			raise RuntimeError("Error prolonging %(ip)s" % aInfo)

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

	def flush(self):
		"""Executes the "actionflush" command.
		
		Command executed in order to flush all bans at once (e. g. by stop/shutdown 
		the system), instead of unbanning of each single ticket.

		Replaces the tags in the action command with actions properties
		and executes the resulting command.
		"""
		family = []
		# collect started families, if started on demand (conditional):
		if self._startOnDemand:
			for f in CommandAction.COND_FAMILIES:
				if self.__started.get(f) == 1: # only real started:
					family.append(f)
			# if no started (on demand) actions:
			if not family: return True
		return self._executeOperation('<actionflush>', 'flushing', family=family)

	def stop(self):
		"""Executes the "actionstop" command.

		Replaces the tags in the action command with actions properties
		and executes the resulting command.
		"""
		family = []
		# collect started families, if started on demand (conditional):
		if self._startOnDemand:
			for f in CommandAction.COND_FAMILIES:
				if self.__started.get(f) == 1: # only real started:
					family.append(f)
					self.__started[f] = 0
			# if no started (on demand) actions:
			if not family: return True
		return self._executeOperation('<actionstop>', 'stopping', family=family)

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

	ESCAPE_CRE = re.compile(r"""[\\#&;`|*?~<>^()\[\]{}$'"\n\r]""")
	
	@classmethod
	def escapeTag(cls, value):
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

			\\#&;`|*?~<>^()[]{}$'"\n\r

		"""
		_map2c = {'\n': 'n', '\r': 'r'}
		def substChar(m):
			c = m.group()
			return '\\' + _map2c.get(c, c)
		
		value = cls.ESCAPE_CRE.sub(substChar, value)
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
		if '<' not in query: return query

		# use cache if allowed:
		if cache is not None:
			ckey = (query, conditional)
			try:
				return cache[ckey]
			except KeyError:
				pass

		# **Important**: don't replace if calling map - contains dynamic values only,
		# no recursive tags, otherwise may be vulnerable on foreign user-input:
		noRecRepl = isinstance(aInfo, CallingMap)
		subInfo = aInfo
		if not noRecRepl:
			# substitute tags recursive (and cache if possible),
			# first try get cached tags dictionary:
			subInfo = csubkey = None
			if cache is not None:
				csubkey = ('subst-tags', id(aInfo), conditional)
				try:
					subInfo = cache[csubkey]
				except KeyError:
					pass
			# interpolation of dictionary:
			if subInfo is None:
				subInfo = substituteRecursiveTags(aInfo, conditional, ignore=cls._escapedTags)
			# cache if possible:
			if csubkey is not None:
				cache[csubkey] = subInfo

		# additional replacement as calling map:
		ADD_REPL_TAGS_CM = CallingMap(ADD_REPL_TAGS)
		# substitution callable, used by interpolation of each tag
		def substVal(m):
			tag = m.group(1)			# tagname from match
			value = None
			if conditional:
				value = subInfo.get(tag + '?' + conditional)
			if value is None:
				value = subInfo.get(tag)
				if value is None:
					# fallback (no or default replacement)
					return ADD_REPL_TAGS_CM.get(tag, m.group())
			value = uni_string(value)		# assure string
			if tag in cls._escapedTags:
				# That one needs to be escaped since its content is
				# out of our control
				value = cls.escapeTag(value)
			# replacement for tag:
			return value

		# interpolation of query:
		count = MAX_TAG_REPLACE_COUNT + 1
		while True:
			value = TAG_CRE.sub(substVal, query)
			# **Important**: no recursive replacement for tags from calling map (properties only):
			if noRecRepl: break
			# possible recursion ?
			if value == query or '<' not in value: break
			query = value
			count -= 1
			if count <= 0:
				raise ValueError(
					"unexpected too long replacement interpolation, "
					"possible self referencing definitions in query: %s" % (query,))

		# cache if possible:
		if cache is not None:
			cache[ckey] = value
		#
		return value

	ESCAPE_CRE = re.compile(r"""[\\#&;`|*?~<>\^\(\)\[\]{}$'"\n\r]""")
	ESCAPE_VN_CRE = re.compile(r"\W")

	@classmethod
	def replaceDynamicTags(cls, realCmd, aInfo):
		"""Replaces dynamical tags in `query` with property values.

		**Important**
		-------------
		Because this tags are dynamic resp. foreign (user) input:
		  - values should be escaped (using "escape" as shell variable)
		  - no recursive substitution (no interpolation for <a<b>>)
		  - don't use cache

		Parameters
		----------
		query : str
			String with tags.
		aInfo : dict
			Tags(keys) and associated values for substitution in query.

		Returns
		-------
		str
			shell script as string or array with tags replaced (direct or as variables).
		"""
		# array for escaped vars:
		varsDict = dict()

		def escapeVal(tag, value):
			# if the value should be escaped:
			if cls.ESCAPE_CRE.search(value):
				# That one needs to be escaped since its content is
				# out of our control
				tag = 'f2bV_%s' % cls.ESCAPE_VN_CRE.sub('_', tag)
				varsDict[tag] = value # add variable
				value = '$'+tag	# replacement as variable
			# replacement for tag:
			return value

		# additional replacement as calling map:
		ADD_REPL_TAGS_CM = CallingMap(ADD_REPL_TAGS)
		# substitution callable, used by interpolation of each tag
		def substVal(m):
			tag = m.group(1)			# tagname from match
			try:
				value = aInfo[tag]
			except KeyError:
				# fallback (no or default replacement)
				return ADD_REPL_TAGS_CM.get(tag, m.group())
			value = uni_string(value)		# assure string
			# replacement for tag:
			return escapeVal(tag, value)
		
		# Replace normally properties of aInfo non-recursive:
		realCmd = TAG_CRE.sub(substVal, realCmd)

		# Replace ticket options (filter capture groups) non-recursive:
		if '<' in realCmd:
			tickData = aInfo.get("F-*")
			if not tickData: tickData = {}
			def substTag(m):
				tag = mapTag2Opt(m.groups()[0])
				try:
					value = uni_string(tickData[tag])
				except KeyError:
					return ""
				return escapeVal("F_"+tag, value)
			
			realCmd = FCUSTAG_CRE.sub(substTag, realCmd)

		# build command corresponding "escaped" variables:
		if varsDict:
			realCmd = Utils.buildShellCmd(realCmd, varsDict)
		return realCmd

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
					try:
						self.stop()
					except RuntimeError: # bypass error in stop (if start/check succeeded hereafter).
						pass
					self.start()
				if not self.executeCmd(checkCmd, self.timeout):
					self._logSys.critical("Unable to restore environment")
					return False

		# Replace static fields
		realCmd = self.replaceTag(cmd, self._properties, 
			conditional=conditional, cache=self.__substCache)

		# Replace dynamical tags, important - don't cache, no recursion and auto-escape here
		if aInfo is not None:
			realCmd = self.replaceDynamicTags(realCmd, aInfo)
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
		if logSys.getEffectiveLevel() < logging.DEBUG: # pragma: no cover
			logSys.log(9, realCmd)
		if not realCmd:
			logSys.debug("Nothing to do")
			return True

		with _cmd_lock:
			return Utils.executeCmd(realCmd, timeout, shell=True, output=False, **kwargs)
