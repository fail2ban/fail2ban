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

import logging
import os
import sys
import time
from collections import Mapping
try:
	from collections import OrderedDict
except ImportError:
	OrderedDict = dict

from .banmanager import BanManager
from .jailthread import JailThread
from .action import ActionBase, CommandAction, CallingMap
from .mytime import MyTime
from .utils import Utils
from ..helpers import getLogger

# Gets the instance of the logger.
logSys = getLogger(__name__)


class Actions(JailThread, Mapping):
	"""Handles jail actions.

	This class handles the actions of the jail. Creation, deletion or to
	actions must be done through this class. This class is based on the
	Mapping type, and the `add` method must be used to add new actions.
	This class also starts and stops the actions, and fetches bans from
	the jail executing these bans via the actions.

	Parameters
	----------
	jail: Jail
		The jail of which the actions belongs to.

	Attributes
	----------
	daemon
	ident
	name
	status
	active : bool
		Control the state of the thread.
	idle : bool
		Control the idle state of the thread.
	sleeptime : int
		The time the thread sleeps for in the loop.
	"""

	def __init__(self, jail):
		JailThread.__init__(self)
		## The jail which contains this action.
		self._jail = jail
		self._actions = OrderedDict()
		## The ban manager.
		self.__banManager = BanManager()

	@staticmethod
	def _load_python_module(pythonModule):
		mod = Utils.load_python_module(pythonModule)
		if not hasattr(mod, "Action"): # pragma: no cover
			raise RuntimeError(
				"%s module does not have 'Action' class" % pythonModule)
		elif not issubclass(mod.Action, ActionBase): # pragma: no cover
			raise RuntimeError(
				"%s module %s does not implement required methods" % (
					pythonModule, mod.Action.__name__))
		return mod


	def add(self, name, pythonModule=None, initOpts=None, reload=False):
		"""Adds a new action.

		Add a new action if not already present, defaulting to standard
		`CommandAction`, or specified Python module.

		Parameters
		----------
		name : str
			The name of the action.
		pythonModule : str, optional
			Path to Python file which must contain `Action` class.
			Default None, which means `CommandAction` is used.
		initOpts : dict, optional
			Options for Python Action, used as keyword arguments for
			initialisation. Default None.

		Raises
		------
		ValueError
			If action name already exists.
		RuntimeError
			If external Python module does not have `Action` class
			or does not implement necessary methods as per `ActionBase`
			abstract class.
		"""
		# Check is action name already exists
		if name in self._actions:
			if not reload:
				raise ValueError("Action %s already exists" % name)
			# don't create new action if reload supported:
			action = self._actions[name]
			if hasattr(action, 'reload'):
				# don't execute reload right now, reload after all parameters are actualized
				if hasattr(action, 'clearAllParams'):
					action.clearAllParams()
					self._reload_actions[name] = initOpts
				return
		## Create new action:
		if pythonModule is None:
			action = CommandAction(self._jail, name)
		else:
			customActionModule = self._load_python_module(pythonModule)
			action = customActionModule.Action(self._jail, name, **initOpts)
		self._actions[name] = action

	def reload(self, begin=True):
		""" Begin or end of reloading resp. refreshing of all parameters
		"""
		if begin:
			self._reload_actions = dict()
		else:
			if hasattr(self, '_reload_actions'):
				# reload actions after all parameters set via stream:
				for name, initOpts in self._reload_actions.iteritems():
					if name in self._actions:
						self._actions[name].reload(**(initOpts if initOpts else {}))
				# remove obsolete actions (untouched by reload process):
				delacts = OrderedDict((name, action) for name, action in self._actions.iteritems()
					if name not in self._reload_actions)
				if len(delacts):
					# unban all tickets using remove action only:
					self.__flushBan(db=False, actions=delacts)
					# stop and remove it:
					self.stopActions(actions=delacts)
				delattr(self, '_reload_actions')

	def __getitem__(self, name):
		try:
			return self._actions[name]
		except KeyError:
			raise KeyError("Invalid Action name: %s" % name)

	def __delitem__(self, name):
		try:
			del self._actions[name]
		except KeyError:
			raise KeyError("Invalid Action name: %s" % name)

	def __iter__(self):
		return iter(self._actions)

	def __len__(self):
		return len(self._actions)

	def __eq__(self, other): # Required for Threading
		return False

	def __hash__(self): # Required for Threading
		return id(self)

	##
	# Set the ban time.
	#
	# @param value the time
	
	def setBanTime(self, value):
		value = MyTime.str2seconds(value)
		self.__banManager.setBanTime(value)
		logSys.info("  banTime: %s" % value)
	
	##
	# Get the ban time.
	#
	# @return the time
	
	def getBanTime(self):
		return self.__banManager.getBanTime()

	def removeBannedIP(self, ip=None, db=True, ifexists=False):
		"""Removes banned IP calling actions' unban method

		Remove a banned IP now, rather than waiting for it to expire,
		even if set to never expire.

		Parameters
		----------
		ip : str or IPAddr or None
			The IP address to unban or all IPs if None

		Raises
		------
		ValueError
			If `ip` is not banned
		"""
		# Unban all?
		if ip is None:
			return self.__flushBan(db)
		# Single IP:
		# Always delete ip from database (also if currently not banned)
		if db and self._jail.database is not None:
			self._jail.database.delBan(self._jail, ip)
		# Find the ticket with the IP.
		ticket = self.__banManager.getTicketByID(ip)
		if ticket is not None:
			# Unban the IP.
			self.__unBan(ticket)
		else:
			if ifexists:
				return 0
			raise ValueError("%s is not banned" % ip)
		return 1


	def stopActions(self, actions=None):
		"""Stops the actions in reverse sequence (optionally filtered)
		"""
		if actions is None:
			actions = self._actions
		revactions = actions.items()
		revactions.reverse()
		for name, action in revactions:
			try:
				action.stop()
			except Exception as e:
				logSys.error("Failed to stop jail '%s' action '%s': %s",
					self._jail.name, name, e,
					exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)
			del self._actions[name]
			logSys.debug("%s: action %s terminated", self._jail.name, name)


	def run(self):
		"""Main loop for Threading.

		This function is the main loop of the thread. It checks the jail
		queue and executes commands when an IP address is banned.

		Returns
		-------
		bool
			True when the thread exits nicely.
		"""
		for name, action in self._actions.iteritems():
			try:
				action.start()
			except Exception as e:
				logSys.error("Failed to start jail '%s' action '%s': %s",
					self._jail.name, name, e,
					exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)
		while self.active:
			if self.idle:
				Utils.wait_for(lambda: not self.active or not self.idle,
					self.sleeptime * 10, self.sleeptime)
				continue
			if not Utils.wait_for(lambda: not self.active or self.__checkBan(), self.sleeptime):
				self.__checkUnBan()
		
		self.__flushBan()
		self.stopActions()
		return True

	class ActionInfo(CallingMap):

		AI_DICT = {
			"ip":				lambda self: self.__ticket.getIP(),
			"family":   lambda self: self['ip'].familyStr,
			"ip-rev":		lambda self: self['ip'].getPTR(''),
			"ip-host":	lambda self: self['ip'].getHost(),
			"fid":			lambda self: self.__ticket.getID(),
			"failures":	lambda self: self.__ticket.getAttempt(),
			"time":			lambda self: self.__ticket.getTime(),
			"matches":	lambda self: "\n".join(self.__ticket.getMatches()),
			# to bypass actions, that should not be executed for restored tickets
			"restored":	lambda self: (1 if self.__ticket.restored else 0),
			# extra-interpolation - all match-tags (captured from the filter):
			"F-*":			lambda self, tag=None: self.__ticket.getData(tag),
			# merged info:
			"ipmatches":			lambda self: "\n".join(self._mi4ip(True).getMatches()),
			"ipjailmatches":	lambda self: "\n".join(self._mi4ip().getMatches()),
			"ipfailures":			lambda self: self._mi4ip(True).getAttempt(),
			"ipjailfailures":	lambda self: self._mi4ip().getAttempt(),
		}

		__slots__ = CallingMap.__slots__ + ('__ticket', '__jail', '__mi4ip')

		def __init__(self, ticket, jail=None, immutable=True, data=AI_DICT):
			self.__ticket = ticket
			self.__jail = jail
			self.storage = dict()
			self.immutable = immutable
			self.data = data
		
		def copy(self): # pargma: no cover
			return self.__class__(self.__ticket, self.__jail, self.immutable, self.data.copy())

		def _mi4ip(self, overalljails=False):
			"""Gets bans merged once, a helper for lambda(s), prevents stop of executing action by any exception inside.

			This function never returns None for ainfo lambdas - always a ticket (merged or single one)
			and prevents any errors through merging (to guarantee ban actions will be executed).
			[TODO] move merging to observer - here we could wait for merge and read already merged info from a database

			Parameters
			----------
			overalljails : bool
				switch to get a merged bans :
				False - (default) bans merged for current jail only
				True - bans merged for all jails of current ip address

			Returns
			-------
			BanTicket 
				merged or self ticket only
			"""
			if not hasattr(self, '__mi4ip'):
				self.__mi4ip = {}
			mi = self.__mi4ip
			idx = 'all' if overalljails else 'jail'
			if idx in mi:
				return mi[idx] if mi[idx] is not None else self.__ticket
			try:
				jail = self.__jail
				ip = self['ip']
				mi[idx] = None
				if not jail.database: # pragma: no cover
					return self.__ticket
				if overalljails:
					mi[idx] = jail.database.getBansMerged(ip=ip)
				else:
					mi[idx] = jail.database.getBansMerged(ip=ip, jail=jail)
			except Exception as e:
				logSys.error(
					"Failed to get %s bans merged, jail '%s': %s",
					idx, jail.name, e,
					exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)
			return mi[idx] if mi[idx] is not None else self.__ticket


	def __getActionInfo(self, ticket):
		ip = ticket.getIP()
		aInfo = Actions.ActionInfo(ticket, self._jail)
		return aInfo


	def __checkBan(self):
		"""Check for IP address to ban.

		Look in the jail queue for FailTicket. If a ticket is available,
		it executes the "ban" command and adds a ticket to the BanManager.

		Returns
		-------
		bool
			True if an IP address get banned.
		"""
		cnt = 0
		while cnt < 100:
			ticket = self._jail.getFailTicket()
			if not ticket:
				break
			bTicket = BanManager.createBanTicket(ticket)
			ip = bTicket.getIP()
			aInfo = self.__getActionInfo(bTicket)
			reason = {}
			if self.__banManager.addBanTicket(bTicket, reason=reason):
				cnt += 1
				logSys.notice("[%s] %sBan %s", self._jail.name, ('' if not bTicket.restored else 'Restore '), ip)
				for name, action in self._actions.iteritems():
					try:
						if ticket.restored and getattr(action, 'norestored', False):
							continue
						if not aInfo.immutable: aInfo.reset()
						action.ban(aInfo)
					except Exception as e:
						logSys.error(
							"Failed to execute ban jail '%s' action '%s' "
							"info '%r': %s",
							self._jail.name, name, aInfo, e,
							exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)
				# after all actions are processed set banned flag:
				bTicket.banned = True
			else:
				bTicket = reason['ticket']
				# if already banned (otherwise still process some action)
				if bTicket.banned:
					# compare time of failure occurrence with time ticket was really banned:
					diftm = ticket.getTime() - bTicket.getTime()
					# log already banned with following level:
					#   DEBUG   - before 3 seconds - certain interval for it, because of possible latency by recognizing in backends, etc.
					#   NOTICE  - before 60 seconds - may still occurre if action are slow, or very high load in backend,
					#   WARNING - after 60 seconds - very long time, something may be wrong
					ll = logging.DEBUG   if diftm < 3 \
					else logging.NOTICE  if diftm < 60 \
					else logging.WARNING
					logSys.log(ll, "[%s] %s already banned", self._jail.name, ip)
		if cnt:
			logSys.debug("Banned %s / %s, %s ticket(s) in %r", cnt, 
				self.__banManager.getBanTotal(), self.__banManager.size(), self._jail.name)
		return cnt

	def __checkUnBan(self):
		"""Check for IP address to unban.

		Unban IP addresses which are outdated.
		"""
		lst = self.__banManager.unBanList(MyTime.time())
		for ticket in lst:
			self.__unBan(ticket)
		cnt = len(lst)
		if cnt:
			logSys.debug("Unbanned %s, %s ticket(s) in %r", 
				cnt, self.__banManager.size(), self._jail.name)
		return cnt

	def __flushBan(self, db=False, actions=None):
		"""Flush the ban list.

		Unban all IP address which are still in the banning list.

		If actions specified, don't flush list - just execute unban for 
		given actions (reload, obsolete resp. removed actions).
		"""
		if actions is None:
			logSys.debug("Flush ban list")
			lst = self.__banManager.flushBanList()
		else:
			lst = iter(self.__banManager)
		cnt = 0
		for ticket in lst:
			# delete ip from database also:
			if db and self._jail.database is not None:
				ip = str(ticket.getIP())
				self._jail.database.delBan(self._jail, ip)
			# unban ip:
			self.__unBan(ticket, actions=actions)
			cnt += 1
		logSys.debug("Unbanned %s, %s ticket(s) in %r", 
			cnt, self.__banManager.size(), self._jail.name)
		return cnt

	def __unBan(self, ticket, actions=None):
		"""Unbans host corresponding to the ticket.

		Executes the actions in order to unban the host given in the
		ticket.

		Parameters
		----------
		ticket : FailTicket
			Ticket of failures of which to unban
		"""
		if actions is None:
			unbactions = self._actions
		else:
			unbactions = actions
		ip = ticket.getIP()
		aInfo = self.__getActionInfo(ticket)
		if actions is None:
			logSys.notice("[%s] Unban %s", self._jail.name, aInfo["ip"])
		for name, action in unbactions.iteritems():
			try:
				if ticket.restored and getattr(action, 'norestored', False):
					continue
				logSys.debug("[%s] action %r: unban %s", self._jail.name, name, ip)
				if not aInfo.immutable: aInfo.reset()
				action.unban(aInfo)
			except Exception as e:
				logSys.error(
					"Failed to execute unban jail '%s' action '%s' "
					"info '%r': %s",
					self._jail.name, name, aInfo, e,
					exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)

	def status(self, flavor="basic"):
		"""Status of current and total ban counts and current banned IP list.
		"""
		# TODO: Allow this list to be printed as 'status' output
		supported_flavors = ["basic", "cymru"]
		if flavor is None or flavor not in supported_flavors:
			logSys.warning("Unsupported extended jail status flavor %r. Supported: %s" % (flavor, supported_flavors))
		# Always print this information (basic)
		ret = [("Currently banned", self.__banManager.size()),
			   ("Total banned", self.__banManager.getBanTotal()),
			   ("Banned IP list", self.__banManager.getBanList())]
		if flavor == "cymru":
			cymru_info = self.__banManager.getBanListExtendedCymruInfo()
			ret += \
				[("Banned ASN list", self.__banManager.geBanListExtendedASN(cymru_info)),
				 ("Banned Country list", self.__banManager.geBanListExtendedCountry(cymru_info)),
				 ("Banned RIR list", self.__banManager.geBanListExtendedRIR(cymru_info))]
		return ret
