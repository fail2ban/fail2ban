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

import time, logging
import os, datetime
import sys
if sys.version_info >= (3, 3):
	import importlib.machinery
else:
	import imp
from collections import Mapping
try:
	from collections import OrderedDict
except ImportError:
	OrderedDict = None

from .banmanager import BanManager
from .observer import Observers
from .jailthread import JailThread
from .action import ActionBase, CommandAction, CallingMap
from .mytime import MyTime
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
		if OrderedDict is not None:
			self._actions = OrderedDict()
		else:
			self._actions = dict()
		## The ban manager.
		self.__banManager = BanManager()

	def add(self, name, pythonModule=None, initOpts=None):
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
			raise ValueError("Action %s already exists" % name)
		if pythonModule is None:
			action = CommandAction(self._jail, name)
		else:
			pythonModuleName = os.path.splitext(
				os.path.basename(pythonModule))[0]
			if sys.version_info >= (3, 3):
				customActionModule = importlib.machinery.SourceFileLoader(
					pythonModuleName, pythonModule).load_module()
			else:
				customActionModule = imp.load_source(
					pythonModuleName, pythonModule)
			if not hasattr(customActionModule, "Action"):
				raise RuntimeError(
					"%s module does not have 'Action' class" % pythonModule)
			elif not issubclass(customActionModule.Action, ActionBase):
				raise RuntimeError(
					"%s module %s does not implement required methods" % (
						pythonModule, customActionModule.Action.__name__))
			action = customActionModule.Action(self._jail, name, **initOpts)
		self._actions[name] = action

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
		logSys.info("Set banTime = %s" % value)
	
	##
	# Get the ban time.
	#
	# @return the time
	
	def getBanTime(self):
		return self.__banManager.getBanTime()

	def removeBannedIP(self, ip):
		"""Removes banned IP calling actions' unban method

		Remove a banned IP now, rather than waiting for it to expire,
		even if set to never expire.

		Parameters
		----------
		ip : str
			The IP address to unban

		Raises
		------
		ValueError
			If `ip` is not banned
		"""
		# Always delete ip from database (also if currently not banned)
		if self._jail.database is not None:
			self._jail.database.delBan(self._jail, ip)
		# Find the ticket with the IP.
		ticket = self.__banManager.getTicketByIP(ip)
		if ticket is not None:
			# Unban the IP.
			self.__unBan(ticket)
		else:
			raise ValueError("IP %s is not banned" % ip)

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
			if not self.idle:
				#logSys.debug(self._jail.name + ": action")
				ret = self.__checkBan()
				if not ret:
					self.__checkUnBan()
					time.sleep(self.sleeptime)
			else:
				time.sleep(self.sleeptime)
		self.__flushBan()

		actions = self._actions.items()
		actions.reverse()
		for name, action in actions:
			try:
				action.stop()
			except Exception as e:
				logSys.error("Failed to stop jail '%s' action '%s': %s",
					self._jail.name, name, e,
					exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)
		logSys.debug(self._jail.name + ": action terminated")
		return True

	def __getBansMerged(self, mi, idx):
		"""Helper for lamda to get bans merged once

		This function never returns None for ainfo lambdas - always a ticket (merged or single one)
		and prevents any errors through merging (to guarantee ban actions will be executed).
		[TODO] move merging to observer - here we could wait for merge and read already merged info from a database

		Parameters
		----------
		mi : dict
			initial for lambda should contains {ip, ticket}
		idx : str
			key to get a merged bans :
			'all' - bans merged for all jails
			'jail' - bans merged for current jail only

		Returns
		-------
		BanTicket 
			merged or self ticket only
		"""
		if idx in mi:
			return mi[idx] if mi[idx] is not None else mi['ticket']
		try:
			jail=self._jail
			ip=mi['ip']
			mi[idx] = None
			if idx == 'all':
				mi[idx] = jail.database.getBansMerged(ip=ip)
			elif idx == 'jail':
				mi[idx] = jail.database.getBansMerged(ip=ip, jail=jail)
		except Exception as e:
			logSys.error(
				"Failed to get %s bans merged, jail '%s': %s",
				idx, jail.name, e,
				exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)
		return mi[idx] if mi[idx] is not None else mi['ticket']

	def __checkBan(self):
		"""Check for IP address to ban.

		Look in the jail queue for FailTicket. If a ticket is available,
		it executes the "ban" command and adds a ticket to the BanManager.

		Returns
		-------
		bool
			True if an IP address get banned.
		"""
		ticket = self._jail.getFailTicket()
		if ticket != False:
			aInfo = CallingMap()
			bTicket = BanManager.createBanTicket(ticket)
			if ticket.getBanTime() is not None:
				bTicket.setBanTime(ticket.getBanTime())
				bTicket.setBanCount(ticket.getBanCount())
			if ticket.getRestored():
				bTicket.setRestored(True)
			ip = bTicket.getIP()
			aInfo["ip"] = ip
			aInfo["failures"] = bTicket.getAttempt()
			aInfo["time"] = bTicket.getTime()
			aInfo["matches"] = "\n".join(bTicket.getMatches())
			btime = bTicket.getBanTime(self.__banManager.getBanTime())
			# retarded merge info via twice lambdas : once for merge, once for matches/failures:
			if self._jail.database is not None:
				mi4ip = lambda idx, self=self, mi={'ip':ip, 'ticket':bTicket}: self.__getBansMerged(mi, idx)
				aInfo["ipmatches"]      = lambda: "\n".join(mi4ip('all').getMatches())
				aInfo["ipjailmatches"]  = lambda: "\n".join(mi4ip('jail').getMatches())
				aInfo["ipfailures"]     = lambda: mi4ip('all').getAttempt()
				aInfo["ipjailfailures"] = lambda: mi4ip('jail').getAttempt()

			if btime != -1:
				bendtime = aInfo["time"] + btime
				logtime = (datetime.timedelta(seconds=int(btime)),
					datetime.datetime.fromtimestamp(bendtime).strftime("%Y-%m-%d %H:%M:%S"))
				# check ban is not too old :
				if bendtime < MyTime.time():
					logSys.info('[%s] Ignore %s, expired bantime - %s', self._jail.name, ip, logtime[1])
					return False
			else:
				logtime = ('permanent', 'infinite')

			if self.__banManager.addBanTicket(bTicket):
				# report ticket to observer, to check time should be increased and hereafter observer writes ban to database (asynchronous)
				if Observers.Main is not None and not bTicket.getRestored():
					Observers.Main.add('banFound', bTicket, self._jail, btime)
				logSys.notice("[%s] %sBan %s (%s # %s -> %s)", self._jail.name, ('' if not bTicket.getRestored() else 'Restore '),
					aInfo["ip"], (bTicket.getBanCount() if bTicket.getRestored() else '_'), *logtime)
				# do actions :
				for name, action in self._actions.iteritems():
					try:
						action.ban(aInfo.copy())
					except Exception as e:
						logSys.error(
							"Failed to execute ban jail '%s' action '%s' "
							"info '%r': %s",
							self._jail.name, name, aInfo, e,
							exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)
				return True
			else:
				logSys.notice("[%s] %s already banned (%d # %s -> %s)" % ((self._jail.name,
					aInfo["ip"], bTicket.getBanCount()) + logtime))
		return False

	def __checkUnBan(self):
		"""Check for IP address to unban.

		Unban IP addresses which are outdated.
		"""
		for ticket in self.__banManager.unBanList(MyTime.time()):
			self.__unBan(ticket)

	def __flushBan(self):
		"""Flush the ban list.

		Unban all IP address which are still in the banning list.
		"""
		logSys.debug("Flush ban list")
		for ticket in self.__banManager.flushBanList():
			self.__unBan(ticket)

	def __unBan(self, ticket):
		"""Unbans host corresponding to the ticket.

		Executes the actions in order to unban the host given in the
		ticket.

		Parameters
		----------
		ticket : FailTicket
			Ticket of failures of which to unban
		"""
		aInfo = dict()
		aInfo["ip"] = ticket.getIP()
		aInfo["failures"] = ticket.getAttempt()
		aInfo["time"] = ticket.getTime()
		aInfo["matches"] = "".join(ticket.getMatches())
		logSys.notice("[%s] Unban %s" % (self._jail.name, aInfo["ip"]))
		for name, action in self._actions.iteritems():
			try:
				action.unban(aInfo.copy())
			except Exception as e:
				logSys.error(
					"Failed to execute unban jail '%s' action '%s' "
					"info '%r': %s",
					self._jail.name, name, aInfo, e,
					exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)

	@property
	def status(self):
		"""Status of active bans, and total ban counts.
		"""
		ret = [("Currently banned", self.__banManager.size()), 
			   ("Total banned", self.__banManager.getBanTotal()),
			   ("Banned IP list", self.__banManager.getBanList())]
		return ret
