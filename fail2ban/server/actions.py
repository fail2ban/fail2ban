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
import os, datetime, math, json, random
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
from .jailthread import JailThread
from .action import ActionBase, CommandAction, CallingMap
from .mytime import MyTime

# Gets the instance of the logger.
logSys = logging.getLogger(__name__)

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
		## Extra parameters for increase ban time
		self._banExtra = {'maxtime': 24*60*60};

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

	class BanTimeIncr:
		def __init__(self, banTime, banCount):
			self.Time = banTime
			self.Count = banCount

	def setBanTimeExtra(self, opt, value):
		# merge previous extra with new option:
		be = self._banExtra;
		if value == '':
			value = None
		if value is not None:
			be[opt] = value;
		elif opt in be:
			del be[opt]
		logSys.info('Set banTimeExtra.%s = %s', opt, value)
		if opt == 'enabled':
			if isinstance(value, str):
				be[opt] = value.lower() in ("yes", "true", "ok", "1")
			if be[opt] and self._jail.database is None:
				logSys.warning("banTimeExtra is not available as long jail database is not set")
		if opt in ['findtime', 'maxtime', 'rndtime']:
			if not value is None:
				be[opt] = eval(value)
		# prepare formula lambda:
		if opt in ['formula', 'factor', 'maxtime', 'rndtime', 'multipliers'] or be.get('evformula', None) is None:
			# split multifiers to an array begins with 0 (or empty if not set):
			if opt == 'multipliers':
				be['evmultipliers'] = [int(i) for i in (value.split(' ') if value is not None and value != '' else [])]
			# if we have multifiers - use it in lambda, otherwise compile and use formula within lambda
			multipliers = be.get('evmultipliers', [])
			if len(multipliers):
				banFactor = eval(be.get('factor', "1"))
				evformula = lambda ban, banFactor=banFactor: (
					ban.Time * banFactor * multipliers[ban.Count if ban.Count < len(multipliers) else -1]
				)
			else:
				banFactor = eval(be.get('factor', "2.0 / 2.885385"))
				formula = be.get('formula', 'ban.Time * math.exp(float(ban.Count+1)*banFactor)/math.exp(1*banFactor)')
				formula = compile(formula, '~inline-conf-expr~', 'eval')
				evformula = lambda ban, banFactor=banFactor, formula=formula: max(ban.Time, eval(formula))
			# extend lambda with max time :
			if not be.get('maxtime', None) is None:
				maxtime = be['maxtime']
				evformula = lambda ban, evformula=evformula: min(evformula(ban), maxtime)
			# mix lambda with random time (to prevent bot-nets to calculate exact time IP can be unbanned):
			if not be.get('rndtime', None) is None:
				rndtime = be['rndtime']
				evformula = lambda ban, evformula=evformula: (evformula(ban) + random.random() * rndtime)
			# set to extra dict:
			be['evformula'] = evformula
		#logSys.info('banTimeExtra : %s' % json.dumps(be))

	def getBanTimeExtra(self, opt):
		return self._banExtra.get(opt, None)

	def calcBanTime(self, banTime, banCount):
		return self._banExtra['evformula'](self.BanTimeIncr(banTime, banCount))

	def incrBanTime(self, bTicket, ip):
		"""Check for IP address to increment ban time (if was already banned).

		Returns
		-------
		float
			new ban time.
		"""
		orgBanTime = self.__banManager.getBanTime()
		banTime = orgBanTime
		# check ip was already banned (increment time of ban):
		try:
			be = self._banExtra;
			if banTime > 0 and be.get('enabled', False):
				# search IP in database and increase time if found:
				for banCount, timeOfBan, lastBanTime in \
				  self._jail.database.getBan(ip, self._jail, be.get('findtime', None), be.get('overalljails', False) \
				):
					#logSys.debug('IP %s was already banned: %s #, %s' % (ip, banCount, timeOfBan));
					bTicket.setBanCount(banCount);
					# calculate new ban time
					if banCount > 0:
						banTime = be['evformula'](self.BanTimeIncr(banTime, banCount))
					bTicket.setBanTime(banTime);
					logSys.info('[%s] %s was already banned: %s # at last %s - increase time %s to %s' % (self._jail.name, ip, banCount, 
						datetime.datetime.fromtimestamp(timeOfBan).strftime("%Y-%m-%d %H:%M:%S"), 
						datetime.timedelta(seconds=int(orgBanTime)), datetime.timedelta(seconds=int(banTime))));
					break
		except Exception as e:
			logSys.error('%s', e, exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)
			#logSys.error('%s', e, exc_info=True)

		return banTime

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
			ip = bTicket.getIP()
			aInfo["ip"] = ip
			aInfo["failures"] = bTicket.getAttempt()
			aInfo["time"] = bTicket.getTime()
			aInfo["matches"] = "\n".join(bTicket.getMatches())
			btime = bTicket.getBanTime(self.__banManager.getBanTime());
			if self._jail.database is not None:
				aInfo["ipmatches"] = lambda: "\n".join(
					self._jail.database.getBansMerged(
						ip=ip).getMatches())
				aInfo["ipjailmatches"] = lambda: "\n".join(
					self._jail.database.getBansMerged(
						ip=ip, jail=self._jail).getMatches())
				aInfo["ipfailures"] = lambda: "\n".join(
					self._jail.database.getBansMerged(
						ip=ip).getAttempt())
				aInfo["ipjailfailures"] = lambda: "\n".join(
					self._jail.database.getBansMerged(
						ip=ip, jail=self._jail).getAttempt())
				try:
					# if ban time was not set:
					if not ticket.getRestored() and bTicket.getBanTime() is None:
						btime = self.incrBanTime(bTicket, ip)
					bTicket.setBanTime(btime);
				except Exception as e:
					logSys.error('%s', e, exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)
					#logSys.error('%s', e, exc_info=True)

			if self.__banManager.addBanTicket(bTicket):
				if self._jail.database is not None:
					# add to database always only after ban time was calculated an not yet already banned:
					# if ticked was not restored from database - put it into database:
					if not ticket.getRestored():
						self._jail.database.addBan(self._jail, bTicket)
				logSys.notice("[%s] %sBan %s (%d # %s -> %s)" % (self._jail.name, ('Resore ' if ticket.getRestored() else ''),
					aInfo["ip"], bTicket.getBanCount(), datetime.timedelta(seconds=int(btime)),
					datetime.datetime.fromtimestamp(aInfo["time"] + btime).strftime("%Y-%m-%d %H:%M:%S")))
				for name, action in self._actions.iteritems():
					try:
						action.ban(aInfo)
					except Exception as e:
						logSys.error(
							"Failed to execute ban jail '%s' action '%s': %s",
							self._jail.name, name, e,
							exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)
				return True
			else:
				logSys.notice("[%s] %s already banned" % (self._jail.name,
														aInfo["ip"]))
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
				action.unban(aInfo)
			except Exception as e:
				logSys.error(
					"Failed to execute unban jail '%s' action '%s': %s",
					self._jail.name, name, e,
					exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)

	@property
	def status(self):
		"""Status of active bans, and total ban counts.
		"""
		ret = [("Currently banned", self.__banManager.size()), 
			   ("Total banned", self.__banManager.getBanTotal()),
			   ("Banned IP list", self.__banManager.getBanList())]
		return ret
