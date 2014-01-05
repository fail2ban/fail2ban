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
import os
import imp

from fail2ban.server.banmanager import BanManager
from fail2ban.server.jailthread import JailThread
from fail2ban.server.action import ActionBase, CommandAction, CallingMap
from fail2ban.server.mytime import MyTime

# Gets the instance of the logger.
logSys = logging.getLogger(__name__)

##
# Execute commands.
#
# This class reads the failures from the Jail queue and decide if an
# action has to be taken. A BanManager take care of the banned IP
# addresses.

class Actions(JailThread):
	
	##
	# Constructor.
	#
	# Initialize the filter object with default values.
	# @param jail the jail object
	
	def __init__(self, jail):
		JailThread.__init__(self)
		## The jail which contains this action.
		self.jail = jail
		self.__actions = list()
		## The ban manager.
		self.__banManager = BanManager()
	
	##
	# Adds an action.
	#
	# @param name The action name
	
	def addAction(self, name, pythonModule=None, initOpts=None):
		# Check is action name already exists
		if name in [action.getName() for action in self.__actions]:
			raise ValueError("Action %s already exists" % name)
		if pythonModule is None:
			action = CommandAction(name)
		else:
			pythonModuleName = os.path.basename(pythonModule.strip(".py"))
			customActionModule = imp.load_source(
				pythonModuleName, pythonModule)
			if not hasattr(customActionModule, "Action"):
				raise RuntimeError(
					"%s module does not have 'Action' class" % pythonModule)
			elif not issubclass(customActionModule.Action, ActionBase):
				raise RuntimeError(
					"%s module %s does not implment required methods" % (
						pythonModule, customActionModule.Action.__name__))
			action = customActionModule.Action(self.jail, name, **initOpts)
		self.__actions.append(action)
	
	##
	# Removes an action.
	#
	# @param name The action name
	
	def delAction(self, name):
		for action in self.__actions:
			if action.getName() == name:
				self.__actions.remove(action)
				return
		raise KeyError("Invalid Action name: %s" % name)
	
	##
	# Returns an action.
	#
	# Raises a KeyError exception if the action does not exist.
	#
	# @param name the action name
	# @return the action
	
	def getAction(self, name):
		for action in self.__actions:
			if action.getName() == name:
				return action
		raise KeyError("Invalid Action name")
	
	##
	# Returns the last defined action.
	#
	# @return The last defined action.
	
	def getLastAction(self):
		action = self.__actions.pop()
		self.__actions.append(action)
		return action
	
	##
	# Returns the list of actions
	#
	# @return list of actions
	
	def getActions(self):
		return self.__actions
	
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
	
	##
	# Remove a banned IP now, rather than waiting for it to expire, even if set to never expire.
	#
	# @return the IP string or 'None' if not unbanned.
	def removeBannedIP(self, ip):
		# Find the ticket with the IP.
		ticket = self.__banManager.getTicketByIP(ip)
		if ticket is not None:
			# Unban the IP.
			self.__unBan(ticket)
			return ip
		raise ValueError("IP %s is not banned" % ip)

	##
	# Main loop.
	#
	# This function is the main loop of the thread. It checks the Jail
	# queue and executes commands when an IP address is banned.
	# @return True when the thread exits nicely
	
	def run(self):
		self.setActive(True)
		for action in self.__actions:
			try:
				action.execActionStart()
			except Exception as e:
				logSys.error("Failed to start jail '%s' action '%s': %s",
					self.jail.getName(), action.getName(), e)
		while self._isActive():
			if not self.getIdle():
				#logSys.debug(self.jail.getName() + ": action")
				ret = self.__checkBan()
				if not ret:
					self.__checkUnBan()
					time.sleep(self.getSleepTime())
			else:
				time.sleep(self.getSleepTime())
		self.__flushBan()
		for action in self.__actions:
			try:
				action.execActionStop()
			except Exception as e:
				logSys.error("Failed to stop jail '%s' action '%s': %s",
					self.jail.getName(), action.getName(), e)
		logSys.debug(self.jail.getName() + ": action terminated")
		return True

	##
	# Check for IP address to ban.
	#
	# Look in the Jail queue for FailTicket. If a ticket is available,
	# it executes the "ban" command and add a ticket to the BanManager.
	# @return True if an IP address get banned
	
	def __checkBan(self):
		ticket = self.jail.getFailTicket()
		if ticket != False:
			aInfo = CallingMap()
			bTicket = BanManager.createBanTicket(ticket)
			aInfo["ip"] = bTicket.getIP()
			aInfo["failures"] = bTicket.getAttempt()
			aInfo["time"] = bTicket.getTime()
			aInfo["matches"] = "\n".join(bTicket.getMatches())
			if self.jail.getDatabase() is not None:
				aInfo["ipmatches"] = lambda: "\n".join(
					self.jail.getDatabase().getBansMerged(
						ip=bTicket.getIP()).getMatches())
				aInfo["ipjailmatches"] = lambda: "\n".join(
					self.jail.getDatabase().getBansMerged(
						ip=bTicket.getIP(), jail=self.jail).getMatches())
				aInfo["ipfailures"] = lambda: "\n".join(
					self.jail.getDatabase().getBansMerged(
						ip=bTicket.getIP()).getAttempt())
				aInfo["ipjailfailures"] = lambda: "\n".join(
					self.jail.getDatabase().getBansMerged(
						ip=bTicket.getIP(), jail=self.jail).getAttempt())
			if self.__banManager.addBanTicket(bTicket):
				logSys.warning("[%s] Ban %s" % (self.jail.getName(), aInfo["ip"]))
				for action in self.__actions:
					try:
						action.execActionBan(aInfo)
					except Exception as e:
						logSys.error(
							"Failed to execute ban jail '%s' action '%s': %s",
							self.jail.getName(), action.getName(), e)
				return True
			else:
				logSys.info("[%s] %s already banned" % (self.jail.getName(),
														aInfo["ip"]))
		return False
	
	##
	# Check for IP address to unban.
	#
	# Unban IP address which are outdated.
	
	def __checkUnBan(self):
		for ticket in self.__banManager.unBanList(MyTime.time()):
			self.__unBan(ticket)
	
	##
	# Flush the ban list.
	#
	# Unban all IP address which are still in the banning list.
	
	def __flushBan(self):
		logSys.debug("Flush ban list")
		for ticket in self.__banManager.flushBanList():
			self.__unBan(ticket)
	
	##
	# Unbans host corresponding to the ticket.
	#
	# Executes the actions in order to unban the host given in the
	# ticket.
	
	def __unBan(self, ticket):
		aInfo = dict()
		aInfo["ip"] = ticket.getIP()
		aInfo["failures"] = ticket.getAttempt()
		aInfo["time"] = ticket.getTime()
		aInfo["matches"] = "".join(ticket.getMatches())
		logSys.warning("[%s] Unban %s" % (self.jail.getName(), aInfo["ip"]))
		for action in self.__actions:
			try:
				action.execActionUnban(aInfo)
			except Exception as e:
				logSys.error(
					"Failed to execute unban jail '%s' action '%s': %s",
					self.jail.getName(), action.getName(), e)
			
	
	##
	# Get the status of the filter.
	#
	# Get some informations about the filter state such as the total
	# number of failures.
	# @return a list with tuple
	
	def status(self):
		ret = [("Currently banned", self.__banManager.size()), 
			   ("Total banned", self.__banManager.getBanTotal()),
			   ("IP list", self.__banManager.getBanList())]
		return ret
