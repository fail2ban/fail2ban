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
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

# Author: Cyril Jaquier
# 
# $Revision$

__author__ = "Cyril Jaquier"
__version__ = "$Revision$"
__date__ = "$Date$"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

from banmanager import BanManager
from failmanager import FailManager, FailManagerEmpty
from jailthread import JailThread
from action import Action
import time, logging, os

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.actions")

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
		JailThread.__init__(self, jail)
		## The jail which contains this action.
		self.jail = jail
		self.__actions = list()
		## The ban manager.
		self.__banManager = BanManager()
	
	def addAction(self, name):
		action = Action(name)
		self.__actions.append(action)
	
	def delAction(self, name):
		for action in self.__actions:
			if action.getName() == name:
				self.__actions.remove(action)
				break
	
	def getAction(self, name):
		for action in self.__actions:
			if action.getName() == name:
				return action
		raise KeyError
	
	def getLastAction(self):
		action = self.__actions.pop()
		self.__actions.append(action)
		return action
	
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
	# Main loop.
	#
	# This function is the main loop of the thread. It checks the Jail
	# queue and executes commands when an IP address is banned.
	# @return True when the thread exits nicely
	
	def run(self):
		for action in self.__actions:
			action.execActionStart()
		self.setActive(True)
		while self.isActive():
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
			action.execActionStop()
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
			aInfo = dict()
			bTicket = BanManager.createBanTicket(ticket)
			aInfo["ip"] = bTicket.getIP()
			aInfo["failures"] = bTicket.getAttempt()
			logSys.info("Ban %s" % aInfo["ip"])
			for action in self.__actions:
				action.execActionBan(aInfo)
			self.__banManager.addBanTicket(bTicket)
			return True
		return False
	
	##
	# Check for IP address to unban.
	#
	# Unban IP address which are outdated.
	
	def __checkUnBan(self):
		for ticket in self.__banManager.unBanList(time.time()):
			aInfo = dict()
			aInfo["ip"] = ticket.getIP()
			logSys.info("Unban %s" % aInfo["ip"])
			for action in self.__actions:
				action.execActionUnban(aInfo)
	
	##
	# Flush the ban list.
	#
	# Unban all IP address which are still in the banning list.
	
	def __flushBan(self):
		logSys.debug("Flush ban list")
		for ticket in self.__banManager.flushBanList():
			aInfo = dict()
			aInfo["ip"] = ticket.getIP()
			logSys.info("Unban %s" % aInfo["ip"])
			for action in self.__actions:
				action.execActionUnban(aInfo)
	
	##
	# Get the status of the filter.
	#
	# Get some informations about the filter state such as the total
	# number of failures.
	# @return a list with tuple
	
	def status(self):
		ret = [("Currently banned", self.__banManager.size()),
			   ("Total banned", self.__banManager.getBanTotal())]
		return ret
		