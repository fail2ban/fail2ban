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
# $Revision: 1.1 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 1.1 $"
__date__ = "$Date: 2004/10/10 13:33:40 $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

from banmanager import BanManager
from failmanager import FailManager, FailManagerEmpty
from jailthread import JailThread
import time, logging, os

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.action")

##
# Execute commands.
#
# This class reads the failures from the Jail queue and decide if an
# action has to be taken. A BanManager take care of the banned IP
# addresses.

class Action(JailThread):
	
	##
	# Constructor.
	#
	# Initialize the filter object with default values.
	# @param jail the jail object
	
	def __init__(self, jail):
		JailThread.__init__(self, jail)
		## The jail which contains this action.
		self.jail = jail
		## The ban manager.
		self.banManager = BanManager()
		## Command executed in order to initialize the system.
		self.actionStart = ''
		## Command executed when an IP address gets banned.
		self.actionBan = ''
		## Command executed when an IP address gets removed.
		self.actionUnban = ''
		## Command executed in order to check requirements.
		self.actionCheck = ''
		## Command executed in order to stop the system.
		self.actionStop = ''
		logSys.debug("Created Action")

	##
	# Set the "start" command.
	#
	# @param value the command
		
	def setActionStart(self, value):
		self.actionStart = value
		logSys.info("Set actionStart = %s" % value)
	
	##
	# Get the "start" command.
	#
	# @return the command
	
	def getActionStart(self):
		return self.actionStart
	
	##
	# Set the "ban" command.
	#
	# @param value the command
	
	def setActionBan(self, value):
		self.actionBan = value
		logSys.info("Set actionBan = %s" % value)
	
	##
	# Get the "ban" command.
	#
	# @return the command
	
	def getActionBan(self):
		return self.actionBan
	
	##
	# Set the "unban" command.
	#
	# @param value the command
	
	def setActionUnban(self, value):
		self.actionUnban = value
		logSys.info("Set actionUnban = %s" % value)
	
	##
	# Get the "unban" command.
	#
	# @return the command
	
	def getActionUnban(self):
		return self.actionUnban
	
	##
	# Set the "check" command.
	#
	# @param value the command
	
	def setActionCheck(self, value):
		self.actionCheck = value
		logSys.info("Set actionCheck = %s" % value)
	
	##
	# Get the "check" command.
	#
	# @return the command
	
	def getActionCheck(self):
		return self.actionCheck
	
	##
	# Set the "stop" command.
	#
	# @param value the command
	
	def setActionStop(self, value):
		self.actionStop = value
		logSys.info("Set actionStop = %s" % value)
	
	##
	# Get the "stop" command.
	#
	# @return the command
	
	def getActionStop(self):
		return self.actionStop
	
	##
	# Set the ban time.
	#
	# @param value the time
	
	def setBanTime(self, value):
		self.banManager.setBanTime(value)
		logSys.info("Set banTime = %s" % value)
	
	##
	# Get the ban time.
	#
	# @return the time
	
	def getBanTime(self):
		return self.banManager.getBanTime()
	
	##
	# Main loop.
	#
	# This function is the main loop of the thread. It checks the Jail
	# queue and executes commands when an IP address is banned.
	# @return True when the thread exits nicely
	
	def run(self):
		self.executeCmd(self.actionStart)
		self.setActive(True)
		while self.isActive():
			if not self.isIdle:
				#logSys.debug(self.jail.getName() + ": action")
				ret = self.checkBan()
				if not ret:
					self.checkUnBan()
					time.sleep(self.sleepTime)
			else:
				time.sleep(self.sleepTime)
		self.flushBan()
		self.executeCmd(self.actionStop)
		logSys.debug(self.jail.getName() + ": action terminated")
		return True

	##
	# Check for IP address to ban.
	#
	# Look in the Jail queue for FailTicket. If a ticket is available,
	# it executes the "ban" command and add a ticket to the BanManager.
	# @return True if an IP address get banned
	
	def checkBan(self):
		logSys.debug("Check for IP address to ban")
		ticket = self.jail.getFailTicket()
		if ticket != False:
			aInfo = dict()
			bTicket = BanManager.createBanTicket(ticket)
			aInfo["ip"] = bTicket.getIP()
			logSys.info("Ban %s" % aInfo["ip"])
			self.executeCmd(self.replaceTag(self.actionBan, aInfo))
			self.banManager.addBanTicket(bTicket)
			return True
		return False
	
	##
	# Check for IP address to unban.
	#
	# Unban IP address which are outdated.
	
	def checkUnBan(self):
		logSys.debug("Check for IP address to unban")
		for ticket in self.banManager.unBanList(time.time()):
			aInfo = dict()
			aInfo["ip"] = ticket.getIP()
			logSys.info("Unban %s" % aInfo["ip"])
			self.executeCmd(self.replaceTag(self.actionUnban, aInfo))
	
	##
	# Flush the ban list.
	#
	# Unban all IP address which are still in the banning list.
	
	def flushBan(self):
		logSys.debug("Flush ban list")
		for ticket in self.banManager.flushBanList():
			aInfo = dict()
			aInfo["ip"] = ticket.getIP()
			logSys.info("Unban %s" % aInfo["ip"])
			self.executeCmd(self.replaceTag(self.actionUnban, aInfo))
	
	##
	# Get the status of the filter.
	#
	# Get some informations about the filter state such as the total
	# number of failures.
	# @return a list with tuple
	
	def status(self):
		ret = [("Currently banned", self.banManager.size()),
			   ("Total banned", self.banManager.getBanTotal())]
		return ret
	
	@staticmethod
	def replaceTag(query, aInfo):
		""" Replace tags in query
		"""
		string = query
		for tag in aInfo:
			string = string.replace('<' + tag + '>', str(aInfo[tag]))
		# New line
		string = string.replace("<br>", '\n')
		return string
	
	@staticmethod
	def executeCmd(cmd):
		""" Executes an OS command.
		"""
		if cmd == "":
			logSys.debug("Nothing to do")
			return True
		
		logSys.debug(cmd)
		retval = os.system(cmd)
		#if not retval == 0:
		#	logSys.error("'" + cmd + "' returned " + `retval`)
		#	raise Exception("Execution of command '%s' failed" % cmd)
		if retval == 0:
			return True
		else:
			logSys.error("%s returned %x" % (cmd, retval))
			return False
		