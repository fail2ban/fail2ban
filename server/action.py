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

import time, logging
from subprocess import call

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.actions.action")

##
# Execute commands.
#
# This class reads the failures from the Jail queue and decide if an
# action has to be taken. A BanManager take care of the banned IP
# addresses.

class Action:
	
	def __init__(self, name):
		self.__name = name
		self.__cInfo = dict()
		## Command executed in order to initialize the system.
		self.__actionStart = ''
		## Command executed when an IP address gets banned.
		self.__actionBan = ''
		## Command executed when an IP address gets removed.
		self.__actionUnban = ''
		## Command executed in order to check requirements.
		self.__actionCheck = ''
		## Command executed in order to stop the system.
		self.__actionStop = ''
		logSys.debug("Created Action")
	
	def setName(self, name):
		self.__name = name
	
	def getName(self):
		return self.__name
	
	def setCInfo(self, key, value):
		self.__cInfo[key] = value
	
	def getCInfo(self, key):
		return self.__cInfo[key]
	
	def delCInfo(self, key):
		del self.__cInfo[key]
	
	##
	# Set the "start" command.
	#
	# @param value the command
		
	def setActionStart(self, value):
		self.__actionStart = value
		logSys.info("Set actionStart = %s" % value)
	
	##
	# Get the "start" command.
	#
	# @return the command
	
	def getActionStart(self):
		return self.__actionStart
	
	def execActionStart(self):
		startCmd = Action.replaceTag(self.__actionStart, self.__cInfo)
		return Action.executeCmd(startCmd)
	
	##
	# Set the "ban" command.
	#
	# @param value the command
	
	def setActionBan(self, value):
		self.__actionBan = value
		logSys.info("Set actionBan = %s" % value)
	
	##
	# Get the "ban" command.
	#
	# @return the command
	
	def getActionBan(self):
		return self.__actionBan
	
	def execActionBan(self, aInfo):
		return self.__processCmd(self.__actionBan, aInfo);
	
	##
	# Set the "unban" command.
	#
	# @param value the command
	
	def setActionUnban(self, value):
		self.__actionUnban = value
		logSys.info("Set actionUnban = %s" % value)
	
	##
	# Get the "unban" command.
	#
	# @return the command
	
	def getActionUnban(self):
		return self.__actionUnban
	
	def execActionUnban(self, aInfo):
		return self.__processCmd(self.__actionUnban, aInfo);
	
	##
	# Set the "check" command.
	#
	# @param value the command
	
	def setActionCheck(self, value):
		self.__actionCheck = value
		logSys.info("Set actionCheck = %s" % value)
	
	##
	# Get the "check" command.
	#
	# @return the command
	
	def getActionCheck(self):
		return self.__actionCheck
	
	##
	# Set the "stop" command.
	#
	# @param value the command
	
	def setActionStop(self, value):
		self.__actionStop = value
		logSys.info("Set actionStop = %s" % value)
	
	##
	# Get the "stop" command.
	#
	# @return the command
	
	def getActionStop(self):
		return self.__actionStop
	
	def execActionStop(self):
		stopCmd = Action.replaceTag(self.__actionStop, self.__cInfo)
		return Action.executeCmd(stopCmd)
	
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
	
	def __processCmd(self, cmd, aInfo = None):
		""" Executes an OS command.
		"""
		if cmd == "":
			logSys.debug("Nothing to do")
			return True
		
		checkCmd = Action.replaceTag(self.__actionCheck, self.__cInfo)
		if not Action.executeCmd(checkCmd):
			logSys.error("Invariant check failed. Trying to restore a sane" +
						 " environment")
			stopCmd = Action.replaceTag(self.__actionStop, self.__cInfo)
			Action.executeCmd(stopCmd)
			startCmd = Action.replaceTag(self.__actionStart, self.__cInfo)
			Action.executeCmd(startCmd)
			if not Action.executeCmd(checkCmd):
				logSys.fatal("Unable to restore environment")
				return False

		# Replace tags
		if not aInfo == None:
			realCmd = Action.replaceTag(cmd, aInfo)
		else:
			realCmd = cmd
		
		# Replace static fields
		realCmd = Action.replaceTag(realCmd, self.__cInfo)
		
  		return Action.executeCmd(realCmd)

  	@staticmethod
	def executeCmd(realCmd):
		logSys.debug(realCmd)
		try:
			retcode = call(realCmd, shell=True)
			if retcode < 0:
				logSys.error("%s returned %x" % (realCmd, -retcode))
			else:
				logSys.debug("%s returned %x" % (realCmd, retcode))
				return True
		except OSError, e:
			logSys.error("%s failed with %s" % (realCmd, e))
		return False
