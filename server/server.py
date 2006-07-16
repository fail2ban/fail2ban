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

from jail import Jail
from transmitter import Transmitter
import locale, logging

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.server")

class Server:
	
	def __init__(self):
		self.jails = dict()
		self.transm = Transmitter(self)
		self.logLevel = 3
		# Set logging level
		self.setLogLevel(self.logLevel)
	
	def start(self):
		# Start the communication
		self.transm.start()
	
	def quit(self):
		for jail in self.jails.copy():
			self.stopJail(jail)
		self.transm.stop()
	
	def addJail(self, name):
		self.jails[name] = Jail(name)
		
	def delJail(self, name):
		if self.jails.has_key(name):
			del self.jails[name]
		else:
			raise ServerUnknownJail(name)
	
	def startJail(self, name):
		if self.jails.has_key(name):
			self.jails[name].start()
		else:
			raise ServerUnknownJail(name)
	
	def stopJail(self, name):
		if self.jails.has_key(name):
			if self.isActive(name):
				self.jails[name].stop()
				self.delJail(name)
		else:
			raise ServerUnknownJail(name)
			
	def isActive(self, name):
		if self.jails.has_key(name):
			return self.jails[name].isActive()
		else:
			raise ServerUnknownJail(name)
	
	def setIdleJail(self, name, value):
		if self.jails.has_key(name):
			self.jails[name].setIdle(value)
			return True
		else:
			raise ServerUnknownJail(name)

	def getIdleJail(self, name):
		if self.jails.has_key(name):
			return self.jails[name].getIdle()
		else:
			raise ServerUnknownJail(name)
	
	# Filter
	def setLogPath(self, name, file):
		if self.jails.has_key(name):
			self.jails[name].getFilter().setLogPath(file)
	
	def getLogPath(self, name):
		if self.jails.has_key(name):
			return self.jails[name].getFilter().getLogPath()
		else:
			raise ServerUnknownJail(name)
	
	def setTimeRegex(self, name, value):
		if self.jails.has_key(name):
			self.jails[name].getFilter().setTimeRegex(value)
		else:
			raise ServerUnknownJail(name)
	
	def getTimeRegex(self, name):
		if self.jails.has_key(name):
			return self.jails[name].getFilter().getTimeRegex()
		else:
			raise ServerUnknownJail(name)
	
	def setTimePattern(self, name, value):
		if self.jails.has_key(name):
			self.jails[name].getFilter().setTimePattern(value)
		else:
			raise ServerUnknownJail(name)
	
	def getTimePattern(self, name):
		if self.jails.has_key(name):
			return self.jails[name].getFilter().getTimePattern()
		else:
			raise ServerUnknownJail(name)

	def setFailRegex(self, name, value):
		if self.jails.has_key(name):
			self.jails[name].getFilter().setFailRegex(value)
		else:
			raise ServerUnknownJail(name)
	
	def getFailRegex(self, name):
		if self.jails.has_key(name):
			return self.jails[name].getFilter().getFailRegex()
		else:
			raise ServerUnknownJail(name)
	
	def setMaxRetry(self, name, value):
		if self.jails.has_key(name):
			self.jails[name].getFilter().setMaxRetry(value)
		else:
			raise ServerUnknownJail(name)
	
	def getMaxRetry(self, name):
		if self.jails.has_key(name):
			return self.jails[name].getFilter().getMaxRetry()
		else:
			raise ServerUnknownJail(name)
	
	def setMaxTime(self, name, value):
		if self.jails.has_key(name):
			self.jails[name].getFilter().setMaxTime(value)
		else:
			raise ServerUnknownJail(name)
	
	def getMaxTime(self, name):
		if self.jails.has_key(name):
			return self.jails[name].getFilter().getMaxTime()
		else:
			raise ServerUnknownJail(name)
	
	# Action
	def addAction(self, name, value):
		if self.jails.has_key(name):
			self.jails[name].getAction().addAction(value)
		else:
			raise ServerUnknownJail(name)
	
	def getLastAction(self, name):
		if self.jails.has_key(name):
			return self.jails[name].getAction().getLastAction()
		else:
			raise ServerUnknownJail(name)
	
	def delAction(self, name, value):
		if self.jails.has_key(name):
			self.jails[name].getAction().delAction(value)
		else:
			raise ServerUnknownJail(name)
	
	def setCInfo(self, name, action, key, value):
		if self.jails.has_key(name):
			self.jails[name].getAction().getAction(action).setCInfo(key, value)
		else:
			raise ServerUnknownJail(name)
	
	def getCInfo(self, name, action, key):
		if self.jails.has_key(name):
			return self.jails[name].getAction().getAction(action).getCInfo(key)
		else:
			raise ServerUnknownJail(name)
	
	def delCInfo(self, name, action, key):
		if self.jails.has_key(name):
			self.jails[name].getAction().getAction(action).delCInfo(key)
		else:
			raise ServerUnknownJail(name)
	
	def setBanTime(self, name, value):
		if self.jails.has_key(name):
			self.jails[name].getAction().setBanTime(value)
		else:
			raise ServerUnknownJail(name)
	
	def getBanTime(self, name):
		if self.jails.has_key(name):
			return self.jails[name].getAction().getBanTime()
		else:
			raise ServerUnknownJail(name)
	
	def setActionStart(self, name, action, value):
		if self.jails.has_key(name):
			self.jails[name].getAction().getAction(action).setActionStart(value)
		else:
			raise ServerUnknownJail(name)
	
	def getActionStart(self, name, action):
		if self.jails.has_key(name):
			return self.jails[name].getAction().getAction(action).getActionStart()
		else:
			raise ServerUnknownJail(name)
		
	def setActionStop(self, name, action, value):
		if self.jails.has_key(name):
			self.jails[name].getAction().getAction(action).setActionStop(value)
		else:
			raise ServerUnknownJail(name)
	
	def getActionStop(self, name, action):
		if self.jails.has_key(name):
			return self.jails[name].getAction().getAction(action).getActionStop()
		else:
			raise ServerUnknownJail(name)
	
	def setActionCheck(self, name, action, value):
		if self.jails.has_key(name):
			self.jails[name].getAction().getAction(action).setActionCheck(value)
		else:
			raise ServerUnknownJail(name)
	
	def getActionCheck(self, name, action):
		if self.jails.has_key(name):
			return self.jails[name].getAction().getAction(action).getActionCheck()
		else:
			raise ServerUnknownJail(name)
	
	def setActionBan(self, name, action, value):
		if self.jails.has_key(name):
			self.jails[name].getAction().getAction(action).setActionBan(value)
		else:
			raise ServerUnknownJail(name)
	
	def getActionBan(self, name, action):
		if self.jails.has_key(name):
			return self.jails[name].getAction().getAction(action).getActionBan()
		else:
			raise ServerUnknownJail(name)
	
	def setActionUnban(self, name, action, value):
		if self.jails.has_key(name):
			self.jails[name].getAction().getAction(action).setActionUnban(value)
		else:
			raise ServerUnknownJail(name)
	
	def getActionUnban(self, name, action):
		if self.jails.has_key(name):
			return self.jails[name].getAction().getAction(action).getActionUnban()
		else:
			raise ServerUnknownJail(name)
		
	# Status
	def status(self):
		jailList = ''
		for jail in self.jails:
			jailList += jail + ', '
		length = len(jailList)
		if not length == 0:
			jailList = jailList[:length-2]
		ret = [("Number of jail", len(self.jails)),
			   ("Jail list", jailList)]
		return ret
	
	def statusJail(self, name):
		if self.jails.has_key(name):
			return self.jails[name].getStatus()
		raise ServerUnknownJail(name)
	
	# Logging
	
	##
	# Set the logging level.
	#
	# Incrementing the value gives more messages.
	# 0 = FATAL
	# 1 = ERROR
	# 2 = WARNING
	# 3 = INFO
	# 4 = DEBUG
	# @param value the level
	
	def setLogLevel(self, value):
		self.logLevel = value
		logLevel = logging.DEBUG
		if value == 0:
			logLevel = logging.FATAL
		elif value == 1:
			logLevel = logging.ERROR
		elif value == 2:
			logLevel = logging.WARNING
		elif value == 3:
			logLevel = logging.INFO
		logging.getLogger("fail2ban").setLevel(logLevel)
	
	##
	# Get the logging level.
	#
	# @see setLogLevel
	# @return the log level
	
	def getLogLevel(self):
		return self.logLevel

class ServerUnknownJail(Exception):
	pass