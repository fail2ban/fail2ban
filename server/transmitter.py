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
# $Revision: 745 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 745 $"
__date__ = "$Date: 2009-08-30 20:26:15 +0200 (Sun, 30 Aug 2009) $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import logging, time

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.comm")

class Transmitter:
	
	##
	# Constructor.
	#
	# @param The server reference
	
	def __init__(self, server):
		self.__server = server
		
	##
	# Proceeds a command.
	#
	# Proceeds an incoming command.
	# @param command The incoming command
	
	def proceed(self, command):
		# Deserialize object
		logSys.debug("Command: " + `command`)
		try:
			ret = self.__commandHandler(command)
			ack = 0, ret
		except Exception, e:
			logSys.warn("Invalid command: " + `command`)
			ack = 1, e
		return ack
	
	##
	# Handle an command.
	#
	# 
	
	def __commandHandler(self, command):
		if command[0] == "ping":
			return "pong"
		elif command[0] == "add":
			name = command[1]
			if name == "all":
				raise Exception("Reserved name")
			try:
				backend = command[2]
			except IndexError:
				backend = "auto"
			self.__server.addJail(name, backend)
			return name
		elif command[0] == "start":
			name = command[1]
			self.__server.startJail(name)
			return None
		elif command[0] == "stop":
			if len(command) == 1:
				self.__server.quit()
			elif command[1] == "all":
				self.__server.stopAllJail()
			else:
				name = command[1]
				self.__server.stopJail(name)
			return None
		elif command[0] == "sleep":
			value = command[1]
			time.sleep(int(value))
			return None
		elif command[0] == "set":
			return self.__commandSet(command[1:])
		elif command[0] == "get":
			return self.__commandGet(command[1:])
		elif command[0] == "status":
			return self.status(command[1:])			
		raise Exception("Invalid command")
	
	def __commandSet(self, command):
		name = command[0]
		# Logging
		if name == "loglevel":
			value = int(command[1])
			self.__server.setLogLevel(value)
			return self.__server.getLogLevel()
		elif name == "logtarget":
			value = command[1]
			self.__server.setLogTarget(value)
			return self.__server.getLogTarget()
		# Jail
		elif command[1] == "idle":
			if command[2] == "on":
				self.__server.setIdleJail(name, True)
			elif command[2] == "off":
				self.__server.setIdleJail(name, False)
			return self.__server.getIdleJail(name)
		# Filter
		elif command[1] == "addignoreip":
			value = command[2]
			self.__server.addIgnoreIP(name, value)
			return self.__server.getIgnoreIP(name)
		elif command[1] == "delignoreip":
			value = command[2]
			self.__server.delIgnoreIP(name, value)
			return self.__server.getIgnoreIP(name)
		elif command[1] == "addlogpath":
			value = command[2:]
			for path in value:
				self.__server.addLogPath(name, path)
			return self.__server.getLogPath(name)
		elif command[1] == "dellogpath":
			value = command[2]
			self.__server.delLogPath(name, value)
			return self.__server.getLogPath(name)
		elif command[1] == "addfailregex":
			value = command[2]
			self.__server.addFailRegex(name, value)
			return self.__server.getFailRegex(name)
		elif command[1] == "delfailregex":
			value = int(command[2])
			self.__server.delFailRegex(name, value)
			return self.__server.getFailRegex(name)
		elif command[1] == "addignoreregex":
			value = command[2]
			self.__server.addIgnoreRegex(name, value)
			return self.__server.getIgnoreRegex(name)
		elif command[1] == "delignoreregex":
			value = int(command[2])
			self.__server.delIgnoreRegex(name, value)
			return self.__server.getIgnoreRegex(name)
		elif command[1] == "findtime":
			value = command[2]
			self.__server.setFindTime(name, int(value))
			return self.__server.getFindTime(name)
		elif command[1] == "maxretry":
			value = command[2]
			self.__server.setMaxRetry(name, int(value))
			return self.__server.getMaxRetry(name)
		# command
		elif command[1] == "bantime":
			value = command[2]
			self.__server.setBanTime(name, int(value))
			return self.__server.getBanTime(name)
		elif command[1] == "banip":
			value = command[2]
			return self.__server.setBanIP(name,value)
		elif command[1] == "addaction":
			value = command[2]
			self.__server.addAction(name, value)
			return self.__server.getLastAction(name).getName()
		elif command[1] == "delaction":
			self.__server.delAction(name, value)
			return None
		elif command[1] == "setcinfo":
			act = command[2]
			key = command[3]
			value = command[4]
			self.__server.setCInfo(name, act, key, value)
			return self.__server.getCInfo(name, act, key)
		elif command[1] == "delcinfo":
			act = command[2]
			key = command[3]
			self.__server.delCInfo(name, act, key)
			return None
		elif command[1] == "actionstart":
			act = command[2]
			value = command[3]
			self.__server.setActionStart(name, act, value)
			return self.__server.getActionStart(name, act)
		elif command[1] == "actionstop":
			act = command[2]
			value = command[3]
			self.__server.setActionStop(name, act, value)
			return self.__server.getActionStop(name, act)
		elif command[1] == "actioncheck":
			act = command[2]
			value = command[3]
			self.__server.setActionCheck(name, act, value)
			return self.__server.getActionCheck(name, act)
		elif command[1] == "actionban":
			act = command[2]
			value = command[3]
			self.__server.setActionBan(name, act, value)
			return self.__server.getActionBan(name, act)
		elif command[1] == "actionunban":
			act = command[2]
			value = command[3]
			self.__server.setActionUnban(name, act, value)
			return self.__server.getActionUnban(name, act)
		raise Exception("Invalid command (no set action or not yet implemented)")
	
	def __commandGet(self, command):
		name = command[0]
		# Logging
		if name == "loglevel":
			return self.__server.getLogLevel()
		elif name == "logtarget":
			return self.__server.getLogTarget()
		# Filter
		elif command[1] == "logpath":
			return self.__server.getLogPath(name)
		elif command[1] == "ignoreip":
			return self.__server.getIgnoreIP(name)
		elif command[1] == "failregex":
			return self.__server.getFailRegex(name)
		elif command[1] == "ignoreregex":
			return self.__server.getIgnoreRegex(name)
		elif command[1] == "findtime":
			return self.__server.getFindTime(name)
		elif command[1] == "maxretry":
			return self.__server.getMaxRetry(name)
		# Action
		elif command[1] == "bantime":
			return self.__server.getBanTime(name)
		elif command[1] == "addaction":
			return self.__server.getLastAction(name).getName()
		elif command[1] == "actionstart":
			act = command[2]
			return self.__server.getActionStart(name, act)
		elif command[1] == "actionstop":
			act = command[2]
			return self.__server.getActionStop(name, act)
		elif command[1] == "actioncheck":
			act = command[2]
			return self.__server.getActionCheck(name, act)
		elif command[1] == "actionban":
			act = command[2]
			return self.__server.getActionBan(name, act)
		elif command[1] == "actionunban":
			act = command[2]
			return self.__server.getActionUnban(name, act)
		raise Exception("Invalid command (no get action or not yet implemented)")
	
	def status(self, command):
		if len(command) == 0:
			return self.__server.status()
		else:
			name = command[0]
			return self.__server.statusJail(name)
		raise Exception("Invalid command (no status)")
	