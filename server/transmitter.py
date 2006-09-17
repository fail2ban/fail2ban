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

from ssocket import SSocket
from ssocket import SSocketErrorException
from threading import Lock
import re, pickle, logging

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.comm")

class Transmitter:
	
	def __init__(self, server):
		self.lock = Lock()
		self.server = server
		self.socket = SSocket(self)
	
	##
	# Start the transmittion server.
	#
	# This function wait for the socket thread.
	
	def start(self, force):
		try:
			self.lock.acquire()
			self.socket.initialize(force)
			self.socket.start()
			self.lock.release()
			self.socket.join()
		except SSocketErrorException:
			logSys.error("Could not start server")
			self.lock.release()
	
	##
	# Stop the transmitter.
	#
	# @bug Fix the issue with join(). When using servertestcase.py, errors
	# happen which disappear when using join() in this function.
	
	def stop(self):
		self.socket.stop()
		self.socket.join()
		
	def proceed(self, action):
		# Deserialize object
		try:
			self.lock.acquire()
			logSys.debug("Action: " + `action`)
			try:
				ret = self.actionHandler(action)
				ack = 0, ret
			except Exception, e:
				logSys.warn("Invalid command: " + `action`)
				ack = 1, e
			return ack
		finally:
			self.lock.release()
	
	##
	# Handle an action.
	#
	# 
	
	def actionHandler(self, action):
		if action[0] == "ping":
			return "pong"
		elif action[0] == "add":
			name = action[1]
			if name == "all":
				raise Exception("Reserved name")
			self.server.addJail(name)
			return name
		elif action[0] == "start":
			name = action[1]
			self.server.startJail(name)
			return None
		elif action[0] == "stop":
			if len(action) == 1:
				self.server.quit()
			elif action[1] == "all":
				self.server.stopAllJail()
			else:
				name = action[1]
				self.server.stopJail(name)
			return None
		elif action[0] == "sleep":
			value = action[1]
			time.sleep(int(value))
			return None
		elif action[0] == "set":
			return self.actionSet(action[1:])
		elif action[0] == "get":
			return self.actionGet(action[1:])
		elif action[0] == "status":
			return self.status(action[1:])			
		raise Exception("Invalid command")
	
	def actionSet(self, action):
		name = action[0]
		# Logging
		if name == "loglevel":
			value = int(action[1])
			self.server.setLogLevel(value)
			return self.server.getLogLevel()
		elif name == "logtarget":
			value = action[1]
			self.server.setLogTarget(value)
			return self.server.getLogTarget()
		# Jail
		elif action[1] == "idle":
			if action[2] == "on":
				self.server.setIdleJail(name, True)
			elif action[2] == "off":
				self.server.setIdleJail(name, False)
			return self.server.getIdleJail(name)
		# Filter
		elif action[1] == "addignoreip":
			value = action[2]
			self.server.addIgnoreIP(name, value)
			return self.server.getIgnoreIP(name)
		elif action[1] == "delignoreip":
			value = action[2]
			self.server.delIgnoreIP(name, value)
			return self.server.getIgnoreIP(name)
		elif action[1] == "addlogpath":
			value = action[2:]
			for path in value:
				self.server.addLogPath(name, path)
			return self.server.getLogPath(name)
		elif action[1] == "dellogpath":
			value = action[2]
			self.server.delLogPath(name, value)
			return self.server.getLogPath(name)
		elif action[1] == "timeregex":
			value = action[2]
			self.server.setTimeRegex(name, value)
			return self.server.getTimeRegex(name)
		elif action[1] == "timepattern":
			value = action[2]
			self.server.setTimePattern(name, value)
			return self.server.getTimePattern(name)
		elif action[1] == "failregex":
			value = action[2]
			self.server.setFailRegex(name, value)
			return self.server.getFailRegex(name)
		elif action[1] == "maxtime":
			value = action[2]
			self.server.setMaxTime(name, int(value))
			return self.server.getMaxTime(name)
		elif action[1] == "findtime":
			value = action[2]
			self.server.setFindTime(name, int(value))
			return self.server.getFindTime(name)
		elif action[1] == "maxretry":
			value = action[2]
			self.server.setMaxRetry(name, int(value))
			return self.server.getMaxRetry(name)
		# Action
		elif action[1] == "bantime":
			value = action[2]
			self.server.setBanTime(name, int(value))
			return self.server.getBanTime(name)
		elif action[1] == "addaction":
			value = action[2]
			self.server.addAction(name, value)
			return self.server.getLastAction(name).getName()
		elif action[1] == "delaction":
			self.server.delAction(name, value)
			return None
		elif action[1] == "setcinfo":
			act = action[2]
			key = action[3]
			value = action[4]
			self.server.setCInfo(name, act, key, value)
			return self.server.getCInfo(name, act, key)
		elif action[1] == "delcinfo":
			act = action[2]
			key = action[3]
			self.server.delCInfo(name, act, key)
			return None
		elif action[1] == "actionstart":
			act = action[2]
			value = action[3]
			self.server.setActionStart(name, act, value)
			return self.server.getActionStart(name, act)
		elif action[1] == "actionstop":
			act = action[2]
			value = action[3]
			self.server.setActionStop(name, act, value)
			return self.server.getActionStop(name, act)
		elif action[1] == "actioncheck":
			act = action[2]
			value = action[3]
			self.server.setActionCheck(name, act, value)
			return self.server.getActionCheck(name, act)
		elif action[1] == "actionban":
			act = action[2]
			value = action[3]
			self.server.setActionBan(name, act, value)
			return self.server.getActionBan(name, act)
		elif action[1] == "actionunban":
			act = action[2]
			value = action[3]
			self.server.setActionUnban(name, act, value)
			return self.server.getActionUnban(name, act)
		raise Exception("Invalid command (no set action or not yet implemented)")
	
	def actionGet(self, action):
		name = action[0]
		# Logging
		if name == "loglevel":
			return self.server.getLogLevel()
		elif name == "logtarget":
			return self.server.getLogTarget()
		# Filter
		elif action[1] == "logpath":
			return self.server.getLogPath(name)
		elif action[1] == "ignoreip":
			return self.server.getIgnoreIP(name)
		elif action[1] == "timeregex":
			return self.server.getTimeRegex(name)
		elif action[1] == "timepattern":
			return self.server.getTimePattern(name)
		elif action[1] == "failregex":
			return self.server.getFailRegex(name)
		elif action[1] == "maxtime":
			return self.server.getMaxTime(name)
		elif action[1] == "findtime":
			return self.server.getFindTime(name)
		elif action[1] == "maxretry":
			return self.server.getMaxRetry(name)
		# Action
		elif action[1] == "bantime":
			return self.server.getBanTime(name)
		elif action[1] == "addaction":
			return self.server.getLastAction(name).getName()
		elif action[1] == "actionstart":
			act = action[2]
			return self.server.getActionStart(name, act)
		elif action[1] == "actionstop":
			act = action[2]
			return self.server.getActionStop(name, act)
		elif action[1] == "actioncheck":
			act = action[2]
			return self.server.getActionCheck(name, act)
		elif action[1] == "actionban":
			act = action[2]
			return self.server.getActionBan(name, act)
		elif action[1] == "actionunban":
			act = action[2]
			return self.server.getActionUnban(name, act)
		raise Exception("Invalid command (no get action or not yet implemented)")
	
	def status(self, action):
		if len(action) == 0:
			return self.server.status()
		else:
			name = action[0]
			return self.server.statusJail(name)
		raise Exception("Invalid command (no status)")
	