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

import time
import json

from ..helpers import getLogger, logging
from .. import version

# Gets the instance of the logger.
logSys = getLogger(__name__)


class Transmitter:
	
	##
	# Constructor.
	#
	# @param The server reference
	
	def __init__(self, server):
		self.__server = server
		self.__quiet = 0
		
	##
	# Proceeds a command.
	#
	# Proceeds an incoming command.
	# @param command The incoming command
	
	def proceed(self, command):
		# Deserialize object
		logSys.log(5, "Command: %r", command)
		try:
			ret = self.__commandHandler(command)
			ack = 0, ret
		except Exception as e:
			logSys.warning("Command %r has failed. Received %r",
						command, e, 
						exc_info=logSys.getEffectiveLevel()<=logging.DEBUG)
			ack = 1, e
		return ack
	
	##
	# Handle an command.
	#
	# 
	
	def __commandHandler(self, command):
		name = command[0]
		if name == "ping":
			return "pong"
		elif name == "add":
			name = command[1]
			if name == "--all":
				raise Exception("Reserved name %r" % (name,))
			try:
				backend = command[2]
			except IndexError:
				backend = "auto"
			self.__server.addJail(name, backend)
			return name
		elif name == "multi-set":
			return self.__commandSet(command[1:], True)
		elif name == "set":
			return self.__commandSet(command[1:])
		elif name == "start":
			name = command[1]
			self.__server.startJail(name)
			return None
		elif name == "stop":
			if len(command) == 1:
				self.__server.quit()
			elif command[1] == "--all":
				self.__server.stopAllJail()
			else:
				name = command[1]
				self.__server.stopJail(name)
			return None
		elif name == "reload":
			opts = command[1:3]
			self.__quiet = 1
			try:
				self.__server.reloadJails(*opts, begin=True)
				for cmd in command[3]:
					self.__commandHandler(cmd)
			finally:
				self.__quiet = 0
				self.__server.reloadJails(*opts, begin=False)
			return 'OK'
		elif name == "unban" and len(command) >= 2:
			# unban in all jails:
			value = command[1:]
			# if all ips:
			if len(value) == 1 and value[0] == "--all":
				return self.__server.setUnbanIP()
			return self.__server.setUnbanIP(None, value)
		elif name == "echo":
			return command[1:]
		elif name == "server-status":
			logSys.debug("Status: ready")
			return "Server ready"
		elif name == "server-stream":
			self.__quiet = 1
			try:
				for cmd in command[1]:
					self.__commandHandler(cmd)
			finally:
				self.__quiet = 0
			return None
		elif name == "sleep":
			value = command[1]
			time.sleep(float(value))
			return None
		elif name == "flushlogs":
			return self.__server.flushLogs()
		elif name == "get":
			return self.__commandGet(command[1:])
		elif name == "status":
			return self.status(command[1:])
		elif name == "version":
			return version.version
		elif name == "config-error":
			logSys.error(command[1])
			return None
		raise Exception("Invalid command")
	
	def __commandSet(self, command, multiple=False):
		name = command[0]
		# Logging
		if name == "loglevel":
			value = command[1]
			self.__server.setLogLevel(value)
			if self.__quiet: return
			return self.__server.getLogLevel()
		elif name == "logtarget":
			value = command[1]
			if self.__server.setLogTarget(value):
				if self.__quiet: return
				return self.__server.getLogTarget()
			else:
				raise Exception("Failed to change log target")
		elif name == "syslogsocket":
			value = command[1]
			if self.__server.setSyslogSocket(value):
				if self.__quiet: return
				return self.__server.getSyslogSocket()
			else:
				raise Exception("Failed to change syslog socket")
		#Thread
		elif name == "thread":
			value = command[1]
			return self.__server.setThreadOptions(value)
		#Database
		elif name == "dbfile":
			self.__server.setDatabase(command[1])
			db = self.__server.getDatabase()
			if db is None:
				return None
			else:
				if self.__quiet: return
				return db.filename
		elif name == "dbmaxmatches":
			db = self.__server.getDatabase()
			if db is None:
				logSys.log(logging.MSG, "dbmaxmatches setting was not in effect since no db yet")
				return None
			else:
				db.maxMatches = int(command[1])
				if self.__quiet: return
				return db.maxMatches
		elif name == "dbpurgeage":
			db = self.__server.getDatabase()
			if db is None:
				logSys.log(logging.MSG, "dbpurgeage setting was not in effect since no db yet")
				return None
			else:
				db.purgeage = command[1]
				if self.__quiet: return
				return db.purgeage
		# Jail
		elif command[1] == "idle":
			if command[2] == "on":
				self.__server.setIdleJail(name, True)
			elif command[2] == "off":
				self.__server.setIdleJail(name, False)
			else:
				raise Exception("Invalid idle option, must be 'on' or 'off'")
			if self.__quiet: return
			return self.__server.getIdleJail(name)
		# Filter
		elif command[1] == "ignoreself":
			value = command[2]
			self.__server.setIgnoreSelf(name, value)
			if self.__quiet: return
			return self.__server.getIgnoreSelf(name)
		elif command[1] == "addignoreip":
			for value in command[2:]:
				self.__server.addIgnoreIP(name, value)
			if self.__quiet: return
			return self.__server.getIgnoreIP(name)
		elif command[1] == "delignoreip":
			value = command[2]
			self.__server.delIgnoreIP(name, value)
			if self.__quiet: return
			return self.__server.getIgnoreIP(name)
		elif command[1] == "ignorecommand":
			value = command[2]
			self.__server.setIgnoreCommand(name, value)
			if self.__quiet: return
			return self.__server.getIgnoreCommand(name)
		elif command[1] == "ignorecache":
			value = command[2]
			self.__server.setIgnoreCache(name, value)
			if self.__quiet: return
			return self.__server.getIgnoreCache(name)
		elif command[1] == "addlogpath":
			value = command[2]
			tail = False
			if len(command) == 4:
				if command[3].lower()  == "tail":
					tail = True
				elif command[3].lower() != "head":
					raise ValueError("File option must be 'head' or 'tail'")
			elif len(command) > 4:
				raise ValueError("Only one file can be added at a time")
			self.__server.addLogPath(name, value, tail)
			if self.__quiet: return
			return self.__server.getLogPath(name)
		elif command[1] == "dellogpath":
			value = command[2]
			self.__server.delLogPath(name, value)
			if self.__quiet: return
			return self.__server.getLogPath(name)
		elif command[1] == "logencoding":
			value = command[2]
			self.__server.setLogEncoding(name, value)
			if self.__quiet: return
			return self.__server.getLogEncoding(name)
		elif command[1] == "addjournalmatch": # pragma: systemd no cover
			value = command[2:]
			self.__server.addJournalMatch(name, value)
			if self.__quiet: return
			return self.__server.getJournalMatch(name)
		elif command[1] == "deljournalmatch": # pragma: systemd no cover
			value = command[2:]
			self.__server.delJournalMatch(name, value)
			if self.__quiet: return
			return self.__server.getJournalMatch(name)
		elif command[1] == "prefregex":
			value = command[2]
			self.__server.setPrefRegex(name, value)
			if self.__quiet: return
			return self.__server.getPrefRegex(name)
		elif command[1] == "addfailregex":
			value = command[2]
			self.__server.addFailRegex(name, value, multiple=multiple)
			if multiple:
				return True
			if self.__quiet: return
			return self.__server.getFailRegex(name)
		elif command[1] == "delfailregex":
			value = int(command[2])
			self.__server.delFailRegex(name, value)
			if self.__quiet: return
			return self.__server.getFailRegex(name)
		elif command[1] == "addignoreregex":
			value = command[2]
			self.__server.addIgnoreRegex(name, value, multiple=multiple)
			if multiple:
				return True
			if self.__quiet: return
			return self.__server.getIgnoreRegex(name)
		elif command[1] == "delignoreregex":
			value = int(command[2])
			self.__server.delIgnoreRegex(name, value)
			if self.__quiet: return
			return self.__server.getIgnoreRegex(name)
		elif command[1] == "usedns":
			value = command[2]
			self.__server.setUseDns(name, value)
			if self.__quiet: return
			return self.__server.getUseDns(name)
		elif command[1] == "findtime":
			value = command[2]
			self.__server.setFindTime(name, value)
			if self.__quiet: return
			return self.__server.getFindTime(name)
		elif command[1] == "datepattern":
			value = command[2]
			self.__server.setDatePattern(name, value)
			if self.__quiet: return
			return self.__server.getDatePattern(name)
		elif command[1] == "logtimezone":
			value = command[2]
			self.__server.setLogTimeZone(name, value)
			if self.__quiet: return
			return self.__server.getLogTimeZone(name)
		elif command[1] == "maxmatches":
			value = command[2]
			self.__server.setMaxMatches(name, int(value))
			if self.__quiet: return
			return self.__server.getMaxMatches(name)
		elif command[1] == "maxretry":
			value = command[2]
			self.__server.setMaxRetry(name, int(value))
			if self.__quiet: return
			return self.__server.getMaxRetry(name)
		elif command[1] == "maxlines":
			value = command[2]
			self.__server.setMaxLines(name, int(value))
			if self.__quiet: return
			return self.__server.getMaxLines(name)
		# command
		elif command[1] == "bantime":
			value = command[2]
			self.__server.setBanTime(name, value)
			if self.__quiet: return
			return self.__server.getBanTime(name)
		elif command[1] == "attempt":
			value = command[2:]
			if self.__quiet: return
			return self.__server.addAttemptIP(name, *value)
		elif command[1].startswith("bantime."):
			value = command[2]
			opt = command[1][len("bantime."):]
			self.__server.setBanTimeExtra(name, opt, value)
			if self.__quiet: return
			return self.__server.getBanTimeExtra(name, opt)
		elif command[1] == "banip":
			value = command[2:]
			return self.__server.setBanIP(name,value)
		elif command[1] == "unbanip":
			ifexists = True
			if command[2] != "--report-absent":
				value = command[2:]
			else:
				ifexists = False
				value = command[3:]
			return self.__server.setUnbanIP(name, value, ifexists=ifexists)
		elif command[1] == "addaction":
			args = [command[2]]
			if len(command) > 3:
				args.extend([command[3], json.loads(command[4])])
			self.__server.addAction(name, *args)
			if self.__quiet: return
			return args[0]
		elif command[1] == "delaction":
			value = command[2]
			self.__server.delAction(name, value)
			return None
		elif command[1] == "action":
			actionname = command[2]
			action = self.__server.getAction(name, actionname)
			if multiple:
				for cmd in command[3]:
					logSys.log(5, "  %r", cmd)
					actionkey = cmd[0]
					if callable(getattr(action, actionkey, None)):
						actionvalue = json.loads(cmd[1]) if len(cmd)>1 else {}
						getattr(action, actionkey)(**actionvalue)
					else:
						actionvalue = cmd[1]
						setattr(action, actionkey, actionvalue)
				return True
			else:
				actionkey = command[3]
				if callable(getattr(action, actionkey, None)):
					actionvalue = json.loads(command[4]) if len(command)>4 else {}
					if self.__quiet: return
					return getattr(action, actionkey)(**actionvalue)
				else:
					actionvalue = command[4]
					setattr(action, actionkey, actionvalue)
					if self.__quiet: return
					return getattr(action, actionkey)
		raise Exception("Invalid command %r (no set action or not yet implemented)" % (command[1],))
	
	def __commandGet(self, command):
		name = command[0]
		# Logging
		if name == "loglevel":
			return self.__server.getLogLevel()
		elif name == "logtarget":
			return self.__server.getLogTarget()
		elif name == "syslogsocket":
			return self.__server.getSyslogSocket()
		#Thread
		elif name == "thread":
			return self.__server.getThreadOptions()
		#Database
		elif name == "dbfile":
			db = self.__server.getDatabase()
			if db is None:
				return None
			else:
				return db.filename
		elif name == "dbmaxmatches":
			db = self.__server.getDatabase()
			if db is None:
				return None
			else:
				return db.maxMatches
		elif name == "dbpurgeage":
			db = self.__server.getDatabase()
			if db is None:
				return None
			else:
				return db.purgeage
		# Filter
		elif command[1] == "logpath":
			return self.__server.getLogPath(name)
		elif command[1] == "logencoding":
			return self.__server.getLogEncoding(name)
		elif command[1] == "journalmatch": # pragma: systemd no cover
			return self.__server.getJournalMatch(name)
		elif command[1] == "ignoreself":
			return self.__server.getIgnoreSelf(name)
		elif command[1] == "ignoreip":
			return self.__server.getIgnoreIP(name)
		elif command[1] == "ignorecommand":
			return self.__server.getIgnoreCommand(name)
		elif command[1] == "ignorecache":
			return self.__server.getIgnoreCache(name)
		elif command[1] == "prefregex":
			return self.__server.getPrefRegex(name)
		elif command[1] == "failregex":
			return self.__server.getFailRegex(name)
		elif command[1] == "ignoreregex":
			return self.__server.getIgnoreRegex(name)
		elif command[1] == "usedns":
			return self.__server.getUseDns(name)
		elif command[1] == "findtime":
			return self.__server.getFindTime(name)
		elif command[1] == "datepattern":
			return self.__server.getDatePattern(name)
		elif command[1] == "logtimezone":
			return self.__server.getLogTimeZone(name)
		elif command[1] == "maxmatches":
			return self.__server.getMaxMatches(name)
		elif command[1] == "maxretry":
			return self.__server.getMaxRetry(name)
		elif command[1] == "maxlines":
			return self.__server.getMaxLines(name)
		# Action
		elif command[1] == "bantime":
			return self.__server.getBanTime(name)
		elif command[1] == "banip":
			return self.__server.getBanList(name,
				withTime=len(command) > 2 and command[2] == "--with-time")
		elif command[1].startswith("bantime."):
			opt = command[1][len("bantime."):]
			return self.__server.getBanTimeExtra(name, opt)
		elif command[1] == "actions":
			return self.__server.getActions(name).keys()
		elif command[1] == "action":
			actionname = command[2]
			actionvalue = command[3]
			action = self.__server.getAction(name, actionname)
			return getattr(action, actionvalue)
		elif command[1] == "actionproperties":
			actionname = command[2]
			action = self.__server.getAction(name, actionname)
			return [
				key for key in dir(action)
				if not key.startswith("_") and
					not callable(getattr(action, key))]
		elif command[1] == "actionmethods":
			actionname = command[2]
			action = self.__server.getAction(name, actionname)
			return [
				key for key in dir(action)
				if not key.startswith("_") and callable(getattr(action, key))]
		raise Exception("Invalid command (no get action or not yet implemented)")
	
	def status(self, command):
		if len(command) == 0:
			return self.__server.status()
		elif len(command) == 1:
			name = command[0]
			return self.__server.statusJail(name)
		elif len(command) == 2:
			name = command[0]
			flavor = command[1]
			return self.__server.statusJail(name, flavor=flavor)
		raise Exception("Invalid command (no status)")
