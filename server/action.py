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

__author__ = "Cyril Jaquier and Fail2Ban Contributors"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier, 2011-2012 Yaroslav Halchenko"
__license__ = "GPL"

import logging, os
import threading, re
#from subprocess import call

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.actions.action")

# Create a lock for running system commands
_cmd_lock = threading.Lock()

# Some hints on common abnormal exit codes
_RETCODE_HINTS = {
	0x7f00: '"Command not found".  Make sure that all commands in %(realCmd)r '
	        'are in the PATH of fail2ban-server process '
			'(grep -a PATH= /proc/`pidof -x fail2ban-server`/environ). '
			'You may want to start '
			'"fail2ban-server -f" separately, initiate it with '
			'"fail2ban-client reload" in another shell session and observe if '
			'additional informative error messages appear in the terminals.'
	}

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
	
	##
	# Sets the action name.
	#
	# @param name the name of the action
	
	def setName(self, name):
		self.__name = name
	
	##
	# Returns the action name.
	#
	# @return the name of the action
	
	def getName(self):
		return self.__name
	
	##
	# Sets a "CInfo".
	#
	# CInfo are statically defined properties. They can be definied by
	# the user and are used to set e-mail addresses, port, host or
	# anything that should not change during the life of the server.
	#
	# @param key the property name
	# @param value the property value
	
	def setCInfo(self, key, value):
		self.__cInfo[key] = value
	
	##
	# Returns a "CInfo".
	#
	# @param key the property name
	
	def getCInfo(self, key):
		return self.__cInfo[key]
	
	##
	# Removes a "CInfo".
	#
	# @param key the property name
	
	def delCInfo(self, key):
		del self.__cInfo[key]
	
	##
	# Set the "start" command.
	#
	# @param value the command
		
	def setActionStart(self, value):
		self.__actionStart = value
		logSys.debug("Set actionStart = %s" % value)
	
	##
	# Get the "start" command.
	#
	# @return the command
	
	def getActionStart(self):
		return self.__actionStart
	
	##
	# Executes the action "start" command.
	#
	# Replaces the tags in the action command with value of "cInfo"
	# and executes the resulting command.
	#
	# @return True if the command succeeded
	
	def execActionStart(self):
		if self.__cInfo:
			if not Action.substituteRecursiveTags(self.__cInfo):
				logSys.error("Cinfo/definitions contain self referencing definitions and cannot be resolved")
				return False
		startCmd = Action.replaceTag(self.__actionStart, self.__cInfo)
		return Action.executeCmd(startCmd)
	
	##
	# Set the "ban" command.
	#
	# @param value the command
	
	def setActionBan(self, value):
		self.__actionBan = value
		logSys.debug("Set actionBan = %s" % value)
	
	##
	# Get the "ban" command.
	#
	# @return the command
	
	def getActionBan(self):
		return self.__actionBan
	
	##
	# Executes the action "ban" command.
	#
	# @return True if the command succeeded
	
	def execActionBan(self, aInfo):
		return self.__processCmd(self.__actionBan, aInfo)
	
	##
	# Set the "unban" command.
	#
	# @param value the command
	
	def setActionUnban(self, value):
		self.__actionUnban = value
		logSys.debug("Set actionUnban = %s" % value)
	
	##
	# Get the "unban" command.
	#
	# @return the command
	
	def getActionUnban(self):
		return self.__actionUnban
	
	##
	# Executes the action "unban" command.
	#
	# @return True if the command succeeded
	
	def execActionUnban(self, aInfo):
		return self.__processCmd(self.__actionUnban, aInfo)
	
	##
	# Set the "check" command.
	#
	# @param value the command
	
	def setActionCheck(self, value):
		self.__actionCheck = value
		logSys.debug("Set actionCheck = %s" % value)
	
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
		logSys.debug("Set actionStop = %s" % value)
	
	##
	# Get the "stop" command.
	#
	# @return the command
	
	def getActionStop(self):
		return self.__actionStop
	
	##
	# Executes the action "stop" command.
	#
	# Replaces the tags in the action command with value of "cInfo"
	# and executes the resulting command.
	#
	# @return True if the command succeeded
	
	def execActionStop(self):
		stopCmd = Action.replaceTag(self.__actionStop, self.__cInfo)
		return Action.executeCmd(stopCmd)

	##
	# Sort out tag definitions within other tags
	#
	# so:		becomes:
	# a = 3		a = 3
	# b = <a>_3	b = 3_3
	# @param	tags, a dictionary
	# @returns	tags altered or False if there is a recursive definition
	#@staticmethod
	def substituteRecursiveTags(tags):
		t = re.compile(r'<([^ >]+)>')
		for tag, value in tags.iteritems():
			value = str(value)
			m = t.search(value)
			while m:
				if m.group(1) == tag:
					# recursive definitions are bad
					return False
				else:
					if tags.has_key(m.group(1)):
						value = value[0:m.start()] + tags[m.group(1)] + value[m.end():]
						m = t.search(value, m.start())
					else:
						# Missing tags are ok so we just continue on searching.
						# cInfo can contain aInfo elements like <HOST> and valid shell
						# constructs like <STDIN>.
						m = t.search(value, m.start() + 1)
			tags[tag] = value
		return tags
	substituteRecursiveTags = staticmethod(substituteRecursiveTags)

	#@staticmethod
	def escapeTag(tag):
		for c in '\\#&;`|*?~<>^()[]{}$\n\'"':
			if c in tag:
				tag = tag.replace(c, '\\' + c)
		return tag
	escapeTag = staticmethod(escapeTag)

	##
	# Replaces tags in query with property values in aInfo.
	#
	# @param query the query string with tags
	# @param aInfo the properties
	# @return a string
	
	#@staticmethod
	def replaceTag(query, aInfo):
		""" Replace tags in query
		"""
		string = query
		for tag, value in aInfo.iteritems():
			value = str(value)			  # assure string
			if tag == 'matches':
				# That one needs to be escaped since its content is
				# out of our control
				value = Action.escapeTag(value)
			string = string.replace('<' + tag + '>', value)
		# New line
		string = string.replace("<br>", '\n')
		return string
	replaceTag = staticmethod(replaceTag)
	
	##
	# Executes a command with preliminary checks and substitutions.
	#
	# Before executing any commands, executes the "check" command first
	# in order to check if pre-requirements are met. If this check fails,
	# it tries to restore a sane environment before executing the real
	# command.
	# Replaces "aInfo" and "cInfo" in the query too.
	#
	# @param cmd The command to execute
	# @param aInfo Dynamic properties
	# @return True if the command succeeded
	
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
			self.execActionStop()
			self.execActionStart()
			if not Action.executeCmd(checkCmd):
				logSys.fatal("Unable to restore environment")
				return False

		# Replace tags
		if not aInfo is None:
			realCmd = Action.replaceTag(cmd, aInfo)
		else:
			realCmd = cmd
		
		# Replace static fields
		realCmd = Action.replaceTag(realCmd, self.__cInfo)
		
		return Action.executeCmd(realCmd)

	##
	# Executes a command.
	#
	# We need a shell here because commands are mainly shell script. They
	# contain pipe, redirection, etc.
	# 
	# @todo Force the use of bash!?
	# @todo Kill the command after a given timeout
	#
	# @param realCmd the command to execute
	# @return True if the command succeeded

	#@staticmethod
	def executeCmd(realCmd):
		logSys.debug(realCmd)
		if not realCmd:
			logSys.debug("Nothing to do")
			return True
		
		_cmd_lock.acquire()
		try: # Try wrapped within another try needed for python version < 2.5
			try:
				# The following line gives deadlock with multiple jails
				#retcode = call(realCmd, shell=True)
				retcode = os.system(realCmd)
				if retcode == 0:
					logSys.debug("%s returned successfully" % realCmd)
					return True
				else:
					msg = _RETCODE_HINTS.get(retcode, None)
 					logSys.error("%s returned %x" % (realCmd, retcode))
					if msg:
						logSys.info("HINT on %x: %s"
									% (retcode, msg % locals()))
			except OSError, e:
				logSys.error("%s failed with %s" % (realCmd, e))
		finally:
			_cmd_lock.release()
		return False
	executeCmd = staticmethod(executeCmd)
	
