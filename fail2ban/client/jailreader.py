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
# $Revision$

__author__ = "Cyril Jaquier"
__version__ = "$Revision$"
__date__ = "$Date$"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import logging, re, glob

from configreader import ConfigReader
from filterreader import FilterReader
from actionreader import ActionReader

# Gets the instance of the logger.
logSys = logging.getLogger(__name__)

class JailReader(ConfigReader):
	
	optionCRE = re.compile("^((?:\w|-|_|\.)+)(?:\[(.*)\])?$")
	
	def __init__(self, name, force_enable=False, **kwargs):
		ConfigReader.__init__(self, **kwargs)
		self.__name = name
		self.__filter = None
		self.__force_enable = force_enable
		self.__actions = list()
	
	def setName(self, value):
		self.__name = value
	
	def getName(self):
		return self.__name
	
	def read(self):
		return ConfigReader.read(self, "jail")
	
	def isEnabled(self):
		return self.__force_enable or self.__opts["enabled"]
	
	def getOptions(self):
		opts = [["bool", "enabled", "false"],
				["string", "logpath", "/var/log/messages"],
				["string", "logencoding", "auto"],
				["string", "backend", "auto"],
				["int", "maxretry", 3],
				["int", "findtime", 600],
				["int", "bantime", 600],
				["string", "usedns", "warn"],
				["string", "failregex", None],
				["string", "ignoreregex", None],
				["string", "ignoreip", None],
				["string", "filter", ""],
				["string", "action", ""]]
		self.__opts = ConfigReader.getOptions(self, self.__name, opts)
		
		if self.isEnabled():
			# Read filter
			filterName, filterOpt = JailReader.extractOptions(
				self.__opts["filter"])
			self.__filter = FilterReader(
				filterName, self.__name, filterOpt, basedir=self.getBaseDir())
			ret = self.__filter.read()
			if ret:
				self.__filter.getOptions(self.__opts)
			else:
				logSys.error("Unable to read the filter")
				return False
			
			# Read action
			for act in self.__opts["action"].split('\n'):
				try:
					if not act:			  # skip empty actions
						continue
					actName, actOpt = JailReader.extractOptions(act)
					action = ActionReader(
						actName, self.__name, actOpt, basedir=self.getBaseDir())
					ret = action.read()
					if ret:
						action.getOptions(self.__opts)
						self.__actions.append(action)
					else:
						raise AttributeError("Unable to read action")
				except Exception, e:
					logSys.error("Error in action definition " + act)
					logSys.debug("Caught exception: %s" % (e,))
					return False
			if not len(self.__actions):
				logSys.warn("No actions were defined for %s" % self.__name)
		return True
	
	def convert(self):
		stream = []
		for opt in self.__opts:
			if opt == "logpath":
				for path in self.__opts[opt].split("\n"):
					pathList = glob.glob(path)
					if len(pathList) == 0:
						logSys.error("No file found for " + path)
					for p in pathList:
						stream.append(["set", self.__name, "addlogpath", p])
			elif opt == "logencoding":
				stream.append(["set", self.__name, "logencoding", self.__opts[opt]])
			elif opt == "backend":
				backend = self.__opts[opt]
			elif opt == "maxretry":
				stream.append(["set", self.__name, "maxretry", self.__opts[opt]])
			elif opt == "ignoreip":
				for ip in self.__opts[opt].split():
					# Do not send a command if the rule is empty.
					if ip != '':
						stream.append(["set", self.__name, "addignoreip", ip])
			elif opt == "findtime":
				stream.append(["set", self.__name, "findtime", self.__opts[opt]])
			elif opt == "bantime":
				stream.append(["set", self.__name, "bantime", self.__opts[opt]])
			elif opt == "usedns":
				stream.append(["set", self.__name, "usedns", self.__opts[opt]])
			elif opt == "failregex":
				stream.append(["set", self.__name, "addfailregex", self.__opts[opt]])
			elif opt == "ignoreregex":
				for regex in self.__opts[opt].split('\n'):
					# Do not send a command if the rule is empty.
					if regex != '':
						stream.append(["set", self.__name, "addignoreregex", regex])
		stream.extend(self.__filter.convert())
		for action in self.__actions:
			stream.extend(action.convert())
		stream.insert(0, ["add", self.__name, backend])
		return stream
	
	#@staticmethod
	def extractOptions(option):
		m = JailReader.optionCRE.match(option)
		d = dict()
		mgroups = m.groups()
		if len(mgroups) == 2:
			option_name, option_opts = mgroups
		elif len(mgroups) == 1:
			option_name, option_opts = mgroups[0], None
		else:
			raise ValueError("While reading option %s we should have got up to "
							 "2 groups. Got: %r" % (option, mgroups))
		if not option_opts is None:
			# Huge bad hack :( This method really sucks. TODO Reimplement it.
			options = ""
			escapeChar = None
			allowComma = False
			for c in option_opts:
				if c in ('"', "'") and not allowComma:
					# Start
					escapeChar = c
					allowComma = True
				elif c == escapeChar:
					# End
					escapeChar = None
					allowComma = False
				else:
					if c == ',' and allowComma:
						options += "<COMMA>"
					else:
						options += c
			
			# Split using ,
			optionsSplit = options.split(',')
			# Replace the tag <COMMA> with ,
			optionsSplit = [n.replace("<COMMA>", ',') for n in optionsSplit]
			
			for param in optionsSplit:
				p = param.split('=')
				try:
					d[p[0].strip()] = p[1].strip()
				except IndexError:
					logSys.error("Invalid argument %s in '%s'" % (p, option_opts))
		return [option_name, d]
	extractOptions = staticmethod(extractOptions)
