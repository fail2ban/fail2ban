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
# $Revision: 433 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 433 $"
__date__ = "$Date: 2006-10-24 21:40:51 +0200 (Tue, 24 Oct 2006) $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import logging
from configreader import ConfigReader

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.client.config")

class ActionReader(ConfigReader):
	
	def __init__(self, action, name):
		ConfigReader.__init__(self)
		self.__file = action[0]
		self.__cInfo = action[1]
		self.__name = name
	
	def setFile(self, fileName):
		self.__file = fileName
	
	def getFile(self):
		return self.__file
	
	def setName(self, name):
		self.__name = name
	
	def getName(self):
		return self.__name
	
	def read(self):
		return ConfigReader.read(self, "action.d/" + self.__file)
	
	def getOptions(self, pOpts):
		opts = [["string", "actionstart", ""],
				["string", "actionstop", ""],
				["string", "actioncheck", ""],
				["string", "actionban", ""],
				["string", "actionunban", ""]]
		self.__opts = ConfigReader.getOptions(self, "Definition", opts, pOpts)
		
		if self.has_section("Init"):
			for opt in self.options("Init"):
				if not self.__cInfo.has_key(opt):
					self.__cInfo[opt] = self.get("Init", opt)
	
	def convert(self):
		head = ["set", self.__name]
		stream = list()
		stream.append(head + ["addaction", self.__file])
		for opt in self.__opts:
			if opt == "actionstart":
				stream.append(head + ["actionstart", self.__file, self.__opts[opt]])
			elif opt == "actionstop":
				stream.append(head + ["actionstop", self.__file, self.__opts[opt]])
			elif opt == "actioncheck":
				stream.append(head + ["actioncheck", self.__file, self.__opts[opt]])
			elif opt == "actionban":
				stream.append(head + ["actionban", self.__file, self.__opts[opt]])
			elif opt == "actionunban":
				stream.append(head + ["actionunban", self.__file, self.__opts[opt]])
		# cInfo
		if self.__cInfo:
			for p in self.__cInfo:
				stream.append(head + ["setcinfo", self.__file, p, self.__cInfo[p]])

		return stream
		