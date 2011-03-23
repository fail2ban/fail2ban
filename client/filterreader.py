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
# $Revision: 711 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 711 $"
__date__ = "$Date: 2008-08-13 00:05:13 +0200 (Wed, 13 Aug 2008) $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import logging
from configreader import ConfigReader

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.client.config")

class FilterReader(ConfigReader):
	
	def __init__(self, fileName, name):
		ConfigReader.__init__(self)
		self.__file = fileName
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
		return ConfigReader.read(self, "filter.d/" + self.__file)
	
	def getOptions(self, pOpts):
		opts = [["string", "ignoreregex", ""],
				["string", "failregex", ""]]
		self.__opts = ConfigReader.getOptions(self, "Definition", opts, pOpts)
	
	def convert(self):
		stream = list()
		for opt in self.__opts:
			if opt == "failregex":
				for regex in self.__opts[opt].split('\n'):
					# Do not send a command if the rule is empty.
					if regex != '':
						stream.append(["set", self.__name, "addfailregex", regex])
			elif opt == "ignoreregex":
				for regex in self.__opts[opt].split('\n'):
					# Do not send a command if the rule is empty.
					if regex != '':
						stream.append(["set", self.__name, "addignoreregex", regex])		
		return stream
		