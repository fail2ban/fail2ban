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
# $Revision: 655 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 655 $"
__date__ = "$Date: 2008-03-04 01:13:39 +0100 (Tue, 04 Mar 2008) $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import logging
from configreader import ConfigReader
from fail2banreader import Fail2banReader
from jailsreader import JailsReader

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.client.config")

class Configurator:
	
	def __init__(self):
		self.__settings = dict()
		self.__streams = dict()
		self.__fail2ban = Fail2banReader()
		self.__jails = JailsReader()
	
	#@staticmethod
	def setBaseDir(folderName):
		ConfigReader.setBaseDir(folderName)
	setBaseDir = staticmethod(setBaseDir)
	
	#@staticmethod
	def getBaseDir():
		return ConfigReader.getBaseDir()
	getBaseDir = staticmethod(getBaseDir)
	
	def readEarly(self):
		self.__fail2ban.read()
	
	def readAll(self):
		self.readEarly()
		self.__jails.read()
	
	def getEarlyOptions(self):
		return self.__fail2ban.getEarlyOptions()

	def getOptions(self, jail = None):
		self.__fail2ban.getOptions()
		return self.__jails.getOptions(jail)
		
	def convertToProtocol(self):
		self.__streams["general"] = self.__fail2ban.convert()
		self.__streams["jails"] = self.__jails.convert()
	
	def getConfigStream(self):
		cmds = list()
		for opt in self.__streams["general"]:
			cmds.append(opt)
		for opt in self.__streams["jails"]:
			cmds.append(opt)
		return cmds
	