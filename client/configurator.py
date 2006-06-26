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
# $Revision: 1.6 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 1.6 $"
__date__ = "$Date: 2005/11/20 17:07:47 $"
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
		self.settings = dict()
		self.streams = dict()
		self.fail2ban = Fail2banReader()
		self.jails = JailsReader()
	
	def setBaseDir(self, dir):
		ConfigReader.setBaseDir(dir)
	
	def getBaseDir(self):
		return ConfigReader.getBaseDir()
	
	def readAll(self):
		self.fail2ban.read()
		self.jails.read()
	
	def getAllOptions(self):
		self.settings["general"] = self.fail2ban.getOptions()
		self.settings["jails"] = self.jails.getOptions()
		
	def convertToProtocol(self):
		self.streams["general"] = self.fail2ban.convert()
		self.streams["jails"] = self.jails.convert()
	
	def getConfigStream(self):
		cmds = list()
		for opt in self.streams["general"]:
			cmds.append(opt)
		for opt in self.streams["jails"]:
			cmds.append(opt)
		return cmds
	