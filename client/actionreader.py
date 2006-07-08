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

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.client.config")

class ActionReader(ConfigReader):
	
	def __init__(self, file, name):
		ConfigReader.__init__(self)
		self.file = file
		self.name = name
	
	def setFile(self, file):
		self.file = file
	
	def getFile(self):
		return self.file
	
	def setName(self, name):
		self.name = name
	
	def getName(self):
		return self.name
	
	def read(self):
		ConfigReader.read(self, "action.d/" + self.file)
	
	def getOptions(self, pOpts):
		opts = [["string", "actionstart", ""],
				["string", "actionstop", ""],
				["string", "actioncheck", ""],
				["string", "actionban", ""],
				["string", "actionunban", ""]]
		self.opts = ConfigReader.getOptions(self, "DEFAULT", opts, pOpts)
	
	def convert(self):
		head = ["set", self.name]
		stream = list()
		stream.append(head + ["addaction", self.file])
		for opt in self.opts:
			if opt == "actionstart":
				stream.append(head + ["actionstart", self.file, self.opts[opt]])
			elif opt == "actionstop":
				stream.append(head + ["actionstop", self.file, self.opts[opt]])
			elif opt == "actioncheck":
				stream.append(head + ["actioncheck", self.file, self.opts[opt]])
			elif opt == "actionban":
				stream.append(head + ["actionban", self.file, self.opts[opt]])
			elif opt == "actionunban":
				stream.append(head + ["actionunban", self.file, self.opts[opt]])
		return stream
		