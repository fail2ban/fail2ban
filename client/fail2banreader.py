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
# $Revision: 407 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 407 $"
__date__ = "$Date: 2006-10-09 20:05:13 +0200 (Mon, 09 Oct 2006) $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import logging
from configreader import ConfigReader

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.client.config")

class Fail2banReader(ConfigReader):
	
	def __init__(self):
		ConfigReader.__init__(self)
	
	def read(self):
		ConfigReader.read(self, "fail2ban")
	
	def getEarlyOptions(self):
		opts = [["string", "socket", "/tmp/fail2ban.sock"]]
		return ConfigReader.getOptions(self, "Definition", opts)
	
	def getOptions(self):
		opts = [["int", "loglevel", 1],
				["string", "logtarget", "STDERR"]]
		self.__opts = ConfigReader.getOptions(self, "Definition", opts)
	
	def convert(self):
		stream = list()
		for opt in self.__opts:
			if opt == "loglevel":
				stream.append(["set", "loglevel", self.__opts[opt]])
			elif opt == "logtarget":
				stream.append(["set", "logtarget", self.__opts[opt]])
		return stream
	