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

import os, sys, time

from ConfigParser import *

class ConfigReader:
	""" This class allow the handling of the configuration options.
		The DEFAULT section contains the global information about
		Fail2Ban. Each other section is for a different log file.
	"""
	
	optionValues = ("logfile", "timeregex", "timepattern", "failregex")
	
	def __init__(self, logSys, confPath):
		self.confPath = confPath
		self.configParser = SafeConfigParser()
		self.logSys = logSys
		
	def openConf(self):
		""" Opens the configuration file.
		"""
		self.configParser.read(self.confPath)
	
	def getSections(self):
		""" Returns all the sections present in the configuration
			file except the DEFAULT section.
		"""
		return self.configParser.sections()
		
	def getLogOptions(self, sec):
		""" Gets all the options of a given section. The options
			are defined in the optionValues list.
		"""
		values = dict()
		for option in self.optionValues:
			try:
				v = self.configParser.get(sec, option)
				values[option] = v
			except NoOptionError:
				self.logSys.info("No "+option+" defined in "+sec)
		return values
		