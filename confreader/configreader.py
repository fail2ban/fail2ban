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

import log4py

from ConfigParser import *

# Gets the instance of log4py.
logSys = log4py.Logger().get_instance()

class ConfigReader:
	""" This class allow the handling of the configuration options.
		The DEFAULT section contains the global information about
		Fail2Ban. Each other section is for a different log file.
	"""

	def __init__(self, confPath):
		self.confPath = confPath
		self.configParser = SafeConfigParser()
		
	def openConf(self):
		""" Opens the configuration file.
		"""
		self.configParser.read(self.confPath)
	
	def getSections(self):
		""" Returns all the sections present in the configuration
			file except the DEFAULT and MAIL sections.
		"""
		sections = self.configParser.sections()
		sections.remove("MAIL")
		logSys.debug("Found sections: " + `sections`)
		return sections
	
	# Each optionValues entry is composed of an array with:
	# 0 -> the type of the option
	# 1 -> the name of the option
	# 2 -> the default value for the option
	def getLogOptions(self, sec, options):
		""" Gets all the options of a given section. The options
			are defined in the optionValues list.
		"""
		values = dict()
		for option in options:
			try:
				if option[0] == "bool":
					v = self.configParser.getboolean(sec, option[1])
				elif option[0] == "int":
					v = self.configParser.getint(sec, option[1])
				else:
					v = self.configParser.get(sec, option[1])
				
				values[option[1]] = v
			except NoOptionError:
				logSys.warn("No '" + option[1] + "' defined in '" + sec + "'")
				values[option[1]] = option[2]
		return values
		