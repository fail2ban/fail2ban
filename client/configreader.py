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

import logging, os
from ConfigParser import *

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.client.config")

class ConfigReader(SafeConfigParser):
	
	basedir = "/etc/fail2ban/"
	
	def __init__(self):
		SafeConfigParser.__init__(self)
		self.__opts = None
	
	@staticmethod
	def setBaseDir(dir):
		global basedir
		path = dir.rstrip('/')
		basedir = path + '/'
		
	@staticmethod
	def getBaseDir():
		global basedir
		return basedir
	
	def read(self, filename):
		global basedir
		basename = basedir + filename
		logSys.debug("Reading " + basename)
		bConf = basename + ".conf"
		bLocal = basename + ".local"
		if os.path.exists(bConf) or os.path.exists(bLocal):
			SafeConfigParser.read(self, [bConf, bLocal])
			return True
		else:
			logSys.error(bConf + " and " + bLocal + " do not exist")
			return False
	
	##
	# Read the options.
	#
	# Read the given option in the configuration file. Default values
	# are used...
	# Each optionValues entry is composed of an array with:
	# 0 -> the type of the option
	# 1 -> the name of the option
	# 2 -> the default value for the option
	def getOptions(self, sec, options, pOptions = None):
		values = dict()
		for option in options:
			try:
				if option[0] == "bool":
					v = self.getboolean(sec, option[1])
				elif option[0] == "int":
					v = self.getint(sec, option[1])
				else:
					v = self.get(sec, option[1])
				if not pOptions == None and option[1] in pOptions:
					continue
				values[option[1]] = v
			except NoSectionError, e:
				# No "Definition" section or wrong basedir
				logSys.error(e)
				values[option[1]] = option[2]
			except NoOptionError:
				if not option[2] == None:
					logSys.warn("No '" + option[1] + "' defined in '" + sec + "'")
					values[option[1]] = option[2]
			except ValueError:
				logSys.warn("Wrong value for '" + option[1] + "' in '" + sec +
							"'. Using default one: '" + `option[2]` + "'")
				values[option[1]] = option[2]
		return values
