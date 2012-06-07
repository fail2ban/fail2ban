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

import logging
from configreader import ConfigReader
from jailreader import JailReader

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.client.config")

class JailsReader(ConfigReader):
	
	def __init__(self):
		ConfigReader.__init__(self)
		self.__jails = list()
	
	def read(self):
		ConfigReader.read(self, "jail")
	
	def getOptions(self, section = None):
		opts = []
		self.__opts = ConfigReader.getOptions(self, "Definition", opts)

		if section:
			# Get the options of a specific jail.
			jail = JailReader(section)
			jail.read()
			ret = jail.getOptions()
			if ret:
				if jail.isEnabled():
					# We only add enabled jails
					self.__jails.append(jail)
			else:
				logSys.error("Errors in jail '%s'. Skipping..." % section)
				return False
		else:
			# Get the options of all jails.
			for sec in self.sections():
				jail = JailReader(sec)
				jail.read()
				ret = jail.getOptions()
				if ret:
					if jail.isEnabled():
						# We only add enabled jails
						self.__jails.append(jail)
				else:
					logSys.error("Errors in jail '" + sec + "'. Skipping...")
					return False
		return True
	
	def convert(self):
		stream = list()
		for opt in self.__opts:
			if opt == "":
				stream.append([])
		# Convert jails
		for jail in self.__jails:
			stream.extend(jail.convert())
		# Start jails
		for jail in self.__jails:
			stream.append(["start", jail.getName()])
		
		return stream
		
