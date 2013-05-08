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

__author__ = "Cyril Jaquier"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import logging, os
from configreader import ConfigReader, DefinitionInitConfigReader

# Gets the instance of the logger.
logSys = logging.getLogger(__name__)

class FilterReader(DefinitionInitConfigReader):

	_configOpts = [
		["string", "ignoreregex", ""],
		["string", "failregex", ""],
	]

	def read(self):
		return ConfigReader.read(self, os.path.join("filter.d", self._file))
	
	def convert(self):
		stream = list()
		for opt in self._opts:
			if opt == "failregex":
				for regex in self._opts[opt].split('\n'):
					# Do not send a command if the rule is empty.
					if regex != '':
						stream.append(["set", self._jailName, "addfailregex", regex])
			elif opt == "ignoreregex":
				for regex in self._opts[opt].split('\n'):
					# Do not send a command if the rule is empty.
					if regex != '':
						stream.append(["set", self._jailName, "addignoreregex", regex])		
		if self._initOpts:
			if 'maxlines' in self._initOpts:
				stream.append(["set", self._jailName, "maxlines", self._initOpts["maxlines"]])
		return stream
		
