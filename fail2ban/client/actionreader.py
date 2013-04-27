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

import logging, os
from configreader import ConfigReader, DefinitionInitConfigReader

# Gets the instance of the logger.
logSys = logging.getLogger(__name__)

class ActionReader(DefinitionInitConfigReader):

	_configOpts = [
		["string", "actionstart", ""],
		["string", "actionstop", ""],
		["string", "actioncheck", ""],
		["string", "actionban", ""],
		["string", "actionunban", ""],
	]

	def read(self):
		return ConfigReader.read(self, os.path.join("action.d", self._file))

	def convert(self):
		head = ["set", self._name]
		stream = list()
		stream.append(head + ["addaction", self._file])
		for opt in self._opts:
			if opt == "actionstart":
				stream.append(head + ["actionstart", self._file, self._opts[opt]])
			elif opt == "actionstop":
				stream.append(head + ["actionstop", self._file, self._opts[opt]])
			elif opt == "actioncheck":
				stream.append(head + ["actioncheck", self._file, self._opts[opt]])
			elif opt == "actionban":
				stream.append(head + ["actionban", self._file, self._opts[opt]])
			elif opt == "actionunban":
				stream.append(head + ["actionunban", self._file, self._opts[opt]])
		if self._initOpts:
			if "timeout" in self._initOpts:
				stream.append(head + ["timeout", self._file, self._opts["timeout"]])
			# cInfo
			for p in self._initOpts:
				stream.append(head + ["setcinfo", self._file, p, self._initOpts[p]])

		return stream
