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

import os

from .configreader import DefinitionInitConfigReader
from ..helpers import getLogger

# Gets the instance of the logger.
logSys = getLogger(__name__)


class ActionReader(DefinitionInitConfigReader):

	_configOpts = {
		"actionstart": ["string", None],
		"actionstop": ["string", None],
		"actioncheck": ["string", None],
		"actionban": ["string", None],
		"actionunban": ["string", None],
	}

	def __init__(self, file_, jailName, initOpts, **kwargs):
		self._name = initOpts.get("actname", file_)
		DefinitionInitConfigReader.__init__(
			self, file_, jailName, initOpts, **kwargs)

	def setFile(self, fileName):
		self.__file = fileName
		DefinitionInitConfigReader.setFile(self, os.path.join("action.d", fileName))
	
	def getFile(self):
		return self.__file

	def setName(self, name):
		self._name = name

	def getName(self):
		return self._name

	def convert(self):
		head = ["set", self._jailName]
		stream = list()
		stream.append(head + ["addaction", self._name])
		multi = []
		for opt, optval in self._opts.iteritems():
			if opt in self._configOpts:
				multi.append([opt, optval])
		if self._initOpts:
			for opt, optval in self._initOpts.iteritems():
				multi.append([opt, optval])
		if len(multi) > 1:
			stream.append(["multi-set", self._jailName, "action", self._name, multi])
		elif len(multi):
			stream.append(["set", self._jailName, "action", self._name] + multi[0])

		return stream
