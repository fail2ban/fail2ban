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
from ..server.action import CommandAction

# Gets the instance of the logger.
logSys = getLogger(__name__)


class ActionReader(DefinitionInitConfigReader):

	_configOpts = {
		"actionstart": ["string", None],
		"actionstart_on_demand": ["bool", None],
		"actionstop": ["string", None],
		"actionflush": ["string", None],
		"actionreload": ["string", None],
		"actioncheck": ["string", None],
		"actionrepair": ["string", None],
		"actionrepair_on_unban": ["bool", None],
		"actionban": ["string", None],
		"actionprolong": ["string", None],
		"actionreban": ["string", None],
		"actionunban": ["string", None],
		"norestored": ["bool", None],
	}

	def __init__(self, file_, jailName, initOpts, **kwargs):
		# always supply jail name as name parameter if not specified in options:
		n = initOpts.get("name")
		if n is None:
			initOpts["name"] = n = jailName
		actname = initOpts.get("actname")
		if actname is None:
			actname = file_
			# ensure we've unique action name per jail:
			if n != jailName:
				actname += n[len(jailName):] if n.startswith(jailName) else '-' + n
			initOpts["actname"] = actname
		self._name = actname
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
		opts = self.getCombined(
			ignore=CommandAction._escapedTags | set(('timeout', 'bantime')))
		# stream-convert:
		head = ["set", self._jailName]
		stream = list()
		stream.append(head + ["addaction", self._name])
		multi = []
		for opt, optval in opts.items():
			if opt in self._configOpts and not opt.startswith('known/'):
				multi.append([opt, optval])
		if self._initOpts:
			for opt, optval in self._initOpts.items():
				if opt not in self._configOpts and not opt.startswith('known/'):
					multi.append([opt, optval])
		if len(multi) > 1:
			stream.append(["multi-set", self._jailName, "action", self._name, multi])
		elif len(multi):
			stream.append(["set", self._jailName, "action", self._name] + multi[0])

		return stream
