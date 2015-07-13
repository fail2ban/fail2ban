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
import shlex

from .configreader import DefinitionInitConfigReader
from ..server.action import CommandAction
from ..helpers import getLogger

# Gets the instance of the logger.
logSys = getLogger(__name__)


class FilterReader(DefinitionInitConfigReader):

	_configOpts = [
		["string", "ignoreregex", None],
		["string", "failregex", ""],
	]

	def setFile(self, fileName):
		self.__file = fileName
		DefinitionInitConfigReader.setFile(self, os.path.join("filter.d", fileName))
	
	def getFile(self):
		return self.__file

	def getCombined(self):
		combinedopts = dict(list(self._opts.items()) + list(self._initOpts.items()))
		if not len(combinedopts):
			return {}
		opts = CommandAction.substituteRecursiveTags(combinedopts)
		if not opts:
			raise ValueError('recursive tag definitions unable to be resolved')
		return opts
	
	def convert(self):
		stream = list()
		opts = self.getCombined()
		if not len(opts):
			return stream
		for opt, value in opts.iteritems():
			if opt == "failregex":
				for regex in value.split('\n'):
					# Do not send a command if the rule is empty.
					if regex != '':
						stream.append(["set", self._jailName, "addfailregex", regex])
			elif opt == "ignoreregex":
				for regex in value.split('\n'):
					# Do not send a command if the rule is empty.
					if regex != '':
						stream.append(["set", self._jailName, "addignoreregex", regex])
		if self._initOpts:
			if 'maxlines' in self._initOpts:
				# We warn when multiline regex is used without maxlines > 1
				# therefore keep sure we set this option first.
				stream.insert(0, ["set", self._jailName, "maxlines", self._initOpts["maxlines"]])
			if 'datepattern' in self._initOpts:
				stream.append(["set", self._jailName, "datepattern", self._initOpts["datepattern"]])
			# Do not send a command if the match is empty.
			if self._initOpts.get("journalmatch", '') != '':
				for match in self._initOpts["journalmatch"].split("\n"):
					stream.append(
						["set", self._jailName, "addjournalmatch"] +
                        shlex.split(match))
		return stream
		
