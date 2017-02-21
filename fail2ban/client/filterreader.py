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
from ..helpers import getLogger

# Gets the instance of the logger.
logSys = getLogger(__name__)


class FilterReader(DefinitionInitConfigReader):

	_configOpts = {
		"prefregex": ["string", None],
		"ignoreregex": ["string", None],
		"failregex": ["string", ""],
		"maxlines": ["int", None],
		"datepattern": ["string", None],
		"journalmatch": ["string", None],
	}

	def setFile(self, fileName):
		self.__file = fileName
		DefinitionInitConfigReader.setFile(self, os.path.join("filter.d", fileName))
	
	def getFile(self):
		return self.__file

	def convert(self):
		stream = list()
		opts = self.getCombined()
		if not len(opts):
			return stream
		for opt, value in opts.iteritems():
			if opt in ("failregex", "ignoreregex"):
				if value is None: continue
				multi = []
				for regex in value.split('\n'):
					# Do not send a command if the rule is empty.
					if regex != '':
						multi.append(regex)
				if len(multi) > 1:
					stream.append(["multi-set", self._jailName, "add" + opt, multi])
				elif len(multi):
					stream.append(["set", self._jailName, "add" + opt, multi[0]])
			elif opt in ('maxlines', 'prefregex'):
				# Be sure we set this options first.
				stream.insert(0, ["set", self._jailName, opt, value])
			elif opt in ('datepattern'):
				stream.append(["set", self._jailName, opt, value])
			# Do not send a command if the match is empty.
			elif opt == 'journalmatch':
				if value is None: continue
				for match in value.split("\n"):
					if match == '': continue
					stream.append(
						["set", self._jailName, "addjournalmatch"] +
                        shlex.split(match))
		return stream
		
