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
		"usedns": ["string", None],
		"prefregex": ["string", None],
		"ignoreregex": ["string", None],
		"failregex": ["string", None],
		"maxlines": ["int", None],
		"datepattern": ["string", None],
		"journalmatch": ["string", None],
	}

	def setFile(self, fileName):
		self.__file = fileName
		DefinitionInitConfigReader.setFile(self, os.path.join("filter.d", fileName))
	
	def getFile(self):
		return self.__file

	def applyAutoOptions(self, backend):
		# set init option to backend-related logtype, considering
		# that the filter settings may be overwritten in its local:
		if (not self._initOpts.get('logtype') and 
		    not self.has_option('Definition', 'logtype', False)
		  ):
			self._initOpts['logtype'] = ['file','journal'][int(backend.startswith("systemd"))]

	def convert(self):
		stream = list()
		opts = self.getCombined()
		if not len(opts):
			return stream
		return FilterReader._fillStream(stream, opts, self._jailName)

	@staticmethod
	def _fillStream(stream, opts, jailName):
		prio0idx = 0
		for opt, value in opts.items():
			# Do not send a command if the value is not set (empty).
			if value is None: continue
			if opt in ("failregex", "ignoreregex"):
				multi = []
				for regex in value.split('\n'):
					# Do not send a command if the rule is empty.
					if regex != '':
						multi.append(regex)
				if len(multi) > 1:
					stream.append(["multi-set", jailName, "add" + opt, multi])
				elif len(multi):
					stream.append(["set", jailName, "add" + opt, multi[0]])
			elif opt in ('usedns', 'maxlines', 'prefregex'):
				# Be sure we set this options first, and usedns is before all regex(s).
				stream.insert(0 if opt == 'usedns' else prio0idx,
					["set", jailName, opt, value])
				prio0idx += 1
			elif opt in ('datepattern'):
				stream.append(["set", jailName, opt, value])
			elif opt == 'journalmatch':
				for match in value.split("\n"):
					if match == '': continue
					stream.append(
						["set", jailName, "addjournalmatch"] + shlex.split(match))
		return stream
		
