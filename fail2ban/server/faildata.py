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

from ..helpers import getLogger

# Gets the instance of the logger.
logSys = getLogger(__name__)


class FailData:
	
	def __init__(self):
		self.__retry = 0
		self.__lastTime = 0
		self.__lastReset = 0
		self.__matches = []

	def setRetry(self, value):
		self.__retry = value
		# keep only the last matches or reset entirely
		# Explicit if/else for compatibility with Python 2.4
		if value:
			self.__matches = self.__matches[-min(len(self.__matches, value)):]
		else:
			self.__matches = []

	def getRetry(self):
		return self.__retry

	def getMatches(self):
		return self.__matches

	def inc(self, matches=None):
		self.__retry += 1
		self.__matches += matches or []

	def setLastTime(self, value):
		if value > self.__lastTime:
			self.__lastTime = value
	
	def getLastTime(self):
		return self.__lastTime

	def getLastReset(self):
		return self.__lastReset

	def setLastReset(self, value):
		self.__lastReset = value
