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

__author__ = "Cyril Jaquier"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import datetime
import time


##
# MyTime class.
#

class MyTime:
	"""A wrapper around time module primarily for testing purposes

	This class is a wrapper around time.time()  and time.gmtime(). When
	performing unit test, it is very useful to get a fixed value from
	these functions.  Thus, time.time() and time.gmtime() should never
	be called directly.  This wrapper should be called instead. The API
	are equivalent.
	"""

	myTime = None

	@staticmethod
	def setTime(t):
		"""Set current time.

		Use None in order to always get the real current time.

		@param t the time to set or None
		"""

		MyTime.myTime = t

	@staticmethod
	def time():
		"""Decorate time.time() for the purpose of testing mocking

		@return time.time() if setTime was called with None
		"""

		if MyTime.myTime is None:
			return time.time()
		else:
			return MyTime.myTime

	@staticmethod
	def gmtime():
		"""Decorate time.gmtime() for the purpose of testing mocking

		@return time.gmtime() if setTime was called with None
		"""
		if MyTime.myTime is None:
			return time.gmtime()
		else:
			return time.gmtime(MyTime.myTime)

	@staticmethod
	def now():
		"""Decorate datetime.now() for the purpose of testing mocking

		@return datetime.now() if setTime was called with None
		"""
		if MyTime.myTime is None:
			return datetime.datetime.now()
		else:
			return datetime.datetime.fromtimestamp(MyTime.myTime)

	@staticmethod
	def localtime(x=None):
		"""Decorate time.localtime() for the purpose of testing mocking

		@return time.localtime() if setTime was called with None
		"""
		if MyTime.myTime is None or x is not None:
			return time.localtime(x)
		else:
			return time.localtime(MyTime.myTime)
