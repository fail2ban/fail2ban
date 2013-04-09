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

import time

##
# MyTime class.
#
# This class is a wrapper around time.time()  and time.gmtime(). When
# performing unit test, it is very useful to get a fixed value from these
# functions.
# Thus, time.time() and time.gmtime() should never be called directly.
# This wrapper should be called instead. The API are equivalent.

class MyTime:
	
	myTime = None
	
	##
	# Sets the current time.
	#
	# Use None in order to always get the real current time.
	#
	# @param t the time to set or None
	
	#@staticmethod
	def setTime(t):
		MyTime.myTime = t
	setTime = staticmethod(setTime)
	
	##
	# Equivalent to time.time()
	#
	# @return time.time() if setTime was called with None
	
	#@staticmethod
	def time():
		if MyTime.myTime == None:
			return time.time()
		else:
			return MyTime.myTime
	time = staticmethod(time)
	
	##
	# Equivalent to time.gmtime()
	#
	# @return time.gmtime() if setTime was called with None
	
	#@staticmethod
	def gmtime():
		if MyTime.myTime == None:
			return time.gmtime()
		else:
			return time.gmtime(MyTime.myTime)
	gmtime = staticmethod(gmtime)

	def localtime(x=None):
		if MyTime.myTime == None or x is not None:
			return time.localtime(x)
		else:
			return time.localtime(MyTime.myTime)
	localtime = staticmethod(localtime)
