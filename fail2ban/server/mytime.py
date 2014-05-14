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

import time, datetime, re

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
		if MyTime.myTime is None:
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
		if MyTime.myTime is None:
			return time.gmtime()
		else:
			return time.gmtime(MyTime.myTime)
	gmtime = staticmethod(gmtime)

	#@staticmethod
	def now():
		if MyTime.myTime is None:
			return datetime.datetime.now()
		else:
			return datetime.datetime.fromtimestamp(MyTime.myTime)
	now = staticmethod(now)

	def localtime(x=None):
		if MyTime.myTime is None or x is not None:
			return time.localtime(x)
		else:
			return time.localtime(MyTime.myTime)
	localtime = staticmethod(localtime)

	## 
	# Wraps string expression like "1h 2m 3s" into number contains seconds (3723).
	# The string expression will be evaluated as mathematical expression, spaces between each groups 
	#   will be wrapped to "+" operand (only if any operand does not specified between).
	# Because of case insensitivity and overwriting with minutes ("m" or "mm"), the short replacement for month
	#   are "mo" or "mon" (like %b by date formating).
	# Ex: 1hour+30min = 5400
	#     0d 1h 30m   = 5400
	#     1year-6mo   = 15778800
	#     6 months    = 15778800
	# warn: month is not 30 days, it is a year in seconds / 12, the leap years will be respected also:
	#       >>>> float(Test.str2seconds("1month")) / 60 / 60 / 24
	#       30.4375
	#       >>>> float(Test.str2seconds("1year")) / 60 / 60 / 24
	#       365.25	
	#
	# @returns number (calculated seconds from expression "val")

	#@staticmethod
	def str2seconds(val):
		for rexp, rpl in (
			(r"days?|da|dd?", 24*60*60), (r"week?|wee?|ww?", 7*24*60*60), (r"months?|mon?", (365*3+366)*24*60*60/4/12), (r"years?|yea?|yy?", (365*3+366)*24*60*60/4), 
			(r"seconds?|sec?|ss?", 1), (r"minutes?|min?|mm?", 60), (r"hours?|ho|hh?", 60*60),
		):
			val = re.sub(r"(?i)(?<=[\d\s])(%s)\b" % rexp, "*"+str(rpl), val)
		val = re.sub(r"(\d)\s+(\d)", r"\1+\2", val);
		return eval(val)
