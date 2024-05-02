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
import re
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
	alternateNowTime = None
	alternateNow = None

	@staticmethod
	def setAlternateNow(t):
		"""Set current time.

		Use None in order to always get the real current time.

		@param t the time to set or None
		"""

		MyTime.alternateNowTime = t
		MyTime.alternateNow = \
			datetime.datetime.fromtimestamp(t) if t is not None else None

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
		if MyTime.myTime == MyTime.alternateNowTime:
			return MyTime.alternateNow
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
	
	@staticmethod
	def time2str(unixTime, format="%Y-%m-%d %H:%M:%S"):
		"""Convert time to a string representing as date and time using given format.
		Default format is ISO 8601, YYYY-MM-DD HH:MM:SS without microseconds.

		@return ISO-capable string representation of given unixTime
		"""
		# consider end of 9999th year (in GMT+23 to avoid year overflow in other TZ)
		dt = datetime.datetime.fromtimestamp(
			unixTime).replace(microsecond=0
		) if unixTime < 253402214400 else datetime.datetime(9999, 12, 31, 23, 59, 59)
		return dt.strftime(format)

	## precreate/precompile primitives used in str2seconds:

	## preparing expression:
	_str2sec_prep = re.compile(r"(?i)(?<=[a-z])(\d)")
	## finally expression:
	_str2sec_fini = re.compile(r"(\d)\s+(\d)")
	## wrapper for each sub part:
	_str2sec_subpart = r"(?i)(?<=[\d\s])(%s)\b"
	## parts to be replaced - pair of (regexp x replacement):
	_str2sec_parts = (
		(re.compile(_str2sec_subpart % r"days?|da|dd?"),      "*"+str(24*60*60)),
		(re.compile(_str2sec_subpart % r"weeks?|wee?|ww?"),   "*"+str(7*24*60*60)),
		(re.compile(_str2sec_subpart % r"months?|mon?"),      "*"+str((365*3+366)*24*60*60/4/12)),
		(re.compile(_str2sec_subpart % r"years?|yea?|yy?"),   "*"+str((365*3+366)*24*60*60/4)),
		(re.compile(_str2sec_subpart % r"seconds?|sec?|ss?"), "*"+str(1)),
		(re.compile(_str2sec_subpart % r"minutes?|min?|mm?"), "*"+str(60)),
		(re.compile(_str2sec_subpart % r"hours?|hou?|hh?"),   "*"+str(60*60)),
	)

	@staticmethod
	def str2seconds(val):
		"""Wraps string expression like "1h 2m 3s" into number contains seconds (3723).
		The string expression will be evaluated as mathematical expression, spaces between each groups 
		  will be wrapped to "+" operand (only if any operand does not specified between).
		Because of case insensitivity and overwriting with minutes ("m" or "mm"), the short replacement for month
		  are "mo" or "mon".
		Ex: 1hour+30min = 5400
		    0d 1h 30m   = 5400
		    1year-6mo   = 15778800
		    6 months    = 15778800
		warn: month is not 30 days, it is a year in seconds / 12, the leap years will be respected also:
		      >>>> float(str2seconds("1month")) / 60 / 60 / 24
		      30.4375
		      >>>> float(str2seconds("1year")) / 60 / 60 / 24
		      365.25	
		
		@returns number (calculated seconds from expression "val")
		"""
		if isinstance(val, (int, float, complex)):
			return val
		# replace together standing abbreviations, example '1d12h' -> '1d 12h':
		val = MyTime._str2sec_prep.sub(r" \1", val)
		# replace abbreviation with expression:
		for rexp, rpl in MyTime._str2sec_parts:
			val = rexp.sub(rpl, val)
		val = MyTime._str2sec_fini.sub(r"\1+\2", val)
		return eval(val)

	class seconds2str():
		"""Converts seconds to string on demand (if string representation needed).
		Ex: seconds2str(86400*390)            = 1y 3w 4d
		    seconds2str(86400*368)            = 1y 3d
		    seconds2str(86400*365.5)          = 1y
		    seconds2str(86400*2+3600*7+60*15) = 2d 7h 15m
		    seconds2str(86400*2+3599)         = 2d 1h
		    seconds2str(3600-5)               = 1h
		    seconds2str(3600-10)              = 59m 50s
		    seconds2str(59)                   = 59s
		"""
		def __init__(self, sec):
			self.sec = sec
		def __str__(self):
			# s = str(datetime.timedelta(seconds=int(self.sec)))
			# return s if s[-3:] != ":00" else s[:-3]
			s = self.sec; c = 3
			# automatic accuracy: round by large values (and maximally 3 groups)
			if s >= 31536000: # a year as 365*24*60*60 (don't need to consider leap year by this accuracy)
				s = int(round(float(s)/86400)) # round by a day
				r = str(s//365) + 'y '; s %= 365
				if s >= 7:
					r += str(s//7) + 'w '; s %= 7
				if s:
					r += str(s) + 'd '
				return r[:-1]
			if s >= 604800: # a week as 24*60*60*7
				s = int(round(float(s)/3600)) # round by a hour
				r = str(s//168) + 'w '; s %= 168
				if s >= 24:
					r += str(s//24) + 'd '; s %= 24
				if s:
					r += str(s) + 'h '
				return r[:-1]
			if s >= 86400: # a day as 24*60*60
				s = int(round(float(s)/60)) # round by a minute
				r = str(s//1440) + 'd '; s %= 1440
				if s >= 60:
					r += str(s//60) + 'h '; s %= 60
				if s:
					r += str(s) + 'm '
				return r[:-1]
			if s >= 3595: # a hour as 60*60 (- 5 seconds)
				s = int(round(float(s)/10)) # round by 10 seconds
				r = str(s//360) + 'h '; s %= 360
				if s >= 6: # a minute
					r += str(s//6) + 'm '; s %= 6
				return r[:-1]
			r = ''
			if s >= 60: # a minute
				r += str(s//60) + 'm '; s %= 60
			if s: # remaining seconds
				r += str(s) + 's '
			elif not self.sec: # 0s
				r = '0 '
			return r[:-1]
		def __repr__(self):
			return self.__str__()
