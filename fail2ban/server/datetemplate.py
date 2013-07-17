# emacs: -*- mode: python; coding: utf-8; py-indent-offset: 4; indent-tabs-mode: t -*-
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

import re, time

from mytime import MyTime
import iso8601

import logging
logSys = logging.getLogger(__name__)


class DateTemplate:
	
	def __init__(self):
		self.__name = ""
		self.__regex = ""
		self.__cRegex = None
		self.__hits = 0
	
	def setName(self, name):
		self.__name = name
		
	def getName(self):
		return self.__name
	
	def setRegex(self, regex, wordBegin=True):
		regex = regex.strip()
		if (wordBegin and not re.search(r'^\^', regex)):
			regex = r'\b' + regex
		self.__regex = regex
		self.__cRegex = re.compile(regex, re.UNICODE)
		
	def getRegex(self):
		return self.__regex
	
	def getHits(self):
		return self.__hits

	def incHits(self):
		self.__hits += 1
	
	def matchDate(self, line):
		dateMatch = self.__cRegex.search(line)
		return dateMatch
	
	def getDate(self, line):
		raise Exception("matchDate() is abstract")


class DateEpoch(DateTemplate):
	
	def __init__(self):
		DateTemplate.__init__(self)
		# We already know the format for TAI64N
		self.setRegex("^\d{10}(\.\d{6})?")
	
	def getDate(self, line):
		date = None
		dateMatch = self.matchDate(line)
		if dateMatch:
			# extract part of format which represents seconds since epoch
			date = list(MyTime.localtime(float(dateMatch.group())))
		return date


##
# Use strptime() to parse a date. Our current locale is the 'C'
# one because we do not set the locale explicitly. This is POSIX
# standard.

class DateStrptime(DateTemplate):

	TABLE = dict()
	TABLE["Jan"] = ["Sty"]
	TABLE["Feb"] = [u"Fév", "Lut"]
	TABLE["Mar"] = [u"Mär", "Mar"]
	TABLE["Apr"] = ["Avr", "Kwi"]
	TABLE["May"] = ["Mai", "Maj"]
	TABLE["Jun"] = ["Lip"]
	TABLE["Jul"] = ["Sie"]
	TABLE["Aug"] = ["Aou", "Wrz"]
	TABLE["Sep"] = ["Sie"]
	TABLE["Oct"] = [u"Paź"]
	TABLE["Nov"] = ["Lis"]
	TABLE["Dec"] = [u"Déc", "Dez", "Gru"]
	
	def __init__(self):
		DateTemplate.__init__(self)
		self.__pattern = ""
	
	def setPattern(self, pattern):
		self.__pattern = pattern.strip()
		
	def getPattern(self):
		return self.__pattern
	
	#@staticmethod
	def convertLocale(date):
		for t in DateStrptime.TABLE:
			for m in DateStrptime.TABLE[t]:
				if date.find(m) >= 0:
					logSys.debug(u"Replacing %r with %r in %r" %
								 (m, t, date))
					return date.replace(m, t)
		return date
	convertLocale = staticmethod(convertLocale)
	
	def getDate(self, line):
		date = None
		dateMatch = self.matchDate(line)
		if dateMatch:
			try:
				# Try first with 'C' locale
				date = list(time.strptime(dateMatch.group(), self.getPattern()))
			except ValueError:
				# Try to convert date string to 'C' locale
				conv = self.convertLocale(dateMatch.group())
				try:
					date = list(time.strptime(conv, self.getPattern()))
				except (ValueError, re.error), e:
					# Try to add the current year to the pattern. Should fix
					# the "Feb 29" issue.
					opattern = self.getPattern()
					# makes sense only if %Y is not in already:
					if not '%Y' in opattern:
						pattern = "%s %%Y" % opattern
						conv += " %s" % MyTime.gmtime()[0]
						date = list(time.strptime(conv, pattern))
					else:
						# we are helpless here
						raise ValueError(
							"Given pattern %r does not match. Original "
							"exception was %r and Feb 29 workaround could not "
							"be tested due to already present year mark in the "
							"pattern" % (opattern, e))
			if date[0] < 2000:
				# There is probably no year field in the logs
				# NOTE: Possibly makes week/year day incorrect
				date[0] = MyTime.gmtime()[0]
				# Bug fix for #1241756
				# If the date is greater than the current time, we suppose
				# that the log is not from this year but from the year before
				if time.mktime(tuple(date)) > MyTime.time():
					logSys.debug(
						u"Correcting deduced year from %d to %d since %f > %f" %
						(date[0], date[0]-1, time.mktime(tuple(date)), MyTime.time()))
					# NOTE: Possibly makes week/year day incorrect
					date[0] -= 1
				elif date[1] == 1 and date[2] == 1:
					# If it is Jan 1st, it is either really Jan 1st or there
					# is neither month nor day in the log.
					# NOTE: Possibly makes week/year day incorrect
					date[1] = MyTime.gmtime()[1]
					date[2] = MyTime.gmtime()[2]
		return date

class DatePatternRegex(DateStrptime):
	_reEscape = r"([\\.^$*+?\(\){}\[\]|])"
	_patternRE = r"%(%|[aAbBdHIjmMpSUwWyY])"
	_patternName = {
		'a': "DAY", 'A': "DAYNAME", 'b': "MON", 'B': "MONTH", 'd': "Day",
		'H': "24hour", 'I': "12hour", 'j': "Yearday", 'm': "Month",
		'M': "Minute", 'p': "AMPM", 'S': "Second", 'U': "Yearweek",
		'w': "Weekday", 'W': "Yearweek", 'y': 'Year2', 'Y': "Year", '%': "%"}
	_patternRegex = {
		'a': r"\w{3}", 'A': r"\w+", 'b': r"\w{3}", 'B': r"\w+",
		'd': r"(?:3[0-1]|[1-2]\d|[ 0]?\d)", 'H': r"(?:2[0-3]|1\d|[ 0]?\d)",
		'I': r"(?:1[0-2]|[ 0]?\d)",
		'j': r"(?:36[0-6]3[0-5]\d|[1-2]\d\d|[ 0]?\d\d|[ 0]{0,2}\d)",
		'm': r"(?:1[0-2]|[ 0]?[1-9])", 'M': r"[0-5]\d", 'p': r"[AP]M",
		'S': r"(?:6[01]|[0-5]\d)", 'U': r"(?:5[0-3]|[1-4]\d|[ 0]?\d)",
		'w': r"[0-6]", 'W': r"(?:5[0-3]|[ 0]?\d)", 'y': r"\d{2}",
		'Y': r"\d{4}", '%': "%"}

	def __init__(self, pattern=None, **kwargs):
		DateStrptime.__init__(self)
		if pattern:
			self.setPattern(pattern, **kwargs)

	def setPattern(self, pattern, anchor=False, **kwargs):
		self.__pattern = pattern.strip()

		name = re.sub(self._patternRE, r'%(\1)s', pattern) % self._patternName
		DateStrptime.setName(self, name)

		# Custom escape as don't want to escape "%"
		pattern = re.sub(self._reEscape, r'\\\1', pattern)
		regex = re.sub(
			self._patternRE, r'%(\1)s', pattern) % self._patternRegex
		if anchor:
			regex = r"^" + regex
		DateStrptime.setRegex(self, regex, **kwargs)

	def getPattern(self):
		return self.__pattern

	def setRegex(self, line):
		raise NotImplementedError("Regex derived from pattern")

	def setName(self, line):
		raise NotImplementedError("Name derived from pattern")

class DateTai64n(DateTemplate):
	
	def __init__(self):
		DateTemplate.__init__(self)
		# We already know the format for TAI64N
		# yoh: we should not add an additional front anchor
		self.setRegex("@[0-9a-f]{24}", wordBegin=False)
	
	def getDate(self, line):
		date = None
		dateMatch = self.matchDate(line)
		if dateMatch:
			# extract part of format which represents seconds since epoch
			value = dateMatch.group()
			seconds_since_epoch = value[2:17]
			# convert seconds from HEX into local time stamp
			date = list(MyTime.localtime(int(seconds_since_epoch, 16)))
		return date


class DateISO8601(DateTemplate):

	def __init__(self):
		DateTemplate.__init__(self)
		date_re = "[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}" \
		".[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?" \
		"(Z|(([-+])([0-9]{2}):([0-9]{2})))?"
		self.setRegex(date_re)
	
	def getDate(self, line):
		date = None
		dateMatch = self.matchDate(line)
		if dateMatch:
			# Parses the date.
			value = dateMatch.group()
			date = list(iso8601.parse_date(value, None).timetuple())
		return date

