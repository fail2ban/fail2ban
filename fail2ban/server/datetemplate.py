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

import re, time, calendar

from datetime import datetime
from datetime import timedelta

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
		#logSys.debug(u"setRegex for %s is %r" % (self.__name, regex))
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

	def resetHits(self):
		self.__hits = 0
	
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
		dateMatch = self.matchDate(line)
		if dateMatch:
			# extract part of format which represents seconds since epoch
			return (float(dateMatch.group()), dateMatch)
		return None


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
		self._pattern = ""
		self._unsupportedStrptimeBits = False
	
	def setPattern(self, pattern):
		self._unsupported_f = not DateStrptime._f and re.search('%f', pattern)
		self._unsupported_z = not DateStrptime._z and re.search('%z', pattern)
		self._pattern = pattern
		
	def getPattern(self):
		return self._pattern
	
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
		dateMatch = self.matchDate(line)

		if dateMatch:
			datePattern = self.getPattern()
			if self._unsupported_f:
				if dateMatch.group('_f'):
					datePattern = re.sub(r'%f', dateMatch.group('_f'), datePattern)
					logSys.debug(u"Replacing %%f with %r now %r" % (dateMatch.group('_f'), datePattern))
			if self._unsupported_z:
				if dateMatch.group('_z'):
					datePattern = re.sub(r'%z', dateMatch.group('_z'), datePattern)
					logSys.debug(u"Replacing %%z with %r now %r" % (dateMatch.group('_z'), datePattern))
			try:
				# Try first with 'C' locale
				date = datetime.strptime(dateMatch.group(), datePattern)
			except ValueError:
				# Try to convert date string to 'C' locale
				conv = self.convertLocale(dateMatch.group())
				try:
					date = datetime.strptime(conv, self.getPattern())
				except (ValueError, re.error), e:
					# Try to add the current year to the pattern. Should fix
					# the "Feb 29" issue.
					opattern = self.getPattern()
					# makes sense only if %Y is not in already:
					if not '%Y' in opattern:
						pattern = "%s %%Y" % opattern
						conv += " %s" % MyTime.gmtime()[0]
						date = datetime.strptime(conv, pattern)
					else:
						# we are helpless here
						raise ValueError(
							"Given pattern %r does not match. Original "
							"exception was %r and Feb 29 workaround could not "
							"be tested due to already present year mark in the "
							"pattern" % (opattern, e))

			if self._unsupported_z:
				z = dateMatch.group('_z')
				if z:
					delta = timedelta(hours=int(z[1:3]),minutes=int(z[3:]))
					direction = z[0]
					logSys.debug(u"Altering %r by removing time zone offset (%s)%s" % (date, direction, delta))
					# here we reverse the effect of the timezone and force it to UTC
					if direction == '+':
						date -= delta
					else:
						date += delta
					date = date.replace(tzinfo=iso8601.Utc())
				else:
					logSys.warn("No _z group captured and %%z is not supported on current platform"
								" - timezone ignored and assumed to be localtime. date: %s on line: %s"
								% (date, line))

			if date.year < 2000:
				# There is probably no year field in the logs
				# NOTE: Possibly makes week/year day incorrect
				date = date.replace(year=MyTime.gmtime()[0])
				# Bug fix for #1241756
				# If the date is greater than the current time, we suppose
				# that the log is not from this year but from the year before
				if date > MyTime.now():
					logSys.debug(
						u"Correcting deduced year by one since %s > now (%s)" %
						(date, MyTime.time()))
					date = date.replace(year=date.year-1)
				elif date.month == 1 and date.day == 1:
					# If it is Jan 1st, it is either really Jan 1st or there
					# is neither month nor day in the log.
					# NOTE: Possibly makes week/year day incorrect
					date = date.replace(month=MyTime.gmtime()[1], day=1)

			if date.tzinfo:
				return ( calendar.timegm(date.utctimetuple()), dateMatch )
			else:
				return ( time.mktime(date.utctimetuple()), dateMatch )
				
		return None

try:
	time.strptime("26-Jul-2007 15:20:52.252","%d-%b-%Y %H:%M:%S.%f")
	DateStrptime._f = True
except (ValueError, KeyError):
	DateTemplate._f = False

try:
	time.strptime("24/Mar/2013:08:58:32 -0500","%d/%b/%Y:%H:%M:%S %z")
	DateStrptime._z = True
except ValueError:
	DateStrptime._z = False

class DatePatternRegex(DateStrptime):
	_reEscape = r"([\\.^$*+?\(\){}\[\]|])"
	_patternRE = r"%(%|[aAbBdfHIjmMpSUwWyYz])"
	_patternName = {
		'a': "DAY", 'A': "DAYNAME", 'b': "MON", 'B': "MONTH", 'd': "Day",
		'H': "24hour", 'I': "12hour", 'j': "Yearday", 'm': "Month",
		'M': "Minute", 'p': "AMPM", 'S': "Second", 'U': "Yearweek",
		'w': "Weekday", 'W': "Yearweek", 'y': 'Year2', 'Y': "Year", '%': "%",
		'z': "Zone offset", 'f': "Microseconds" }
	_patternRegex = {
		'a': r"\w{3}", 'A': r"\w+", 'b': r"\w{3}", 'B': r"\w+",
		'd': r"(?:3[0-1]|[1-2]\d|[ 0]?\d)",
		'f': r"(?P<_f>\d{1,6})", 'H': r"(?:2[0-3]|1\d|[ 0]?\d)",
		'I': r"(?:1[0-2]|[ 0]?\d)",
		'j': r"(?:36[0-6]3[0-5]\d|[1-2]\d\d|[ 0]?\d\d|[ 0]{0,2}\d)",
		'm': r"(?:1[0-2]|[ 0]?[1-9])", 'M': r"[0-5]\d", 'p': r"[AP]M",
		'S': r"(?:6[01]|[0-5]\d)", 'U': r"(?:5[0-3]|[1-4]\d|[ 0]?\d)",
		'w': r"[0-6]", 'W': r"(?:5[0-3]|[ 0]?\d)", 'y': r"\d{2}",
		'Y': r"\d{4}",
		'z': r"(?P<_z>[+-]\d{4})", '%': "%"}

	def __init__(self, pattern=None, **kwargs):
		DateStrptime.__init__(self)
		if pattern:
			self.setPattern(pattern, **kwargs)

	def setPattern(self, pattern, anchor=False, **kwargs):
		DateStrptime.setPattern(self, pattern.strip())

		name = re.sub(self._patternRE, r'%(\1)s', pattern) % self._patternName
		DateStrptime.setName(self, name)

		# Custom escape as don't want to escape "%"
		pattern = re.sub(self._reEscape, r'\\\1', pattern)
		regex = re.sub(
			self._patternRE, r'%(\1)s', pattern) % self._patternRegex
		if anchor:
			regex = r"^" + regex
		DateStrptime.setRegex(self, regex, **kwargs)

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
		dateMatch = self.matchDate(line)
		if dateMatch:
			# extract part of format which represents seconds since epoch
			value = dateMatch.group()
			seconds_since_epoch = value[2:17]
			# convert seconds from HEX into local time stamp
			return (int(seconds_since_epoch, 16), dateMatch)
		return None


class DateISO8601(DateTemplate):

	def __init__(self):
		DateTemplate.__init__(self)
		self.setRegex(iso8601.ISO8601_REGEX_RAW)
	
	def getDate(self, line):
		dateMatch = self.matchDate(line)
		if dateMatch:
			# Parses the date.
			value = dateMatch.group()
			return (calendar.timegm(iso8601.parse_date(value).utctimetuple()), dateMatch)
		return None

