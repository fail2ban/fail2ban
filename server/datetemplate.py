# -*- coding: utf8 -*-
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
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

# Author: Cyril Jaquier
# 
# $Revision: 729 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 729 $"
__date__ = "$Date: 2009-02-08 20:50:44 +0100 (Sun, 08 Feb 2009) $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import re, time

from mytime import MyTime
import iso8601

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
	
	def setRegex(self, regex):
		self.__regex = regex.strip()
		self.__cRegex = re.compile(regex)
		
	def getRegex(self):
		return self.__regex
	
	def getHits(self):
		return self.__hits
	
	def matchDate(self, line):
		dateMatch = self.__cRegex.search(line)
		if not dateMatch == None:
			self.__hits += 1
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
			date = list(time.localtime(float(dateMatch.group())))
		return date


##
# Use strptime() to parse a date. Our current locale is the 'C'
# one because we do not set the locale explicitly. This is POSIX
# standard.

class DateStrptime(DateTemplate):
	
	TABLE = dict()
	TABLE["Jan"] = []
	TABLE["Feb"] = [u"Fév"]
	TABLE["Mar"] = [u"Mär"]
	TABLE["Apr"] = ["Avr"]
	TABLE["May"] = ["Mai"]
	TABLE["Jun"] = []
	TABLE["Jul"] = []
	TABLE["Aug"] = ["Aou"]
	TABLE["Sep"] = []
	TABLE["Oct"] = ["Okt"]
	TABLE["Nov"] = []
	TABLE["Dec"] = [u"Déc", "Dez"]
	
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
				except ValueError, e:
					# Try to add the current year to the pattern. Should fix
					# the "Feb 29" issue.
					conv += " %s" % MyTime.gmtime()[0]
					pattern = "%s %%Y" % self.getPattern()
					date = list(time.strptime(conv, pattern))
			if date[0] < 2000:
				# There is probably no year field in the logs
				date[0] = MyTime.gmtime()[0]
				# Bug fix for #1241756
				# If the date is greater than the current time, we suppose
				# that the log is not from this year but from the year before
				if time.mktime(date) > MyTime.time():
					date[0] -= 1
				elif date[1] == 1 and date[2] == 1:
					# If it is Jan 1st, it is either really Jan 1st or there
					# is neither month nor day in the log.
					date[1] = MyTime.gmtime()[1]
					date[2] = MyTime.gmtime()[2]
		return date


class DateTai64n(DateTemplate):
	
	def __init__(self):
		DateTemplate.__init__(self)
		# We already know the format for TAI64N
		self.setRegex("@[0-9a-f]{24}")
	
	def getDate(self, line):
		date = None
		dateMatch = self.matchDate(line)
		if dateMatch:
			# extract part of format which represents seconds since epoch
			value = dateMatch.group()
			seconds_since_epoch = value[2:17]
			date = list(time.gmtime(int(seconds_since_epoch, 16)))
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
			date = list(iso8601.parse_date(value).timetuple())
		return date
