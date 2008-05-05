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
# $Revision: 645 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 645 $"
__date__ = "$Date: 2008-01-16 23:55:04 +0100 (Wed, 16 Jan 2008) $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import time

from template import Template, Templates
from mytime import MyTime

class TimeTemplate(Template):
	
	def __init__(self):
		Template.__init__(self, Template.TEMPLATE_TIME, "<TIME>")
	
	def setRegex(self, regex):
		Template.setRegex(self, "(?P<%s>%s)" % (self.getName(), regex))
	
	def getTime(self, line):
		raise Exception("getTime() is abstract")


class TimeEpoch(TimeTemplate):
	
	def __init__(self):
		TimeTemplate.__init__(self)
		# We already know the format for TAI64N
		self.setRegex("\d{10}(\.\d{6})?")
	
	def getTime(self, line):
		# extract part of format which represents seconds since epoch
		return list(time.localtime(float(line)))


##
# Use strptime() to parse a date. Our current locale is the 'C'
# one because we do not set the locale explicitly. This is POSIX
# standard.

class TimeStrptime(TimeTemplate):
	
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
		TimeTemplate.__init__(self)
		self.__pattern = ""
	
	def setPattern(self, pattern):
		self.__pattern = pattern.strip()
		
	def getPattern(self):
		return self.__pattern
	
	#@staticmethod
	def convertLocale(date):
		for t in TimeStrptime.TABLE:
			for m in TimeStrptime.TABLE[t]:
				if date.find(m) >= 0:
					return date.replace(m, t)
		return date
	convertLocale = staticmethod(convertLocale)
	
	def getTime(self, line):
		try:
			# Try first with 'C' locale
			date = list(time.strptime(line, self.getPattern()))
		except ValueError:
			# Try to convert date string to 'C' locale
			conv = self.convertLocale(line)
			try:
				date = list(time.strptime(conv, self.getPattern()))
			except ValueError:
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
		return date


class TimeTai64n(TimeTemplate):
	
	def __init__(self):
		TimeTemplate.__init__(self)
		# We already know the format for TAI64N
		self.setRegex("@[0-9a-f]{24}")
	
	def getTime(self, line):
		# extract part of format which represents seconds since epoch
		seconds_since_epoch = line[2:17]
		return list(time.gmtime(int(seconds_since_epoch, 16)))


class TimeTemplates(Templates):
	
	def __init__(self):
		Templates.__init__(self)
		# standard
		template = TimeStrptime()
		template.setDescription("Month Day Hour:Minute:Second")
		template.setRegex("\S{3}\s{1,2}\d{1,2} \d{2}:\d{2}:\d{2}")
		template.setPattern("%b %d %H:%M:%S")
		self.templates.append(template)
		# asctime
		template = TimeStrptime()
		template.setDescription("Weekday Month Day Hour:Minute:Second Year")
		template.setRegex("\S{3} \S{3}\s{1,2}\d{1,2} \d{2}:\d{2}:\d{2} \d{4}")
		template.setPattern("%a %b %d %H:%M:%S %Y")
		self.templates.append(template)
		# asctime without year
		template = TimeStrptime()
		template.setDescription("Weekday Month Day Hour:Minute:Second")
		template.setRegex("\S{3} \S{3}\s{1,2}\d{1,2} \d{2}:\d{2}:\d{2}")
		template.setPattern("%a %b %d %H:%M:%S")
		self.templates.append(template)
		# simple date
		template = TimeStrptime()
		template.setDescription("Year/Month/Day Hour:Minute:Second")
		template.setRegex("\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}")
		template.setPattern("%Y/%m/%d %H:%M:%S")
		self.templates.append(template)
		# simple date too (from x11vnc)
		template = TimeStrptime()
		template.setDescription("Day/Month/Year Hour:Minute:Second")
		template.setRegex("\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}")
		template.setPattern("%d/%m/%Y %H:%M:%S")
		self.templates.append(template)
		# Apache format [31/Oct/2006:09:22:55 -0000]
		template = TimeStrptime()
		template.setDescription("Day/Month/Year:Hour:Minute:Second")
		template.setRegex("\d{2}/\S{3}/\d{4}:\d{2}:\d{2}:\d{2}")
		template.setPattern("%d/%b/%Y:%H:%M:%S")
		self.templates.append(template)
		# Exim 2006-12-21 06:43:20
		template = TimeStrptime()
		template.setDescription("Year-Month-Day Hour:Minute:Second")
		template.setRegex("\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")
		template.setPattern("%Y-%m-%d %H:%M:%S")
		self.templates.append(template)
		# named 26-Jul-2007 15:20:52.252 
		template = TimeStrptime()
		template.setDescription("Day-Month-Year Hour:Minute:Second[.Millisecond]")
		template.setRegex("\d{2}-\S{3}-\d{4} \d{2}:\d{2}:\d{2}")
		template.setPattern("%d-%b-%Y %H:%M:%S")
		self.templates.append(template)
		# TAI64N
		template = TimeTai64n()
		template.setDescription("TAI64N")
		self.templates.append(template)
		# Epoch
		template = TimeEpoch()
		template.setDescription("Epoch")
		self.templates.append(template)
