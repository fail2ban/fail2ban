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
# $Revision: 321 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 321 $"
__date__ = "$Date: 2006-09-04 21:19:58 +0200 (Mon, 04 Sep 2006) $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import re, time

from datetemplate import DateTemplate

##
# Use strptime() to parse a date. Our current locale is the 'C'
# one because we do not set the locale explicitly. This is POSIX
# standard.

class DateStrptime(DateTemplate):
	
	TABLE = dict()
	TABLE["Oct"] = ["Okt"]
	TABLE["Dec"] = ["Dez"]
	
	def __init__(self):
		DateTemplate.__init__(self)
	
	@staticmethod
	def convertLocale(date):
		for t in DateStrptime.TABLE:
			for m in DateStrptime.TABLE[t]:
				if date.find(m) >= 0:
					return date.replace(m, t)
		return date
	
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
				date = list(time.strptime(conv, self.getPattern()))
			if date[0] < 2000:
				# There is probably no year field in the logs
				date[0] = time.gmtime()[0]
				# Bug fix for #1241756
				# If the date is greater than the current time, we suppose
				# that the log is not from this year but from the year before
				if time.mktime(date) > time.time():
					date[0] -= 1
		return date
