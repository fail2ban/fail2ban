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

import time, logging

from datetemplate import DateStrptime, DateTai64n, DateEpoch, DateISO8601
from threading import Lock

# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.filter.datedetector")

class DateDetector:
	
	def __init__(self):
		self.__lock = Lock()
		self.__templates = list()
		self.__known_names = set()

	def _appendTemplate(self, template):
		name = template.getName()
		if name in self.__known_names:
			raise ValueError("There is already a template with name %s" % name)
		self.__known_names.add(name)
		self.__templates.append(template)
	
	def addDefaultTemplate(self):
		self.__lock.acquire()
		try:
			# standard
			template = DateStrptime()
			template.setName("MONTH Day Hour:Minute:Second")
			template.setRegex("\S{3}\s{1,2}\d{1,2} \d{2}:\d{2}:\d{2}")
			template.setPattern("%b %d %H:%M:%S")
			self._appendTemplate(template)
			# asctime
			template = DateStrptime()
			template.setName("WEEKDAY MONTH Day Hour:Minute:Second Year")
			template.setRegex("\S{3} \S{3}\s{1,2}\d{1,2} \d{2}:\d{2}:\d{2} \d{4}")
			template.setPattern("%a %b %d %H:%M:%S %Y")
			self._appendTemplate(template)
			# asctime without year
			template = DateStrptime()
			template.setName("WEEKDAY MONTH Day Hour:Minute:Second")
			template.setRegex("\S{3} \S{3}\s{1,2}\d{1,2} \d{2}:\d{2}:\d{2}")
			template.setPattern("%a %b %d %H:%M:%S")
			self._appendTemplate(template)
			# simple date
			template = DateStrptime()
			template.setName("Year/Month/Day Hour:Minute:Second")
			template.setRegex("\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}")
			template.setPattern("%Y/%m/%d %H:%M:%S")
			self._appendTemplate(template)
			# simple date too (from x11vnc)
			template = DateStrptime()
			template.setName("Day/Month/Year Hour:Minute:Second")
			template.setRegex("\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}")
			template.setPattern("%d/%m/%Y %H:%M:%S")
			self._appendTemplate(template)
			# previous one but with year given by 2 digits
			# (See http://bugs.debian.org/537610)
			template = DateStrptime()
			template.setName("Day/Month/Year2 Hour:Minute:Second")
			template.setRegex("\d{2}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}")
			template.setPattern("%d/%m/%y %H:%M:%S")
			self._appendTemplate(template)
			# Apache format [31/Oct/2006:09:22:55 -0000]
			template = DateStrptime()
			template.setName("Day/MONTH/Year:Hour:Minute:Second")
			template.setRegex("\d{2}/\S{3}/\d{4}:\d{2}:\d{2}:\d{2}")
			template.setPattern("%d/%b/%Y:%H:%M:%S")
			self._appendTemplate(template)
			# CPanel 05/20/2008:01:57:39
			template = DateStrptime()
			template.setName("Month/Day/Year:Hour:Minute:Second")
			template.setRegex("\d{2}/\d{2}/\d{4}:\d{2}:\d{2}:\d{2}")
			template.setPattern("%m/%d/%Y:%H:%M:%S")
			self._appendTemplate(template)
			# Exim 2006-12-21 06:43:20
			template = DateStrptime()
			template.setName("Year-Month-Day Hour:Minute:Second")
			template.setRegex("\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")
			template.setPattern("%Y-%m-%d %H:%M:%S")
			self._appendTemplate(template)
			# custom for syslog-ng 2006.12.21 06:43:20
			template = DateStrptime()
			template.setName("Year.Month.Day Hour:Minute:Second")
			template.setRegex("\d{4}.\d{2}.\d{2} \d{2}:\d{2}:\d{2}")
			template.setPattern("%Y.%m.%d %H:%M:%S")
			self._appendTemplate(template)
			# named 26-Jul-2007 15:20:52.252 
			template = DateStrptime()
			template.setName("Day-MONTH-Year Hour:Minute:Second[.Millisecond]")
			template.setRegex("\d{2}-\S{3}-\d{4} \d{2}:\d{2}:\d{2}")
			template.setPattern("%d-%b-%Y %H:%M:%S")
			self._appendTemplate(template)
			# 17-07-2008 17:23:25
			template = DateStrptime()
			template.setName("Day-Month-Year Hour:Minute:Second")
			template.setRegex("\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2}")
			template.setPattern("%d-%m-%Y %H:%M:%S")
			self._appendTemplate(template)
			# 01-27-2012 16:22:44.252
			template = DateStrptime()
			template.setName("Month-Day-Year Hour:Minute:Second[.Millisecond]")
			template.setRegex("\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2}")
			template.setPattern("%m-%d-%Y %H:%M:%S")
			self._appendTemplate(template)
			# TAI64N
			template = DateTai64n()
			template.setName("TAI64N")
			self._appendTemplate(template)
			# Epoch
			template = DateEpoch()
			template.setName("Epoch")
			self._appendTemplate(template)
			# ISO 8601
			template = DateISO8601()
			template.setName("ISO 8601")
			self._appendTemplate(template)
			# Only time information in the log
			template = DateStrptime()
			template.setName("Hour:Minute:Second")
			template.setRegex("^\d{2}:\d{2}:\d{2}")
			template.setPattern("%H:%M:%S")
			self._appendTemplate(template)
			# <09/16/08@05:03:30>
			template = DateStrptime()
			template.setName("<Month/Day/Year@Hour:Minute:Second>")
			template.setRegex("^<\d{2}/\d{2}/\d{2}@\d{2}:\d{2}:\d{2}>")
			template.setPattern("<%m/%d/%y@%H:%M:%S>")
			self._appendTemplate(template)
		finally:
			self.__lock.release()
	
	def getTemplates(self):
		return self.__templates
	
	def matchTime(self, line):
		self.__lock.acquire()
		try:
			for template in self.__templates:
				match = template.matchDate(line)
				if not match is None:
					logSys.debug("Matched time template %s" % template.getName())
					return match
			return None
		finally:
			self.__lock.release()

	def getTime(self, line):
		self.__lock.acquire()
		try:
			for template in self.__templates:
				try:
					date = template.getDate(line)
					if date is None:
						continue
					logSys.debug("Got time using template %s" % template.getName())
					return date
				except ValueError:
					pass
			return None
		finally:
			self.__lock.release()

	def getUnixTime(self, line):
		date = self.getTime(line)
		if date == None:
			return None
		else:
			return time.mktime(date)

	##
	# Sort the template lists using the hits score. This method is not called
	# in this object and thus should be called from time to time.
	
	def sortTemplate(self):
		self.__lock.acquire()
		try:
			logSys.debug("Sorting the template list")
			self.__templates.sort(lambda x, y: cmp(x.getHits(), y.getHits()), reverse=True)
			t = self.__templates[0]
			logSys.debug("Winning template: %s with %d hits" % (t.getName(), t.getHits()))
		finally:
			self.__lock.release()
