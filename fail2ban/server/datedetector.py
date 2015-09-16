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

__author__ = "Cyril Jaquier and Fail2Ban Contributors"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

from threading import Lock

from .datetemplate import DatePatternRegex, DateTai64n, DateEpoch
from ..helpers import getLogger

# Gets the instance of the logger.
logSys = getLogger(__name__)


class DateDetector(object):
	"""Manages one or more date templates to find a date within a log line.

	Attributes
	----------
	templates
	"""

	def __init__(self):
		self.__lock = Lock()
		self.__templates = list()
		self.__known_names = set()

	def _appendTemplate(self, template):
		name = template.name
		if name in self.__known_names:
			raise ValueError(
				"There is already a template with name %s" % name)
		self.__known_names.add(name)
		self.__templates.append(template)

	def appendTemplate(self, template):
		"""Add a date template to manage and use in search of dates.

		Parameters
		----------
		template : DateTemplate or str
			Can be either a `DateTemplate` instance, or a string which will
			be used as the pattern for the `DatePatternRegex` template. The
			template will then be added to the detector.

		Raises
		------
		ValueError
			If a template already exists with the same name.
		"""
		if isinstance(template, str):
			template = DatePatternRegex(template)
		self._appendTemplate(template)

	def addDefaultTemplate(self):
		"""Add Fail2Ban's default set of date templates.
		"""
		self.__lock.acquire()
		try:
			# asctime with optional day, subsecond and/or year:
			# Sun Jan 23 21:59:59.011 2005 
			self.appendTemplate("(?:%a )?%b %d %H:%M:%S(?:\.%f)?(?: %Y)?")
			# asctime with optional day, subsecond and/or year coming after day
			# http://bugs.debian.org/798923
			# Sun Jan 23 2005 21:59:59.011
			self.appendTemplate("(?:%a )?%b %d %Y %H:%M:%S(?:\.%f)?")
			# simple date, optional subsecond (proftpd):
			# 2005-01-23 21:59:59 
			# simple date: 2005/01/23 21:59:59 
			# custom for syslog-ng 2006.12.21 06:43:20
			self.appendTemplate("%Y(?P<_sep>[-/.])%m(?P=_sep)%d %H:%M:%S(?:,%f)?")
			# simple date too (from x11vnc): 23/01/2005 21:59:59 
			# and with optional year given by 2 digits: 23/01/05 21:59:59 
			# (See http://bugs.debian.org/537610)
			# 17-07-2008 17:23:25
			self.appendTemplate("%d(?P<_sep>[-/])%m(?P=_sep)(?:%Y|%y) %H:%M:%S")
			# Apache format optional time zone:
			# [31/Oct/2006:09:22:55 -0000]
			# 26-Jul-2007 15:20:52
			self.appendTemplate("%d(?P<_sep>[-/])%b(?P=_sep)%Y[ :]?%H:%M:%S(?:\.%f)?(?: %z)?")
			# CPanel 05/20/2008:01:57:39
			self.appendTemplate("%m/%d/%Y:%H:%M:%S")
			# named 26-Jul-2007 15:20:52.252 
			# roundcube 26-Jul-2007 15:20:52 +0200
			# 01-27-2012 16:22:44.252
			# subseconds explicit to avoid possible %m<->%d confusion
			# with previous
			self.appendTemplate("%m-%d-%Y %H:%M:%S\.%f")
			# TAI64N
			template = DateTai64n()
			template.name = "TAI64N"
			self.appendTemplate(template)
			# Epoch
			template = DateEpoch()
			template.name = "Epoch"
			self.appendTemplate(template)
			# ISO 8601
			self.appendTemplate("%Y-%m-%d[T ]%H:%M:%S(?:\.%f)?(?:%z)?")
			# Only time information in the log
			self.appendTemplate("^%H:%M:%S")
			# <09/16/08@05:03:30>
			self.appendTemplate("^<%m/%d/%y@%H:%M:%S>")
			# MySQL: 130322 11:46:11
			self.appendTemplate("^%y%m%d  ?%H:%M:%S")
			# Apache Tomcat
			self.appendTemplate("%b %d, %Y %I:%M:%S %p")
			# ASSP: Apr-27-13 02:33:06
			self.appendTemplate("^%b-%d-%y %H:%M:%S")
		finally:
			self.__lock.release()

	@property
	def templates(self):
		"""List of template instances managed by the detector.
		"""
		return self.__templates

	def matchTime(self, line):
		"""Attempts to find date on a log line using templates.

		This uses the templates' `matchDate` method in an attempt to find
		a date. It also increments the match hit count for the winning
		template.

		Parameters
		----------
		line : str
			Line which is searched by the date templates.

		Returns
		-------
		re.MatchObject
			The regex match returned from the first successfully matched
			template.
		"""
		self.__lock.acquire()
		try:
			for template in self.__templates:
				match = template.matchDate(line)
				if not match is None:
					logSys.debug("Matched time template %s" % template.name)
					template.hits += 1
					return match
			return None
		finally:
			self.__lock.release()

	def getTime(self, line):
		"""Attempts to return the date on a log line using templates.

		This uses the templates' `getDate` method in an attempt to find
		a date.

		Parameters
		----------
		line : str
			Line which is searched by the date templates.

		Returns
		-------
		float
			The Unix timestamp returned from the first successfully matched
			template.
		"""
		self.__lock.acquire()
		try:
			for template in self.__templates:
				try:
					date = template.getDate(line)
					if date is None:
						continue
					logSys.debug("Got time %f for \"%r\" using template %s" %
						(date[0], date[1].group(), template.name))
					return date
				except ValueError:
					pass
			return None
		finally:
			self.__lock.release()

	def sortTemplate(self):
		"""Sort the date templates by number of hits

		Sort the template lists using the hits score. This method is not
		called in this object and thus should be called from time to time.
		This ensures the most commonly matched templates are checked first,
		improving performance of matchTime and getTime.
		"""
		self.__lock.acquire()
		try:
			logSys.debug("Sorting the template list")
			self.__templates.sort(key=lambda x: x.hits, reverse=True)
			t = self.__templates[0]
			logSys.debug("Winning template: %s with %d hits" % (t.name, t.hits))
		finally:
			self.__lock.release()
