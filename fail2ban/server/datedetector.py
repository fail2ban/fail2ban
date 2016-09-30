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

import copy
import time

from threading import Lock

from .datetemplate import DatePatternRegex, DateTai64n, DateEpoch
from ..helpers import getLogger

# Gets the instance of the logger.
logSys = getLogger(__name__)

logLevel = 6


class DateDetectorCache(object):
	"""Implements the caching of the default templates list.
	"""
	def __init__(self):
		self.__lock = Lock()
		self.__templates = list()

	@property
	def templates(self):
		"""List of template instances managed by the detector.
		"""
		with self.__lock:
			if self.__templates:
				return self.__templates
			self._addDefaultTemplate()
			return self.__templates

	def _cacheTemplate(self, template):
		"""Cache Fail2Ban's default template.

		"""
		if isinstance(template, str):
			# exact given template with word benin-end boundary:
			template = DatePatternRegex(template)
		# additional template, that prefers datetime at start of a line (safety+performance feature):
		if 0 and hasattr(template, 'regex'):
			template2 = copy.copy(template)
			regex = getattr(template, 'pattern', template.regex)
			template2.setRegex(regex, wordBegin='start', wordEnd=True)
			if template2.name != template.name:
				# increase weight of such templates, because they should be always
				# preferred in template sorting process (bubble up):
				template2.weight = 100
				self.__templates.append(template2)
		# add template:
		self.__templates.append(template)

	def _addDefaultTemplate(self):
		"""Add resp. cache Fail2Ban's default set of date templates.
		"""
		# ISO 8601, simple date, optional subsecond and timezone:
		# 2005-01-23T21:59:59.981746, 2005-01-23 21:59:59
		# simple date: 2005/01/23 21:59:59 
		# custom for syslog-ng 2006.12.21 06:43:20
		self._cacheTemplate("%ExY(?P<_sep>[-/.])%m(?P=_sep)%d[T ]%H:%M:%S(?:[.,]%f)?(?:\s*%z)?")
		# 20050123T215959, 20050123 215959
		self._cacheTemplate("%ExY%Exm%Exd[T ]%ExH%ExM%ExS(?:[.,]%f)?(?:\s*%z)?")
		# asctime with optional day, subsecond and/or year:
		# Sun Jan 23 21:59:59.011 2005 
		# prefixed with optional time zone (monit):
		# PDT Apr 16 21:05:29
		self._cacheTemplate("(?:%z )?(?:%a )?%b %d %H:%M:%S(?:\.%f)?(?: %ExY)?")
		# asctime with optional day, subsecond and/or year coming after day
		# http://bugs.debian.org/798923
		# Sun Jan 23 2005 21:59:59.011
		self._cacheTemplate("(?:%a )?%b %d %ExY %H:%M:%S(?:\.%f)?")
		# simple date too (from x11vnc): 23/01/2005 21:59:59 
		# and with optional year given by 2 digits: 23/01/05 21:59:59 
		# (See http://bugs.debian.org/537610)
		# 17-07-2008 17:23:25
		self._cacheTemplate("%d(?P<_sep>[-/])%m(?P=_sep)(?:%ExY|%Exy) %H:%M:%S")
		# Apache format optional time zone:
		# [31/Oct/2006:09:22:55 -0000]
		# 26-Jul-2007 15:20:52
		# named 26-Jul-2007 15:20:52.252
		# roundcube 26-Jul-2007 15:20:52 +0200
		self._cacheTemplate("%d(?P<_sep>[-/])%b(?P=_sep)%ExY[ :]?%H:%M:%S(?:\.%f)?(?: %z)?")
		# CPanel 05/20/2008:01:57:39
		self._cacheTemplate("%m/%d/%ExY:%H:%M:%S")
		# 01-27-2012 16:22:44.252
		# subseconds explicit to avoid possible %m<->%d confusion
		# with previous ("%d-%m-%ExY %H:%M:%S" by "%d(?P<_sep>[-/])%m(?P=_sep)(?:%ExY|%Exy) %H:%M:%S")
		self._cacheTemplate("%m-%d-%ExY %H:%M:%S(?:\.%f)?")
		# TAI64N
		self._cacheTemplate(DateTai64n())
		# Epoch
		self._cacheTemplate(DateEpoch())
		# Only time information in the log
		self._cacheTemplate("^%H:%M:%S")
		# <09/16/08@05:03:30>
		self._cacheTemplate("^<%m/%d/%Exy@%H:%M:%S>")
		# MySQL: 130322 11:46:11
		self._cacheTemplate("%Exy%Exm%Exd  ?%H:%M:%S")
		# Apache Tomcat
		self._cacheTemplate("%b %d, %ExY %I:%M:%S %p")
		# ASSP: Apr-27-13 02:33:06
		self._cacheTemplate("^%b-%d-%Exy %H:%M:%S")


class DateDetectorTemplate(object):
	"""Used for "shallow copy" of the template object.

	Prevents collectively usage of hits/lastUsed in cached templates
	"""
	__slots__ = ('template', 'hits', 'lastUsed', 'distance')
	def __init__(self, template):
		self.template = template
		self.hits = 0
		self.lastUsed = 0
		# the last distance to date-match within the log file:
		self.distance = 0x7fffffff

	def __getattr__(self, name):
		""" Returns attribute of template (called for parameters not in slots)
		"""
		return getattr(self.template, name)


class DateDetector(object):
	"""Manages one or more date templates to find a date within a log line.

	Attributes
	----------
	templates
	"""
	_defCache = DateDetectorCache()

	def __init__(self):
		self.__lock = Lock()
		self.__templates = list()
		self.__known_names = set()
		# time the template was long unused (currently 300 == 5m):
		self.__unusedTime = 300
		# first free place:
		self.__firstUnused = 0

	def _appendTemplate(self, template):
		name = template.name
		if name in self.__known_names:
			raise ValueError(
				"There is already a template with name %s" % name)
		self.__known_names.add(name)
		self.__templates.append(DateDetectorTemplate(template))

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
		with self.__lock:
			for template in DateDetector._defCache.templates:
				self._appendTemplate(template)

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
		re.MatchObject, DateTemplate
			The regex match returned from the first successfully matched
			template.
		"""
		match = None
		i = 0
		found = None, 0x7fffffff, -1
		with self.__lock:
			for ddtempl in self.__templates:
				template = ddtempl.template
				match = template.matchDate(line)
				if match is not None:
					distance = max(1, match.start() + 1)
					if logSys.getEffectiveLevel() <= logLevel:
						logSys.log(logLevel, "  matched time template #%r (at %r <= %r) %s",
							i, distance, ddtempl.distance, template.name)
					## [grave] if distance changed, possible date-match was found somewhere 
					## in body of message, so save this template, and search further:
					if distance > ddtempl.distance and len(self.__templates) > 1:
						if logSys.getEffectiveLevel() <= logLevel:
							logSys.log(logLevel, "  ** distance collision - pattern change, reserve")
						## shortest of both:
						if distance < found[1]:
							found = match, distance, i
						## search further:
						match = None
						i += 1
						continue
					## winner - stop search:
					break
				i += 1
			# check other template was found (use this one with shortest distance):
			if match is None and found[0]:
				match, distance, i = found
				ddtempl = self.__templates[i]
				template = ddtempl.template
			# we've winner, incr hits, set distance, usage, reorder, etc:
			if match is not None:
				ddtempl.hits += 1
				ddtempl.distance = distance
				ddtempl.lastUsed = time.time()
				if self.__firstUnused == i:
					self.__firstUnused += 1
				# if not first - try to reorder current template (bubble up), they will be not sorted anymore:
				if i:
					logSys.log(logLevel, "  -> reorder template #%r, hits: %r", i, ddtempl.hits)
					self._reorderTemplate(i)
				# return tuple with match and template reference used for parsing:
				return (match, template)

		# not found:
		return (None, None)

	def getTime(self, line, timeMatch=None):
		"""Attempts to return the date on a log line using templates.

		This uses the templates' `getDate` method in an attempt to find
		a date. 
		For the faster usage, always specify a parameter timeMatch (the previous tuple result
		of the matchTime), then this will work without locking and without cycle over templates.

		Parameters
		----------
		line : str
			Line which is searched by the date templates.

		Returns
		-------
		float
			The Unix timestamp returned from the first successfully matched
			template or None if not found.
		"""
		# search match for all specified templates:
		if timeMatch is None:
			timeMatch = self.matchTime(line)
		# convert:
		template = timeMatch[1]
		if template is not None:
			try:
				date = template.getDate(line, timeMatch[0])
				if date is not None:
					if logSys.getEffectiveLevel() <= logLevel:
						logSys.log(logLevel, "  got time %f for %r using template %s",
							date[0], date[1].group(), template.name)
					return date
			except ValueError:
				return None

	def _reorderTemplate(self, num):
		"""Reorder template (bubble up) in template list if hits grows enough.

		Parameters
		----------
		num : int
			Index of template should be moved.
		"""
		if num:
			templates = self.__templates
			ddtempl = templates[num]
		  ## current hits and time the template was long unused:
			untime = ddtempl.lastUsed - self.__unusedTime
			weight = ddtempl.hits * ddtempl.template.weight / ddtempl.distance
			## try to move faster (first if unused available, or half of part to current template position):
			pos = self.__firstUnused if self.__firstUnused < num else num // 2
			pweight = templates[pos].hits * templates[pos].template.weight / templates[pos].distance
			## don't move too often (multiline logs resp. log's with different date patterns),
			## if template not used too long, replace it also :
			logSys.log(logLevel, "  -> compare template #%r & #%r, weight %r > %r", num, pos, weight, pweight)
			if not pweight or weight > pweight + 5 or templates[pos].lastUsed < untime:
				## if not larger (and target position recently used) - move slow (exact 1 position):
				if weight <= pweight and templates[pos].lastUsed > untime:
					pos = num-1
					## if still smaller and template at position used, don't move:
					pweight = templates[pos].hits * templates[pos].template.weight / templates[pos].distance
					logSys.log(logLevel, "  -> compare template #%r & #%r, weight %r > %r", num, pos, weight, pweight)
					if weight < pweight and templates[pos].lastUsed > untime:
						return
				templates[pos], templates[num] = ddtempl, templates[pos]
				logSys.log(logLevel, "  -> moved template #%r -> #%r", num, pos)
				## correct first unused:
				if pos == self.__firstUnused:
					self.__firstUnused += 1
