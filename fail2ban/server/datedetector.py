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

from .datetemplate import re, DateTemplate, DatePatternRegex, DateTai64n, DateEpoch
from ..helpers import getLogger

# Gets the instance of the logger.
logSys = getLogger(__name__)

logLevel = 6

RE_DATE_PREMATCH = re.compile("\{DATE\}", re.IGNORECASE)


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
		if self.__templates:
			return self.__templates
		with self.__lock:
			if self.__templates:
				return self.__templates
			self._addDefaultTemplate()
			return self.__templates

	def _cacheTemplate(self, template, lineBeginOnly=False):
		"""Cache Fail2Ban's default template.

		"""
		if isinstance(template, str):
			# exact given template with word benin-end boundary:
			if not lineBeginOnly:
				template = DatePatternRegex(template)
			else:
				template = DatePatternRegex(template, wordBegin='start')
		# additional template, that prefers datetime at start of a line (safety+performance feature):
		if not lineBeginOnly and hasattr(template, 'regex'):
			template2 = copy.copy(template)
			regex = getattr(template, 'pattern', template.regex)
			template2.setRegex(regex, wordBegin='start', wordEnd=True)
			if template2.name != template.name:
				# increase weight of such templates, because they should be always
				# preferred in template sorting process (bubble up):
				template2.weight = 100.0
				self.__tmpcache[0].append(template2)
		# add template:
		self.__tmpcache[1].append(template)

	def _addDefaultTemplate(self):
		"""Add resp. cache Fail2Ban's default set of date templates.
		"""
		self.__tmpcache = [], []
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
		self._cacheTemplate("(?:%Z )?(?:%a )?%b %d %H:%M:%S(?:\.%f)?(?: %ExY)?")
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
		self._cacheTemplate(DateEpoch(lineBeginOnly=True), lineBeginOnly=True)
		self._cacheTemplate(DateEpoch())
		# Only time information in the log
		self._cacheTemplate("%H:%M:%S", lineBeginOnly=True)
		# <09/16/08@05:03:30>
		self._cacheTemplate("<%m/%d/%Exy@%H:%M:%S>", lineBeginOnly=True)
		# MySQL: 130322 11:46:11
		self._cacheTemplate("%Exy%Exm%Exd  ?%H:%M:%S")
		# Apache Tomcat
		self._cacheTemplate("%b %d, %ExY %I:%M:%S %p")
		# ASSP: Apr-27-13 02:33:06
		self._cacheTemplate("%b-%d-%Exy %H:%M:%S", lineBeginOnly=True)
		self.__templates = self.__tmpcache[0] + self.__tmpcache[1]
		del self.__tmpcache


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

	@property
	def weight(self):
		return self.hits * self.template.weight / max(1, self.distance)

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
		self.__templates = list()
		self.__known_names = set()
		# time the template was long unused (currently 300 == 5m):
		self.__unusedTime = 300
		# last known distance (bypass one char collision) and end position:
		self.__lastPos = 1, None
		self.__lastEndPos = 0x7fffffff, None
		self.__lastTemplIdx = 0x7fffffff
		# first free place:
		self.__firstUnused = 0
		# pre-match pattern:
		self.__preMatch = None

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

	def addDefaultTemplate(self, filterTemplate=None, preMatch=None):
		"""Add Fail2Ban's default set of date templates.
		"""
		for template in DateDetector._defCache.templates:
			# filter if specified:
			if filterTemplate is not None and not filterTemplate(template): continue
			# if exact pattern available - create copy of template, contains replaced {DATE} with default regex:
			if preMatch is not None:
				regex = getattr(template, 'pattern', template.regex)
				template = copy.copy(template)
				template.setRegex(RE_DATE_PREMATCH.sub(regex, preMatch))
			# append date detector template:
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
		#logSys.log(logLevel, "try to match time for line: %.120s", line)
		match = None
		# first try to use last template with same start/end position:
		i = self.__lastTemplIdx
		if i < len(self.__templates):
			ddtempl = self.__templates[i]
			template = ddtempl.template
			distance, endpos = self.__lastPos[0], self.__lastEndPos[0]
			if logSys.getEffectiveLevel() <= logLevel-1:
				logSys.log(logLevel-1, "  try to match last template #%02i (from %r to %r): ...%r==%r %s %r==%r...",
					i, distance, endpos, 
					line[distance-1:distance], self.__lastPos[1],
					line[distance:endpos],
					line[endpos:endpos+1], self.__lastEndPos[1])
			# check same boundaries left/right, otherwise possible collision/pattern switch:
			if (line[distance-1:distance] == self.__lastPos[1] and 
					line[endpos:endpos+1] == self.__lastEndPos[1]
			):
				match = template.matchDate(line, distance, endpos)
				if match:
					distance = match.start()
					endpos = match.end()
					# if different position, possible collision/pattern switch:
					if distance == self.__lastPos[0] and endpos == self.__lastEndPos[0]:
						logSys.log(logLevel, "  matched last time template #%02i", i)
					else:
						logSys.log(logLevel, "  ** last pattern collision - pattern change, search ...")
						match = None
		# search template and better match:
		if not match:
			self.__lastTemplIdx = 0x7fffffff
			logSys.log(logLevel, " search template ...")
			found = None, 0x7fffffff, -1
			i = 0
			for ddtempl in self.__templates:
				template = ddtempl.template
				match = template.matchDate(line)
				if match:
					distance = match.start()
					endpos = match.end()
					if logSys.getEffectiveLevel() <= logLevel:
						logSys.log(logLevel, "  matched time template #%02i (at %r <= %r, %r) %s",
							i, distance, ddtempl.distance, self.__lastPos[0], template.name)
					## if line-begin/end anchored - stop searching:
					if template.flags & (DateTemplate.LINE_BEGIN|DateTemplate.LINE_END):
						break
					## [grave] if distance changed, possible date-match was found somewhere 
					## in body of message, so save this template, and search further:
					if (
						(distance > ddtempl.distance or distance > self.__lastPos[0]) and
						len(self.__templates) > 1
					):
						logSys.log(logLevel, "  ** distance collision - pattern change, reserve")
						## shortest of both:
						if distance < found[1]:
							found = match, distance, endpos, i
						## search further:
						match = None
						i += 1
						continue
					## winner - stop search:
					break
				i += 1
			# check other template was found (use this one with shortest distance):
			if not match and found[0]:
				match, distance, endpos, i = found
				logSys.log(logLevel, "  use best time template #%02i", i)
				ddtempl = self.__templates[i]
				template = ddtempl.template
		# we've winner, incr hits, set distance, usage, reorder, etc:
		if match:
			ddtempl.hits += 1
			ddtempl.lastUsed = time.time()
			ddtempl.distance = distance
			if self.__firstUnused == i:
				self.__firstUnused += 1
			self.__lastPos = distance, line[distance-1:distance]
			self.__lastEndPos = endpos, line[endpos:endpos+1]
			# if not first - try to reorder current template (bubble up), they will be not sorted anymore:
			if i:
				i = self._reorderTemplate(i)
			self.__lastTemplIdx = i
			# return tuple with match and template reference used for parsing:
			return (match, template)

		# not found:
		logSys.log(logLevel, " no template.")
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
				pass
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
			if logSys.getEffectiveLevel() <= logLevel:
				logSys.log(logLevel, "  -> reorder template #%02i, hits: %r", num, ddtempl.hits)
		  ## current hits and time the template was long unused:
			untime = ddtempl.lastUsed - self.__unusedTime
			weight = ddtempl.weight
			## try to move faster (first if unused available, or half of part to current template position):
			pos = self.__firstUnused if self.__firstUnused < num else num // 2
			pweight = templates[pos].weight
			## don't move too often (multiline logs resp. log's with different date patterns),
			## if template not used too long, replace it also :
			if logSys.getEffectiveLevel() <= logLevel:
				logSys.log(logLevel, "  -> compare template #%02i & #%02i, weight %.3f > %.3f, hits %r > %r",
					num, pos, weight, pweight, ddtempl.hits, templates[pos].hits)
			if not pweight or weight > pweight or templates[pos].lastUsed < untime:
				## if not larger (and target position recently used) - move slow (exact 1 position):
				if weight <= pweight and templates[pos].lastUsed > untime:
					pos = num-1
					## if still smaller and template at position used, don't move:
					pweight = templates[pos].weight
					if logSys.getEffectiveLevel() <= logLevel:
						logSys.log(logLevel, "  -> compare template #%02i & #%02i, weight %.3f > %.3f, hits %r > %r",
							num, pos, weight, pweight, ddtempl.hits, templates[pos].hits)
					if weight < pweight and templates[pos].lastUsed > untime:
						return
				del templates[num]
				templates[pos:0] = [ddtempl]
				## correct first unused:
				while self.__firstUnused < len(templates) and templates[self.__firstUnused].hits:
					self.__firstUnused += 1
				if logSys.getEffectiveLevel() <= logLevel:
					logSys.log(logLevel, "  -> moved template #%02i -> #%02i", num, pos)
				return pos
		return num
