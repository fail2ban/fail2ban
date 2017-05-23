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
from .utils import Utils
from ..helpers import getLogger

# Gets the instance of the logger.
logSys = getLogger(__name__)

logLevel = 6

RE_DATE_PREMATCH = re.compile("\{DATE\}", re.IGNORECASE)
DD_patternCache = Utils.Cache(maxCount=1000, maxTime=60*60)


def _getPatternTemplate(pattern, key=None):
	if key is None:
		key = pattern
		if '%' not in pattern:
			key = pattern.upper()
	template = DD_patternCache.get(key)

	if not template:
		if key in ("EPOCH", "{^LN-BEG}EPOCH", "^EPOCH"):
			template = DateEpoch(lineBeginOnly=(key != "EPOCH"))
		elif key in ("TAI64N", "{^LN-BEG}TAI64N", "^TAI64N"):
			template = DateTai64n(wordBegin=('start' if key != "TAI64N" else False))
		else:
			template = DatePatternRegex(pattern)

	DD_patternCache.set(key, template)
	return template

def _getAnchoredTemplate(template, wrap=lambda s: '{^LN-BEG}' + s):
	# wrap name:
	name = wrap(template.name)
	# try to find in cache (by name):
	template2 = DD_patternCache.get(name)
	if not template2:
		# wrap pattern (or regexp if not pattern template):
		regex = wrap(getattr(template, 'pattern', template.regex))
		if hasattr(template, 'pattern'):
			# try to find in cache (by pattern):
			template2 = DD_patternCache.get(regex)
		# make duplicate and set new anchored regex:
		if not template2:
			if not hasattr(template, 'pattern'):
				template2 = _getPatternTemplate(name)
			else:
				template2 = _getPatternTemplate(regex)
	return template2



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
			if self.__templates: # pragma: no cover - race-condition + multi-threaded environment only
				return self.__templates
			self._addDefaultTemplate()
			return self.__templates

	def _cacheTemplate(self, template):
		"""Cache Fail2Ban's default template.

		"""
		if isinstance(template, str):
			# exact given template with word begin-end boundary:
			template = _getPatternTemplate(template)
		# if not already line-begin anchored, additional template, that prefers datetime 
		# at start of a line (safety+performance feature):
		name = template.name
		if not name.startswith('{^LN-BEG}') and not name.startswith('^') and hasattr(template, 'regex'):
			template2 = _getAnchoredTemplate(template)
			# prevent to add duplicates:
			if template2.name != name:
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
		# asctime with optional day, subsecond and/or year:
		# Sun Jan 23 21:59:59.011 2005 
		self._cacheTemplate("(?:%a )?%b %d %H:%M:%S(?:\.%f)?(?: %ExY)?")
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
		# Epoch
		self._cacheTemplate('EPOCH')
		# Only time information in the log
		self._cacheTemplate("{^LN-BEG}%H:%M:%S")
		# <09/16/08@05:03:30>
		self._cacheTemplate("^<%m/%d/%Exy@%H:%M:%S>")
		# MySQL: 130322 11:46:11
		self._cacheTemplate("%Exy%Exm%Exd  ?%H:%M:%S")
		# Apache Tomcat
		self._cacheTemplate("%b %d, %ExY %I:%M:%S %p")
		# ASSP: Apr-27-13 02:33:06
		self._cacheTemplate("^%b-%d-%Exy %H:%M:%S")
		# 20050123T215959, 20050123 215959
		self._cacheTemplate("%ExY%Exm%Exd[T ]%ExH%ExM%ExS(?:[.,]%f)?(?:\s*%z)?")
		# prefixed with optional named time zone (monit):
		# PDT Apr 16 21:05:29
		self._cacheTemplate("(?:%Z )?(?:%a )?%b %d %H:%M:%S(?:\.%f)?(?: %ExY)?")
		# +00:00 Jan 23 21:59:59.011 2005 
		self._cacheTemplate("(?:%z )?(?:%a )?%b %d %H:%M:%S(?:\.%f)?(?: %ExY)?")
		# TAI64N
		self._cacheTemplate("TAI64N")
		#
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

	def _appendTemplate(self, template, ignoreDup=False):
		name = template.name
		if name in self.__known_names:
			if ignoreDup: return
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
			key = pattern = template
			if '%' not in pattern:
				key = pattern.upper()
			template = DD_patternCache.get(key)
			if not template:
				if key in ("{^LN-BEG}", "{DEFAULT}"):
					flt = \
						lambda template: template.flags & DateTemplate.LINE_BEGIN if key == "{^LN-BEG}" else None
					self.addDefaultTemplate(flt)
					return
				elif "{DATE}" in key:
					self.addDefaultTemplate(
						lambda template: not template.flags & DateTemplate.LINE_BEGIN, pattern)
					return
				else:
					template = _getPatternTemplate(pattern, key)

			DD_patternCache.set(key, template)

		self._appendTemplate(template)
		logSys.info("  date pattern `%r`: `%s`",
			getattr(template, 'pattern', ''), template.name)
		logSys.debug("  date pattern regex for %r: %s",
			getattr(template, 'pattern', ''), template.regex)

	def addDefaultTemplate(self, filterTemplate=None, preMatch=None):
		"""Add Fail2Ban's default set of date templates.
		"""
		ignoreDup = len(self.__templates) > 0
		for template in DateDetector._defCache.templates:
			# filter if specified:
			if filterTemplate is not None and not filterTemplate(template): continue
			# if exact pattern available - create copy of template, contains replaced {DATE} with default regex:
			if preMatch is not None:
				# get cached or create a copy with modified name/pattern, using preMatch replacement for {DATE}:
				template = _getAnchoredTemplate(template,
					wrap=lambda s: RE_DATE_PREMATCH.sub(lambda m: s, preMatch))
			# append date detector template (ignore duplicate if some was added before default):
			self._appendTemplate(template, ignoreDup=ignoreDup)

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
		# if no templates specified - default templates should be used:
		if not len(self.__templates):
			self.addDefaultTemplate()
		logSys.log(logLevel-1, "try to match time for line: %.120s", line)
		match = None
		# first try to use last template with same start/end position:
		ignoreBySearch = 0x7fffffff
		i = self.__lastTemplIdx
		if i < len(self.__templates):
			ddtempl = self.__templates[i]
			template = ddtempl.template
			if template.flags & (DateTemplate.LINE_BEGIN|DateTemplate.LINE_END):
				if logSys.getEffectiveLevel() <= logLevel-1: # pragma: no cover - very-heavy debug
					logSys.log(logLevel-1, "  try to match last anchored template #%02i ...", i)
				match = template.matchDate(line)
				ignoreBySearch = i
			else:
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
				if (
					template.flags & (DateTemplate.LINE_BEGIN|DateTemplate.LINE_END) or 
					(distance == self.__lastPos[0] and endpos == self.__lastEndPos[0])
				):
					logSys.log(logLevel, "  matched last time template #%02i", i)
				else:
					logSys.log(logLevel, "  ** last pattern collision - pattern change, search ...")
					match = None
			else:
				logSys.log(logLevel, "  ** last pattern not found - pattern change, search ...")
		# search template and better match:
		if not match:
			logSys.log(logLevel, " search template (%i) ...", len(self.__templates))
			found = None, 0x7fffffff, 0x7fffffff, -1
			i = 0
			for ddtempl in self.__templates:
				if logSys.getEffectiveLevel() <= logLevel-1:
					logSys.log(logLevel-1, "  try template #%02i: %s", i, ddtempl.name)
				if i == ignoreBySearch:
					i += 1
					continue
				template = ddtempl.template
				match = template.matchDate(line)
				if match:
					distance = match.start()
					endpos = match.end()
					if logSys.getEffectiveLevel() <= logLevel:
						logSys.log(logLevel, "  matched time template #%02i (at %r <= %r, %r) %s",
							i, distance, ddtempl.distance, self.__lastPos[0], template.name)
					## last (or single) template - fast stop:
					if i+1 >= len(self.__templates):
						break
					## if line-begin/end anchored - stop searching:
					if template.flags & (DateTemplate.LINE_BEGIN|DateTemplate.LINE_END):
						break
					## stop searching if next template still unused, but we had already hits:
					if (distance == 0 and ddtempl.hits) and not self.__templates[i+1].template.hits:
						break
					## [grave] if distance changed, possible date-match was found somewhere 
					## in body of message, so save this template, and search further:
					if distance > ddtempl.distance or distance > self.__lastPos[0]:
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
			if i and i != self.__lastTemplIdx:
				i = self._reorderTemplate(i)
			self.__lastTemplIdx = i
			# return tuple with match and template reference used for parsing:
			return (match, template)

		# not found:
		logSys.log(logLevel, " no template.")
		return (None, None)

	def getTime(self, line, timeMatch=None, default_tz=None):
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
				date = template.getDate(line, timeMatch[0], default_tz=default_tz)
				if date is not None:
					if logSys.getEffectiveLevel() <= logLevel: # pragma: no cover - heavy debug
						logSys.log(logLevel, "  got time %f for %r using template %s",
							date[0], date[1].group(1), template.name)
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
			## don't move too often (multiline logs resp. log's with different date patterns),
			## if template not used too long, replace it also :
			def _moveable():
				pweight = templates[pos].weight
				if logSys.getEffectiveLevel() <= logLevel:
					logSys.log(logLevel, "  -> compare template #%02i & #%02i, weight %.3f > %.3f, hits %r > %r",
						num, pos, weight, pweight, ddtempl.hits, templates[pos].hits)
				return weight > pweight or untime > templates[pos].lastUsed
			##
			## if not moveable (smaller weight or target position recently used):
			if not _moveable():
				## try to move slow (exact 1 position):
				if pos == num-1:
					return num				
				pos = num-1
				## if still smaller and template at position used, don't move:
				if not _moveable():
					return num				
			## move:
			del templates[num]
			templates[pos:0] = [ddtempl]
			## correct first unused:
			while self.__firstUnused < len(templates) and templates[self.__firstUnused].hits:
				self.__firstUnused += 1
			if logSys.getEffectiveLevel() <= logLevel:
				logSys.log(logLevel, "  -> moved template #%02i -> #%02i", num, pos)
			return pos
		return num
