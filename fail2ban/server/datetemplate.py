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
from abc import abstractmethod

from .strptime import reGroupDictStrptime, timeRE, getTimePatternRE
from ..helpers import getLogger

logSys = getLogger(__name__)

# check already grouped contains "(", but ignores char "\(" and conditional "(?(id)...)":
RE_GROUPED = re.compile(r'(?<!(?:\(\?))(?<!\\)\((?!\?)')
RE_GROUP = ( re.compile(r'^((?:\(\?\w+\))?\^?(?:\(\?\w+\))?)(.*?)(\$?)$'), r"\1(\2)\3" )

RE_EXLINE_BOUND_BEG = re.compile(r'^\{\^LN-BEG\}')
RE_NO_WRD_BOUND_BEG = re.compile(r'^\(*(?:\(\?\w+\))?(?:\^|\(*\*\*|\(\?:\^)')
RE_NO_WRD_BOUND_END = re.compile(r'(?<!\\)(?:\$\)?|\*\*\)*)$')
RE_DEL_WRD_BOUNDS = ( re.compile(r'^\(*(?:\(\?\w+\))?\(*\*\*|(?<!\\)\*\*\)*$'), 
	                    lambda m: m.group().replace('**', '') )

RE_LINE_BOUND_BEG = re.compile(r'^(?:\(\?\w+\))?(?:\^|\(\?:\^(?!\|))')
RE_LINE_BOUND_END = re.compile(r'(?<![\\\|])(?:\$\)?)$')

RE_ALPHA_PATTERN = re.compile(r'(?<!\%)\%[aAbBpc]')

class DateTemplate(object):
	"""A template which searches for and returns a date from a log line.

	This is an not functional abstract class which other templates should
	inherit from.

	Attributes
	----------
	name
	regex
	"""

	LINE_BEGIN = 8
	LINE_END =   4
	WORD_BEGIN = 2
	WORD_END =   1

	def __init__(self):
		self.name = ""
		self.weight = 1.0
		self.flags = 0
		self.hits = 0
		self.time = 0
		self._regex = ""
		self._cRegex = None

	def getRegex(self):
		return self._regex

	def setRegex(self, regex, wordBegin=True, wordEnd=True):
		"""Sets regex to use for searching for date in log line.

		Parameters
		----------
		regex : str
			The regex the template will use for searching for a date.
		wordBegin : bool
			Defines whether the regex should be modified to search at beginning of a
			word, by adding special boundary r'(?=^|\b|\W)' to start of regex.
			Can be disabled with specifying of ** at front of regex.
			Default True.
		wordEnd : bool
			Defines whether the regex should be modified to search at end of a word,
			by adding special boundary r'(?=\b|\W|$)' to end of regex.
			Can be disabled with specifying of ** at end of regex.
			Default True.

		Raises
		------
		re.error
			If regular expression fails to compile
		"""
		# Warning: don't use lookahead for line-begin boundary, 
		# (e. g. r"^(?:\W{0,2})?" is much faster as r"(?:^|(?<=^\W)|(?<=^\W{2}))")
		# because it may be very slow in negative case (by long log-lines not matching pattern)

		regex = regex.strip()
		boundBegin = wordBegin and not RE_NO_WRD_BOUND_BEG.search(regex)
		boundEnd = wordEnd and not RE_NO_WRD_BOUND_END.search(regex)
		# if no group add it now, should always have a group(1):
		if not RE_GROUPED.search(regex):
			regex = RE_GROUP[0].sub(RE_GROUP[1], regex)
		self.flags = 0
		# if word or line start boundary:
		if boundBegin:
			self.flags |= DateTemplate.WORD_BEGIN if wordBegin != 'start' else DateTemplate.LINE_BEGIN
			if wordBegin != 'start':
				regex = r'(?:^|\b|\W)' + regex
			else:
				regex = r"^(?:\W{0,2})?" + regex
				if not self.name.startswith('{^LN-BEG}'):
					self.name = '{^LN-BEG}' + self.name
		# if word end boundary:
		if boundEnd:
			self.flags |= DateTemplate.WORD_END
			regex += r'(?=\b|\W|$)'
		if RE_LINE_BOUND_BEG.search(regex): self.flags |= DateTemplate.LINE_BEGIN
		if RE_LINE_BOUND_END.search(regex): self.flags |= DateTemplate.LINE_END
		# remove possible special pattern "**" in front and end of regex:
		regex = RE_DEL_WRD_BOUNDS[0].sub(RE_DEL_WRD_BOUNDS[1], regex)
		self._regex = regex
		logSys.debug('  constructed regex %s', regex)
		self._cRegex = None

	regex = property(getRegex, setRegex, doc=
		"""Regex used to search for date.
		""")

	def _compileRegex(self):
		"""Compile regex by first usage.
		"""
		if not self._cRegex:
			try:
				# print('*'*10 + (' compile - %-30.30s -- %s' % (getattr(self, 'pattern', self.regex), self.name)))
				self._cRegex = re.compile(self.regex)
			except Exception as e:
				logSys.error('Compile %r failed, expression %r', self.name, self.regex)
				raise e

	def matchDate(self, line, *args):
		"""Check if regex for date matches on a log line.
		"""
		if not self._cRegex:
			self._compileRegex()
		dateMatch = self._cRegex.search(line, *args); # pos, endpos
		if dateMatch:
			self.hits += 1
		# print('*'*10 + ('[%s] - %-30.30s -- %s' % ('*' if dateMatch else ' ', getattr(self, 'pattern', self.regex), self.name)))
		return dateMatch

	@abstractmethod
	def getDate(self, line, dateMatch=None, default_tz=None):
		"""Abstract method, which should return the date for a log line

		This should return the date for a log line, typically taking the
		date from the part of the line which matched the templates regex.
		This requires abstraction, therefore just raises exception.

		Parameters
		----------
		line : str
			Log line, of which the date should be extracted from.
		default_tz: if no explicit time zone is present in the line
                            passing this will interpret it as in that time zone.

		Raises
		------
		NotImplementedError
			Abstract method, therefore always returns this.
		"""
		raise NotImplementedError("getDate() is abstract")


class DateEpoch(DateTemplate):
	"""A date template which searches for Unix timestamps.

	This includes Unix timestamps which appear at start of a line, optionally
	within square braces (nsd), or on SELinux audit log lines.

	Attributes
	----------
	name
	regex
	"""

	def __init__(self, lineBeginOnly=False):
		DateTemplate.__init__(self)
		self.name = "Epoch"
		if not lineBeginOnly:
			regex = r"((?:^|(?P<square>(?<=^\[))|(?P<selinux>(?<=\baudit\()))\d{10,11}\b(?:\.\d{3,6})?)(?:(?(selinux)(?=:\d+\)))|(?(square)(?=\])))"
			self.setRegex(regex, wordBegin=False) ;# already line begin resp. word begin anchored
		else:
			regex = r"((?P<square>(?<=^\[))?\d{10,11}\b(?:\.\d{3,6})?)(?(square)(?=\]))"
			self.setRegex(regex, wordBegin='start', wordEnd=True)

	def getDate(self, line, dateMatch=None, default_tz=None):
		"""Method to return the date for a log line.

		Parameters
		----------
		line : str
			Log line, of which the date should be extracted from.
		default_tz: ignored, Unix timestamps are time zone independent

		Returns
		-------
		(float, str)
			Tuple containing a Unix timestamp, and the string of the date
			which was matched and in turned used to calculated the timestamp.
		"""
		if not dateMatch:
			dateMatch = self.matchDate(line)
		if dateMatch:
			# extract part of format which represents seconds since epoch
			return (float(dateMatch.group(1)), dateMatch)


class DatePatternRegex(DateTemplate):
	"""Date template, with regex/pattern

	Parameters
	----------
	pattern : str
		Sets the date templates pattern.

	Attributes
	----------
	name
	regex
	pattern
	"""
	
	_patternRE, _patternName = getTimePatternRE()
	_patternRE = re.compile(_patternRE)

	def __init__(self, pattern=None, **kwargs):
		super(DatePatternRegex, self).__init__()
		self._pattern = None
		if pattern is not None:
			self.setRegex(pattern, **kwargs)

	@property
	def pattern(self):
		"""The pattern used for regex with strptime "%" time fields.

		This should be a valid regular expression, of which matching string
		will be extracted from the log line. strptime style "%" fields will
		be replaced by appropriate regular expressions, or custom regex
		groups with names as per the strptime fields can also be used
		instead.
		"""
		return self._pattern

	@pattern.setter
	def pattern(self, pattern):
		self.setRegex(pattern)

	def setRegex(self, pattern, wordBegin=True, wordEnd=True):
		# original pattern:
		self._pattern = pattern
		# if explicit given {^LN-BEG} - remove it from pattern and set 'start' in wordBegin:
		if wordBegin and RE_EXLINE_BOUND_BEG.search(pattern):
			pattern = RE_EXLINE_BOUND_BEG.sub('', pattern)
			wordBegin = 'start'
		# wrap to regex:
		fmt = self._patternRE.sub(r'%(\1)s', pattern)
		self.name = fmt % self._patternName
		regex = fmt % timeRE
		# if expected add (?iu) for "ignore case" and "unicode":
		if RE_ALPHA_PATTERN.search(pattern):
			regex = r'(?iu)' + regex
		super(DatePatternRegex, self).setRegex(regex, wordBegin, wordEnd)

	def getDate(self, line, dateMatch=None, default_tz=None):
		"""Method to return the date for a log line.

		This uses a custom version of strptime, using the named groups
		from the instances `pattern` property.

		Parameters
		----------
		line : str
			Log line, of which the date should be extracted from.
		default_tz: optionally used to correct timezone

		Returns
		-------
		(float, str)
			Tuple containing a Unix timestamp, and the string of the date
			which was matched and in turned used to calculated the timestamp.
		"""
		if not dateMatch:
			dateMatch = self.matchDate(line)
		if dateMatch:
			return (reGroupDictStrptime(dateMatch.groupdict(), default_tz=default_tz),
				dateMatch)


class DateTai64n(DateTemplate):
	"""A date template which matches TAI64N formate timestamps.

	Attributes
	----------
	name
	regex
	"""

	def __init__(self, wordBegin=False):
		DateTemplate.__init__(self)
		self.name = "TAI64N"
		# We already know the format for TAI64N
		self.setRegex("@[0-9a-f]{24}", wordBegin=wordBegin)

	def getDate(self, line, dateMatch=None, default_tz=None):
		"""Method to return the date for a log line.

		Parameters
		----------
		line : str
			Log line, of which the date should be extracted from.
		default_tz: ignored, since TAI is time zone independent

		Returns
		-------
		(float, str)
			Tuple containing a Unix timestamp, and the string of the date
			which was matched and in turned used to calculated the timestamp.
		"""
		if not dateMatch:
			dateMatch = self.matchDate(line)
		if dateMatch:
			# extract part of format which represents seconds since epoch
			value = dateMatch.group(1)
			seconds_since_epoch = value[2:17]
			# convert seconds from HEX into local time stamp
			return (int(seconds_since_epoch, 16), dateMatch)
