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

import re
from abc import abstractmethod

from .strptime import reGroupDictStrptime, timeRE, getTimePatternRE
from ..helpers import getLogger

logSys = getLogger(__name__)

RE_NO_WRD_BOUND_BEG = re.compile(r'^(?:\^|\*\*|\(\?:\^)')
RE_NO_WRD_BOUND_END = re.compile(r'(?<!\\)(?:\$\)?|\*\*)$')
RE_DEL_WRD_BOUNDS =   re.compile(r'^\*\*|(?<!\\)\*\*$')

RE_LINE_BOUND_BEG = re.compile(r'^(?:\^|\(\?:\^(?!\|))')
RE_LINE_BOUND_END = re.compile(r'(?<![\\\|])(?:\$\)?)$')

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
		regex = regex.strip()
		self.flags = 0
		# if word or line start boundary:
		if wordBegin and not RE_NO_WRD_BOUND_BEG.search(regex):
			self.flags |= DateTemplate.WORD_BEGIN if wordBegin != 'start' else DateTemplate.LINE_BEGIN
			regex = (r'(?=^|\b|\W)' if wordBegin != 'start' else r"(?:^|(?<=^\W)|(?<=^\W{2}))") + regex
			self.name = ('{*WD-BEG}' if wordBegin != 'start' else '{^LN-BEG}') + self.name
		# if word end boundary:
		if wordEnd and not RE_NO_WRD_BOUND_END.search(regex):
			self.flags |= DateTemplate.WORD_END
			regex += r'(?=\b|\W|$)'
			self.name += '{*WD-END}'
		if RE_LINE_BOUND_BEG.search(regex): self.flags |= DateTemplate.LINE_BEGIN
		if RE_LINE_BOUND_END.search(regex): self.flags |= DateTemplate.LINE_END
		# remove possible special pattern "**" in front and end of regex:
		regex = RE_DEL_WRD_BOUNDS.sub('', regex)
		self._regex = regex
		self._cRegex = None

	regex = property(getRegex, setRegex, doc=
		"""Regex used to search for date.
		""")

	def _compileRegex(self):
		"""Compile regex by first usage.
		"""
		if not self._cRegex:
			self._cRegex = re.compile(self.regex, re.UNICODE | re.IGNORECASE)

	def matchDate(self, line, *args):
		"""Check if regex for date matches on a log line.
		"""
		if not self._cRegex:
			self._compileRegex()
		dateMatch = self._cRegex.search(line, *args); # pos, endpos
		return dateMatch

	@abstractmethod
	def getDate(self, line, dateMatch=None):
		"""Abstract method, which should return the date for a log line

		This should return the date for a log line, typically taking the
		date from the part of the line which matched the templates regex.
		This requires abstraction, therefore just raises exception.

		Parameters
		----------
		line : str
			Log line, of which the date should be extracted from.

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
			regex = r"(?:^|(?P<square>(?<=^\[))|(?P<selinux>(?<=\baudit\()))\d{10,11}\b(?:\.\d{3,6})?(?:(?(selinux)(?=:\d+\)))|(?(square)(?=\])))"
			self.setRegex(regex, wordBegin=False) ;# already line begin resp. word begin anchored
		else:
			regex = r"(?P<square>(?<=^\[))\d{10,11}\b(?:\.\d{3,6})?(?(square)(?=\]))"
			self.setRegex(regex, wordBegin='start', wordEnd=True)

	def getDate(self, line, dateMatch=None):
		"""Method to return the date for a log line.

		Parameters
		----------
		line : str
			Log line, of which the date should be extracted from.

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
			return (float(dateMatch.group()), dateMatch)
		return None


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
		self._pattern = pattern
		fmt = self._patternRE.sub(r'%(\1)s', pattern)
		self.name = fmt % self._patternName
		super(DatePatternRegex, self).setRegex(fmt % timeRE, wordBegin, wordEnd)

	def getDate(self, line, dateMatch=None):
		"""Method to return the date for a log line.

		This uses a custom version of strptime, using the named groups
		from the instances `pattern` property.

		Parameters
		----------
		line : str
			Log line, of which the date should be extracted from.

		Returns
		-------
		(float, str)
			Tuple containing a Unix timestamp, and the string of the date
			which was matched and in turned used to calculated the timestamp.
		"""
		if not dateMatch:
			dateMatch = self.matchDate(line)
		if dateMatch:
			return reGroupDictStrptime(dateMatch.groupdict()), dateMatch


class DateTai64n(DateTemplate):
	"""A date template which matches TAI64N formate timestamps.

	Attributes
	----------
	name
	regex
	"""

	def __init__(self):
		DateTemplate.__init__(self)
		self.name = "TAI64N"
		# We already know the format for TAI64N
		# yoh: we should not add an additional front anchor
		self.setRegex("@[0-9a-f]{24}", wordBegin=False)

	def getDate(self, line, dateMatch=None):
		"""Method to return the date for a log line.

		Parameters
		----------
		line : str
			Log line, of which the date should be extracted from.

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
			value = dateMatch.group()
			seconds_since_epoch = value[2:17]
			# convert seconds from HEX into local time stamp
			return (int(seconds_since_epoch, 16), dateMatch)
		return None
