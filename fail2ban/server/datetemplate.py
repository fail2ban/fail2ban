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

from .strptime import reGroupDictStrptime, timeRE
from ..helpers import getLogger

logSys = getLogger(__name__)


class DateTemplate(object):
	"""A template which searches for and returns a date from a log line.

	This is an not functional abstract class which other templates should
	inherit from.

	Attributes
	----------
	name
	regex
	"""

	def __init__(self):
		self._name = ""
		self._regex = ""
		self._cRegex = None
		self.hits = 0

	@property
	def name(self):
		"""Name assigned to template.
		"""
		return self._name

	@name.setter
	def name(self, name):
		self._name = name

	def getRegex(self):
		return self._regex

	def setRegex(self, regex, wordBegin=True):
		"""Sets regex to use for searching for date in log line.

		Parameters
		----------
		regex : str
			The regex the template will use for searching for a date.
		wordBegin : bool
			Defines whether the regex should be modified to search at
			beginning of a word, by adding "\\b" to start of regex.
			Default True.

		Raises
		------
		re.error
			If regular expression fails to compile
		"""
		regex = regex.strip()
		if (wordBegin and not re.search(r'^\^', regex)):
			regex = r'\b' + regex
		self._regex = regex
		self._cRegex = re.compile(regex, re.UNICODE | re.IGNORECASE)

	regex = property(getRegex, setRegex, doc=
		"""Regex used to search for date.
		""")

	def matchDate(self, line):
		"""Check if regex for date matches on a log line.
		"""
		dateMatch = self._cRegex.search(line)
		return dateMatch

	@abstractmethod
	def getDate(self, line):
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

	def __init__(self):
		DateTemplate.__init__(self)
		self.regex = r"(?:^|(?P<square>(?<=^\[))|(?P<selinux>(?<=audit\()))\d{10,11}\b(?:\.\d{3,6})?(?:(?(selinux)(?=:\d+\)))|(?(square)(?=\])))"

	def getDate(self, line):
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
	_patternRE = r"%%(%%|[%s])" % "".join(timeRE.keys())
	_patternName = {
		'a': "DAY", 'A': "DAYNAME", 'b': "MON", 'B': "MONTH", 'd': "Day",
		'H': "24hour", 'I': "12hour", 'j': "Yearday", 'm': "Month",
		'M': "Minute", 'p': "AMPM", 'S': "Second", 'U': "Yearweek",
		'w': "Weekday", 'W': "Yearweek", 'y': 'Year2', 'Y': "Year", '%': "%",
		'z': "Zone offset", 'f': "Microseconds", 'Z': "Zone name"}
	for _key in set(timeRE) - set(_patternName): # may not have them all...
		_patternName[_key] = "%%%s" % _key

	def __init__(self, pattern=None):
		super(DatePatternRegex, self).__init__()
		self._pattern = None
		if pattern is not None:
			self.pattern = pattern

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
		self._pattern = pattern
		self._name = re.sub(
			self._patternRE, r'%(\1)s', pattern) % self._patternName
		super(DatePatternRegex, self).setRegex(
			re.sub(self._patternRE, r'%(\1)s', pattern) % timeRE)

	def setRegex(self, value):
		raise NotImplementedError("Regex derived from pattern")

	@DateTemplate.name.setter
	def name(self, value):
		raise NotImplementedError("Name derived from pattern")

	def getDate(self, line):
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
		dateMatch = self.matchDate(line)
		if dateMatch:
			groupdict = dict(
				(key, value)
				for key, value in dateMatch.groupdict().iteritems()
				if value is not None)
			return reGroupDictStrptime(groupdict), dateMatch


class DateTai64n(DateTemplate):
	"""A date template which matches TAI64N formate timestamps.

	Attributes
	----------
	name
	regex
	"""

	def __init__(self):
		DateTemplate.__init__(self)
		# We already know the format for TAI64N
		# yoh: we should not add an additional front anchor
		self.setRegex("@[0-9a-f]{24}", wordBegin=False)

	def getDate(self, line):
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
		dateMatch = self.matchDate(line)
		if dateMatch:
			# extract part of format which represents seconds since epoch
			value = dateMatch.group()
			seconds_since_epoch = value[2:17]
			# convert seconds from HEX into local time stamp
			return (int(seconds_since_epoch, 16), dateMatch)
		return None
