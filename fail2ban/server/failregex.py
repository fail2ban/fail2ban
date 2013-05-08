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

__author__ = "Cyril Jaquier"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import re, sre_constants

##
# Regular expression class.
#
# This class represents a regular expression with its compiled version.

class Regex:

	##
	# Constructor.
	#
	# Creates a new object. This method can throw RegexException in order to
	# avoid construction of invalid object.
	# @param value the regular expression
	
	def __init__(self, regex):
		self._matchCache = None
		# Perform shortcuts expansions.
		# Replace "<HOST>" with default regular expression for host.
		regex = regex.replace("<HOST>", "(?:::f{4,6}:)?(?P<host>[\w\-.^_]+)")
		# Replace "<SKIPLINES>" with regular expression for multiple lines.
		regexSplit = regex.split("<SKIPLINES>")
		regex = regexSplit[0]
		for n, regexLine in enumerate(regexSplit[1:]):
			regex += "\n(?P<skiplines%i>(?:(.*\n)*?))" % n + regexLine
		if regex.lstrip() == '':
			raise RegexException("Cannot add empty regex")
		try:
			self._regexObj = re.compile(regex, re.MULTILINE)
			self._regex = regex
		except sre_constants.error:
			raise RegexException("Unable to compile regular expression '%s'" %
								 regex)
	
	##
	# Gets the regular expression.
	#
	# The effective regular expression used is returned.
	# @return the regular expression
	
	def getRegex(self):
		return self._regex
	
	##
	# Searches the regular expression.
	#
	# Sets an internal cache (match object) in order to avoid searching for
	# the pattern again. This method must be called before calling any other
	# method of this object.
	# @param value the line
	
	def search(self, value):
		self._matchCache = self._regexObj.search(value)
		if self.hasMatched():
			# Find start of the first line where the match was found
			try:
				self._matchLineStart = self._matchCache.string.rindex(
					"\n", 0, self._matchCache.start() +1 ) + 1
			except ValueError:
				self._matchLineStart = 0
			# Find end of the last line where the match was found
			try:
				self._matchLineEnd = self._matchCache.string.index(
					"\n", self._matchCache.end() - 1) + 1
			except ValueError:
				self._matchLineEnd = len(self._matchCache.string)
	
	##
	# Checks if the previous call to search() matched.
	#
	# @return True if a match was found, False otherwise
	
	def hasMatched(self):
		if self._matchCache:
			return True
		else:
			return False

	##
	# Returns skipped lines.
	#
	# This returns skipped lines captured by the <SKIPLINES> tag.
	# @return list of skipped lines
	
	def getSkippedLines(self):
		if not self._matchCache:
			return []
		skippedLines = ""
		n = 0
		while True:
			try:
				skippedLines += self._matchCache.group("skiplines%i" % n)
				n += 1
			except IndexError:
				break
		return skippedLines.splitlines(False)

	##
	# Returns unmatched lines.
	#
	# This returns unmatched lines including captured by the <SKIPLINES> tag.
	# @return list of unmatched lines
	
	def getUnmatchedLines(self):
		if not self.hasMatched():
			return []
		unmatchedLines = (
			self._matchCache.string[:self._matchLineStart].splitlines(False)
			+ self.getSkippedLines()
			+ self._matchCache.string[self._matchLineEnd:].splitlines(False))
		return unmatchedLines

	##
	# Returns matched lines.
	#
	# This returns matched lines by excluding those captured
	# by the <SKIPLINES> tag.
	# @return list of matched lines
	
	def getMatchedLines(self):
		if not self.hasMatched():
			return []
		matchedLines = self._matchCache.string[
			self._matchLineStart:self._matchLineEnd].splitlines(False)
		return [line for line in matchedLines
			if line not in self.getSkippedLines()]

##
# Exception dedicated to the class Regex.

class RegexException(Exception):
	pass


##
# Regular expression class.
#
# This class represents a regular expression with its compiled version.

class FailRegex(Regex):

	##
	# Constructor.
	#
	# Creates a new object. This method can throw RegexException in order to
	# avoid construction of invalid object.
	# @param value the regular expression
	
	def __init__(self, regex):
		# Initializes the parent.
		Regex.__init__(self, regex)
		# Check for group "host"
		if "host" not in self._regexObj.groupindex:
			raise RegexException("No 'host' group in '%s'" % self._regex)
	
	##
	# Returns the matched host.
	#
	# This corresponds to the pattern matched by the named group "host".
	# @return the matched host
	
	def getHost(self):
		host = self._matchCache.group("host")
		if host is None:
			# Gets a few information.
			s = self._matchCache.string
			r = self._matchCache.re
			raise RegexException("No 'host' found in '%s' using '%s'" % (s, r))
		return str(host)
