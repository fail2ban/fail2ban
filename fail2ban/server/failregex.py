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

import re
import sre_constants
import sys

from .ipdns import IPAddr


FTAG_CRE = re.compile(r'</?[\w\-]+/?>')

FCUSTNAME_CRE = re.compile(r'^(/?)F-([A-Z0-9_\-]+)$'); # currently uppercase only

R_HOST = [
		# separated ipv4:
		r"""(?:::f{4,6}:)?(?P<ip4>%s)""" % (IPAddr.IP_4_RE,),
		# separated ipv6:
		r"""(?P<ip6>%s)""" % (IPAddr.IP_6_RE,),
		# place-holder for ipv6 enclosed in optional [] (used in addr-, host-regex)
		"",
		# separated dns:
		r"""(?P<dns>[\w\-.^_]*\w)""",
		# place-holder for ADDR tag-replacement (joined):
		"",
		# place-holder for HOST tag replacement (joined):
		""
]
RI_IPV4 =		0
RI_IPV6 =		1
RI_IPV6BR =	2
RI_DNS =		3
RI_ADDR =		4
RI_HOST =		5

R_HOST[RI_IPV6BR] =	r"""\[?%s\]?""" % (R_HOST[RI_IPV6],)
R_HOST[RI_ADDR] =		"(?:%s)" % ("|".join((R_HOST[RI_IPV4], R_HOST[RI_IPV6BR])),)
R_HOST[RI_HOST] =		"(?:%s)" % ("|".join((R_HOST[RI_IPV4], R_HOST[RI_IPV6BR], R_HOST[RI_DNS])),)

RH4TAG = {
	# separated ipv4 (self closed, closed):
	"IP4":			R_HOST[RI_IPV4],
	"F-IP4/":		R_HOST[RI_IPV4],
	# separated ipv6 (self closed, closed):
	"IP6":			R_HOST[RI_IPV6],
	"F-IP6/":		R_HOST[RI_IPV6],
	# 2 address groups instead of <ADDR> - in opposition to `<HOST>`, 
	# for separate usage of 2 address groups only (regardless of `usedns`), `ip4` and `ip6` together
	"ADDR":			R_HOST[RI_ADDR],
	"F-ADDR/":	R_HOST[RI_ADDR],
	# separated dns (self closed, closed):
	"DNS":			R_HOST[RI_DNS],
	"F-DNS/":		R_HOST[RI_DNS],
	# default failure-id as no space tag:
	"F-ID/":		r"""(?P<fid>\S+)""",
	# default failure port, like 80 or http :
	"F-PORT/": 	r"""(?P<fport>\w+)""",
}

# default failure groups map for customizable expressions (with different group-id):
R_MAP = {
	"ID": "fid",
	"PORT": "fport",
}

def mapTag2Opt(tag):
	try: # if should be mapped:
		return R_MAP[tag]
	except KeyError:
		return tag.lower()

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
	
	def __init__(self, regex, **kwargs):
		self._matchCache = None
		# Perform shortcuts expansions.
		# Resolve "<HOST>" tag using default regular expression for host:
		regex = Regex._resolveHostTag(regex, **kwargs)
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

	def __str__(self):
		return "%s(%r)" % (self.__class__.__name__, self._regex)

	##
	# Replaces "<HOST>", "<IP4>", "<IP6>", "<FID>" with default regular expression for host
	#
	# (see gh-1374 for the discussion about other candidates)
	# @return the replaced regular expression as string

	@staticmethod
	def _resolveHostTag(regex, useDns="yes"):

		openTags = dict()
		# tag interpolation callable:
		def substTag(m):
			tag = m.group()
			tn = tag[1:-1]
			# 3 groups instead of <HOST> - separated ipv4, ipv6 and host (dns)
			if tn == "HOST":
				return R_HOST[RI_HOST if useDns not in ("no",) else RI_ADDR]
			# static replacement from RH4TAG:
			try:
				return RH4TAG[tn]
			except KeyError:
				pass

			# (begin / end tag) for customizable expressions, additionally used as
			# user custom tags (match will be stored in ticket data, can be used in actions):
			m = FCUSTNAME_CRE.match(tn)
			if m: # match F-...
				m = m.groups()
				tn = m[1]
				# close tag:
				if m[0]:
					# check it was already open:
					if openTags.get(tn):
						return ")"
					return tag; # tag not opened, use original
				# open tag:
				openTags[tn] = 1
				# if should be mapped:
				tn = mapTag2Opt(tn)
				return "(?P<%s>" % (tn,)

			# original, no replacement:
			return tag
		
		# substitute tags:
		return FTAG_CRE.sub(substTag, regex)

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
	# @param a list of tupples. The tupples are ( prematch, datematch, postdatematch )
	
	def search(self, tupleLines):
		self._matchCache = self._regexObj.search(
			"\n".join("".join(value[::2]) for value in tupleLines) + "\n")
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

			lineCount1 = self._matchCache.string.count(
				"\n", 0, self._matchLineStart)
			lineCount2 = self._matchCache.string.count(
				"\n", 0, self._matchLineEnd)
			self._matchedTupleLines = tupleLines[lineCount1:lineCount2]
			self._unmatchedTupleLines = tupleLines[:lineCount1]

			n = 0
			for skippedLine in self.getSkippedLines():
				for m, matchedTupleLine in enumerate(
					self._matchedTupleLines[n:]):
					if "".join(matchedTupleLine[::2]) == skippedLine:
						self._unmatchedTupleLines.append(
							self._matchedTupleLines.pop(n+m))
						n += m
						break
			self._unmatchedTupleLines.extend(tupleLines[lineCount2:])

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
				if self._matchCache.group("skiplines%i" % n) is not None:
					skippedLines += self._matchCache.group("skiplines%i" % n)
				n += 1
			except IndexError:
				break
			# KeyError is because of PyPy issue1665 affecting pypy <= 2.2.1 
			except KeyError:
				if 'PyPy' not in sys.version: # pragma: no cover - not sure this is even reachable
					raise
				break
		return skippedLines.splitlines(False)

	##
	# Returns unmatched lines.
	#
	# This returns unmatched lines including captured by the <SKIPLINES> tag.
	# @return list of unmatched lines

	def getUnmatchedTupleLines(self):
		if not self.hasMatched():
			return []
		else:
			return self._unmatchedTupleLines

	def getUnmatchedLines(self):
		if not self.hasMatched():
			return []
		else:
			return ["".join(line) for line in self._unmatchedTupleLines]

	##
	# Returns matched lines.
	#
	# This returns matched lines by excluding those captured
	# by the <SKIPLINES> tag.
	# @return list of matched lines

	def getMatchedTupleLines(self):
		if not self.hasMatched():
			return []
		else:
			return self._matchedTupleLines

	def getMatchedLines(self):
		if not self.hasMatched():
			return []
		else:
			return ["".join(line) for line in self._matchedTupleLines]


##
# Exception dedicated to the class Regex.

class RegexException(Exception):
	pass


##
# Groups used as failure identifier.
#
# The order of this tuple is important while searching for failure-id
#
FAILURE_ID_GROPS = ("fid", "ip4", "ip6", "dns")

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

	def __init__(self, regex, **kwargs):
		# Initializes the parent.
		Regex.__init__(self, regex, **kwargs)
		# Check for group "dns", "ip4", "ip6", "fid"
		if not [grp for grp in FAILURE_ID_GROPS if grp in self._regexObj.groupindex]:
			raise RegexException("No failure-id group in '%s'" % self._regex)
	
	##
	# Returns all matched groups.
	#

	def getGroups(self):
		return self._matchCache.groupdict()

	##
	# Returns the matched failure id.
	#
	# This corresponds to the pattern matched by the named group from given groups.
	# @return the matched failure-id
	
	def getFailID(self, groups=FAILURE_ID_GROPS):
		fid = None
		for grp in groups:
			try:
				fid = self._matchCache.group(grp)
			except (IndexError, KeyError):
				continue
			if fid is not None:
				break
		if fid is None:
			# Gets a few information.
			s = self._matchCache.string
			r = self._matchCache.re
			raise RegexException("No group found in '%s' using '%s'" % (s, r))
		return str(fid)

	##
	# Returns the matched host.
	#
	# This corresponds to the pattern matched by the named group "ip4", "ip6" or "dns".
	# @return the matched host
	
	def getHost(self):
		return self.getFailID(("ip4", "ip6", "dns"))
