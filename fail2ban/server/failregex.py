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
import sys

from .ipdns import IPAddr


FTAG_CRE = re.compile(r'</?[\w\-]+/?>')

FCUSTNAME_CRE = re.compile(r'^(/?)F-([A-Z0-9_\-]+)$'); # currently uppercase only

R_HOST = [
		# separated ipv4:
		r"""(?:::f{4,6}:)?(?P<ip4>%s)""" % (IPAddr.IP_4_RE,),
		# separated ipv6:
		r"""(?P<ip6>%s)""" % (IPAddr.IP_6_RE,),
		# separated dns:
		r"""(?P<dns>[\w\-.^_]*\w)""",
		# place-holder for ADDR tag-replacement (joined):
		"",
		# place-holder for HOST tag replacement (joined):
		"",
		# CIDR in simplest integer form:
		r"(?P<cidr>\d+)",
		# place-holder for SUBNET tag-replacement
		"",
]
RI_IPV4 =		0
RI_IPV6 =		1
RI_DNS =		2
RI_ADDR =		3
RI_HOST =		4
RI_CIDR =		5
RI_SUBNET =	6

R_HOST[RI_ADDR] =		r"\[?(?:%s|%s)\]?" % (R_HOST[RI_IPV4], R_HOST[RI_IPV6],)
R_HOST[RI_HOST] =		r"(?:%s|%s)" % (R_HOST[RI_ADDR], R_HOST[RI_DNS],)
R_HOST[RI_SUBNET] =	r"\[?(?:%s|%s)(?:/%s)?\]?" % (R_HOST[RI_IPV4], R_HOST[RI_IPV6], R_HOST[RI_CIDR],)

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
	# subnet tags for usage as `<ADDR>/<CIDR>` or `<SUBNET>`:
	"CIDR":			R_HOST[RI_CIDR],
	"F-CIDR/":	R_HOST[RI_CIDR],
	"SUBNET":		R_HOST[RI_SUBNET],
	"F-SUBNET/":R_HOST[RI_SUBNET],
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
	"id": "fid",
	"port": "fport",
}

# map global flags like ((?i)xxx) or (?:(?i)xxx) to local flags (?i:xxx) if supported by RE-engine in this python version:
try:
	re.search("^re(?i:val)$", "reVAL")
	R_GLOB2LOCFLAGS = ( re.compile(r"(?<!\\)\((?:\?:)?(\(\?[a-z]+)\)"), r"\1:" )
except:
	R_GLOB2LOCFLAGS = ()

def mapTag2Opt(tag):
	tag = tag.lower()
	return R_MAP.get(tag, tag)


# complex names:
# ALT_   - alternate names to be merged, e. g. alt_user_1 -> user ...
ALTNAME_PRE = 'alt_'
# TUPLE_ - names of parts to be combined to single value as tuple
TUPNAME_PRE = 'tuple_'

COMPLNAME_PRE = (ALTNAME_PRE, TUPNAME_PRE)
COMPLNAME_CRE = re.compile(r'^(' + '|'.join(COMPLNAME_PRE) + r')(.*?)(?:_\d+)?$')


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
	
	def __init__(self, regex, multiline=False, **kwargs):
		self._matchCache = None
		# Perform shortcuts expansions.
		# Replace standard f2b-tags (like "<HOST>", etc) using default regular expressions:
		regex = Regex._resolveHostTag(regex, **kwargs)
		#
		if regex.lstrip() == '':
			raise RegexException("Cannot add empty regex")
		# special handling wrapping global flags to local flags:
		if R_GLOB2LOCFLAGS:
			regex = R_GLOB2LOCFLAGS[0].sub(R_GLOB2LOCFLAGS[1], regex)
		try:
			self._regexObj = re.compile(regex, re.MULTILINE if multiline else 0)
			self._regex = regex
			self._altValues = []
			self._tupleValues = []
			for k in [k for k in self._regexObj.groupindex if len(k) > len(COMPLNAME_PRE[0])]:
				n = COMPLNAME_CRE.match(k)
				if n:
					g, n = n.group(1), mapTag2Opt(n.group(2))
					if g == ALTNAME_PRE:
						self._altValues.append((k,n))
					else:
						self._tupleValues.append((k,n))
			self._altValues.sort()
			self._tupleValues.sort()
			self._altValues = self._altValues if len(self._altValues) else None
			self._tupleValues = self._tupleValues if len(self._tupleValues) else None
		except re.error as e:
			raise RegexException("Unable to compile regular expression '%s':\n%s" %
								 (regex, e))
		# set fetch handler depending on presence of alternate (or tuple) tags:
		self.getGroups = self._getGroupsWithAlt if (self._altValues or self._tupleValues) else self._getGroups

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
		props = {
			'nl': 0, # new lines counter by <SKIPLINES> tag;
		}
		# tag interpolation callable:
		def substTag(m):
			tag = m.group()
			tn = tag[1:-1]
			# 3 groups instead of <HOST> - separated ipv4, ipv6 and host (dns)
			if tn == "HOST":
				return R_HOST[RI_HOST if useDns not in ("no",) else RI_ADDR]
			# replace "<SKIPLINES>" with regular expression for multiple lines (by buffering with maxlines)
			if tn == "SKIPLINES":
				nl = props['nl']
				props['nl'] = nl + 1
				return r"\n(?P<skiplines%i>(?:(?:.*\n)*?))" % (nl,)
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
	# Returns string buffer using join of the tupleLines.
	#
	@staticmethod
	def _tupleLinesBuf(tupleLines):
		return "\n".join(["".join(v[::2]) for v in tupleLines]) + "\n"

	##
	# Searches the regular expression.
	#
	# Sets an internal cache (match object) in order to avoid searching for
	# the pattern again. This method must be called before calling any other
	# method of this object.
	# @param a list of tuples. The tuples are ( prematch, datematch, postdatematch )
	
	def search(self, tupleLines, orgLines=None):
		buf = tupleLines
		if not isinstance(tupleLines, str):
			buf = Regex._tupleLinesBuf(tupleLines)
		self._matchCache = self._regexObj.search(buf)
		if self._matchCache:
			if orgLines is None: orgLines = tupleLines
			# if single-line:
			if len(orgLines) <= 1:
				self._matchedTupleLines = orgLines
				self._unmatchedTupleLines = []
			else:
				# Find start of the first line where the match was found
				try:
					matchLineStart = self._matchCache.string.rindex(
						"\n", 0, self._matchCache.start() +1 ) + 1
				except ValueError:
					matchLineStart = 0
				# Find end of the last line where the match was found
				try:
					matchLineEnd = self._matchCache.string.index(
						"\n", self._matchCache.end() - 1) + 1
				except ValueError:
					matchLineEnd = len(self._matchCache.string)

				lineCount1 = self._matchCache.string.count(
					"\n", 0, matchLineStart)
				lineCount2 = self._matchCache.string.count(
					"\n", 0, matchLineEnd)
				self._matchedTupleLines = orgLines[lineCount1:lineCount2]
				self._unmatchedTupleLines = orgLines[:lineCount1]
				n = 0
				for skippedLine in self.getSkippedLines():
					for m, matchedTupleLine in enumerate(
						self._matchedTupleLines[n:]):
						if "".join(matchedTupleLine[::2]) == skippedLine:
							self._unmatchedTupleLines.append(
								self._matchedTupleLines.pop(n+m))
							n += m
							break
				self._unmatchedTupleLines.extend(orgLines[lineCount2:])

	# Checks if the previous call to search() matched.
	#
	# @return True if a match was found, False otherwise
	
	def hasMatched(self):
		if self._matchCache:
			return True
		else:
			return False

	##
	# Returns all matched groups.
	#

	def _getGroups(self):
		return self._matchCache.groupdict()

	def _getGroupsWithAlt(self):
		fail = self._matchCache.groupdict()
		#fail = fail.copy()
		# merge alternate values (e. g. 'alt_user_1' -> 'user' or 'alt_host' -> 'host'):
		if self._altValues:
			for k,n in self._altValues:
				v = fail.get(k)
				if v and not fail.get(n):
					fail[n] = v
		# combine tuple values (e. g. 'id', 'tuple_id' ... 'tuple_id_N' -> 'id'):
		if self._tupleValues:
			for k,n in self._tupleValues:
				v = fail.get(k)
				t = fail.get(n)
				if isinstance(t, tuple):
					t += (v,)
				else:
					t = (t,v,)
				fail[n] = t
		return fail

	def getGroups(self): # pragma: no cover - abstract function (replaced in __init__)
		pass

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

# Additionally allows multi-line failure-id (used for wrapping e. g. conn-id to host)
#
FAILURE_ID_PRESENTS = FAILURE_ID_GROPS + ("mlfid",)

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

	def __init__(self, regex, prefRegex=None, **kwargs):
		# Initializes the parent.
		Regex.__init__(self, regex, **kwargs)
		# Check for group "dns", "ip4", "ip6", "fid"
		if (not [grp for grp in FAILURE_ID_PRESENTS if grp in self._regexObj.groupindex]
			and (prefRegex is None or
				not [grp for grp in FAILURE_ID_PRESENTS if grp in prefRegex._regexObj.groupindex])
		):
			raise RegexException("No failure-id group in '%s'" % self._regex)
	
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

	def getIP(self):
		fail = self.getGroups()
		return IPAddr(self.getFailID(("ip4", "ip6")), int(fail.get("cidr") or IPAddr.CIDR_UNSPEC))
