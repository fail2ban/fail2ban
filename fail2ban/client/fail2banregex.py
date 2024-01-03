# emacs: -*- mode: python; py-indent-offset: 4; indent-tabs-mode: t -*-
# vi: set ft=python sts=4 ts=4 sw=4 noet :
#
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
"""
Fail2Ban  reads log file that contains password failure report
and bans the corresponding IP addresses using firewall rules.

This tools can test regular expressions for "fail2ban".
"""

__author__ = "Fail2Ban Developers"
__copyright__ = """Copyright (c) 2004-2008 Cyril Jaquier, 2008- Fail2Ban Contributors
Copyright of modifications held by their respective authors.
Licensed under the GNU General Public License v2 (GPL).

Written by Cyril Jaquier <cyril.jaquier@fail2ban.org>.
Many contributions by Yaroslav O. Halchenko, Steven Hiscocks, Sergey G. Brester (sebres)."""

__license__ = "GPL"

import getopt
import logging
import re
import os
import shlex
import sys
import time
import urllib.request, urllib.parse, urllib.error
from optparse import OptionParser, Option

from configparser import NoOptionError, NoSectionError, MissingSectionHeaderError

try: # pragma: no cover
	from ..server.filtersystemd import FilterSystemd
except ImportError:
	FilterSystemd = None

from ..version import version, normVersion
from .jailreader import FilterReader, JailReader, NoJailError
from ..server.filter import Filter, FileContainer, MyTime
from ..server.failregex import Regex, RegexException

from ..helpers import str2LogLevel, getVerbosityFormat, FormatterWithTraceBack, getLogger, \
  extractOptions, PREFER_ENC
# Gets the instance of the logger.
logSys = getLogger("fail2ban")

def debuggexURL(sample, regex, multiline=False, useDns="yes"):
	args = {
		're': Regex._resolveHostTag(regex, useDns=useDns),
		'str': sample,
		'flavor': 'python'
	}
	if multiline: args['flags'] = 'm'
	return 'https://www.debuggex.com/?' + urllib.parse.urlencode(args)

def output(args): # pragma: no cover (overridden in test-cases)
	print(args)

def shortstr(s, l=53):
	"""Return shortened string
	"""
	if len(s) > l:
		return s[:l-3] + '...'
	return s

def pprint_list(l, header=None):
	if not len(l):
		return
	if header:
		s = "|- %s\n" % header
	else:
		s = ''
	output( s + "|  " + "\n|  ".join(l) + '\n`-' )

def journal_lines_gen(flt, myjournal): # pragma: no cover
	while True:
		try:
			entry = myjournal.get_next()
		except OSError:
			continue
		if not entry:
			break
		yield flt.formatJournalEntry(entry)

def dumpNormVersion(*args):
	output(normVersion())
	sys.exit(0)

usage = lambda: "%s [OPTIONS] <LOG> <REGEX> [IGNOREREGEX]" % sys.argv[0]

class _f2bOptParser(OptionParser):
	def format_help(self, *args, **kwargs):
		""" Overwritten format helper with full ussage."""
		self.usage = ''
		return "Usage: " + usage() + "\n" + __doc__ + """
LOG:
  string                a string representing a log line
  filename              path to a log file (/var/log/auth.log)
  systemd-journal       search systemd journal (systemd-python required),
                        optionally with backend parameters, see `man jail.conf`
                        for usage and examples (systemd-journal[journalflags=1]).

REGEX:
  string                a string representing a 'failregex'
  filter                name of filter, optionally with options (sshd[mode=aggressive])
  filename              path to a filter file (filter.d/sshd.conf)

IGNOREREGEX:
  string                a string representing an 'ignoreregex'
  filename              path to a filter file (filter.d/sshd.conf)
\n""" + OptionParser.format_help(self, *args, **kwargs) + """\n
Report bugs to https://github.com/fail2ban/fail2ban/issues\n
""" + __copyright__ + "\n"


def get_opt_parser():
	# use module docstring for help output
	p = _f2bOptParser(
				usage=usage(),
				version="%prog " + version)

	p.add_options([
		Option("-c", "--config", default='/etc/fail2ban',
			   help="set alternate config directory"),
		Option("-d", "--datepattern",
			   help="set custom pattern used to match date/times"),
		Option("--timezone", "--TZ", action='store', default=None,
			   help="set time-zone used by convert time format"),
		Option("-e", "--encoding", default=PREFER_ENC,
			   help="File encoding. Default: system locale"),
		Option("-r", "--raw", action='store_true', default=False,
			   help="Raw hosts, don't resolve dns"),
		Option("--usedns", action='store', default=None,
			   help="DNS specified replacement of tags <HOST> in regexp "
			        "('yes' - matches all form of hosts, 'no' - IP addresses only)"),
		Option("-L", "--maxlines", type=int, default=0,
			   help="maxlines for multi-line regex."),
		Option("-m", "--journalmatch",
			   help="journalctl style matches overriding filter file. "
			   "\"systemd-journal\" only"),
		Option('-l', "--log-level",
			   dest="log_level",
			   default='critical',
			   help="Log level for the Fail2Ban logger to use"),
		Option('-V', action="callback", callback=dumpNormVersion,
			   help="get version in machine-readable short format"),
		Option('-v', '--verbose', action="count", dest="verbose",
			   default=0,
			   help="Increase verbosity"),
		Option("--verbosity", action="store", dest="verbose", type=int,
			   help="Set numerical level of verbosity (0..4)"),
		Option("--verbose-date", "--VD", action='store_true',
			   help="Verbose date patterns/regex in output"),
		Option("-D", "--debuggex", action='store_true',
			   help="Produce debuggex.com urls for debugging there"),
		Option("--no-check-all", action="store_false", dest="checkAllRegex", default=True,
			   help="Disable check for all regex's"),
		Option("-o", "--out", action="store", dest="out", default=None,
			   help="Set token to print failure information only (row, id, ip, msg, host, ip4, ip6, dns, matches, ...)"),
		Option("--print-no-missed", action='store_true',
			   help="Do not print any missed lines"),
		Option("--print-no-ignored", action='store_true',
			   help="Do not print any ignored lines"),
		Option("--print-all-matched", action='store_true',
			   help="Print all matched lines"),
		Option("--print-all-missed", action='store_true',
			   help="Print all missed lines, no matter how many"),
		Option("--print-all-ignored", action='store_true',
			   help="Print all ignored lines, no matter how many"),
		Option("-t", "--log-traceback", action='store_true',
			   help="Enrich log-messages with compressed tracebacks"),
		Option("--full-traceback", action='store_true',
			   help="Either to make the tracebacks full, not compressed (as by default)"),
		])

	return p


class RegexStat(object):

	def __init__(self, failregex):
		self._stats = 0
		self._failregex = failregex
		self._ipList = list()

	def __str__(self):
		return "%s(%r) %d failed: %s" \
		  % (self.__class__, self._failregex, self._stats, self._ipList)

	def inc(self):
		self._stats += 1

	def getStats(self):
		return self._stats

	def getFailRegex(self):
		return self._failregex

	def appendIP(self, value):
		self._ipList.append(value)

	def getIPList(self):
		return self._ipList


class LineStats(object):
	"""Just a convenience container for stats
	"""
	def __init__(self, opts):
		self.tested = self.matched = 0
		self.matched_lines = []
		self.missed = 0
		self.missed_lines = []
		self.ignored = 0
		self.ignored_lines = []
		if opts.debuggex:
			self.matched_lines_timeextracted = []
			self.missed_lines_timeextracted = []
			self.ignored_lines_timeextracted = []

	def __str__(self):
		return "%(tested)d lines, %(ignored)d ignored, %(matched)d matched, %(missed)d missed" % self

	# just for convenient str
	def __getitem__(self, key):
		return getattr(self, key) if hasattr(self, key) else ''


class Fail2banRegex(object):

	def __init__(self, opts):
		# set local protected members from given options:
		self.__dict__.update(dict(('_'+o,v) for o,v in opts.__dict__.items()))
		self._opts = opts
		self._maxlines_set = False		  # so we allow to override maxlines in cmdline
		self._datepattern_set = False
		self._journalmatch = None

		self.share_config=dict()
		self._filter = Filter(None)
		self._prefREMatched = 0
		self._prefREGroups = list()
		self._ignoreregex = list()
		self._failregex = list()
		self._time_elapsed = None
		self._line_stats = LineStats(opts)

		if opts.maxlines:
			self.setMaxLines(opts.maxlines)
		else:
			self._maxlines = 20
		if opts.journalmatch is not None:
			self.setJournalMatch(shlex.split(opts.journalmatch))
		if opts.timezone:
			self._filter.setLogTimeZone(opts.timezone)
		self._filter.checkFindTime = False
		if True: # not opts.out:
			MyTime.setAlternateNow(0); # accept every date (years from 19xx up to end of current century, '%ExY' and 'Exy' patterns)
			from ..server.strptime import _updateTimeRE
			_updateTimeRE()
		if opts.datepattern:
			self.setDatePattern(opts.datepattern)
		if opts.usedns:
			self._filter.setUseDns(opts.usedns)
		self._filter.returnRawHost = opts.raw
		self._filter.checkAllRegex = opts.checkAllRegex and not opts.out
		# ignore pending (without ID/IP), added to matches if it hits later (if ID/IP can be retrieved)
		self._filter.ignorePending = bool(opts.out)
		# callback to increment ignored RE's by index (during process):
		self._filter.onIgnoreRegex = self._onIgnoreRegex
		self._backend = 'auto'

	def output(self, line):
		if not self._opts.out: output(line)

	def encode_line(self, line):
		return line.encode(self._encoding, 'ignore')

	def setDatePattern(self, pattern):
		if not self._datepattern_set:
			self._filter.setDatePattern(pattern)
			self._datepattern_set = True
			if pattern is not None:
				self.output( "Use      datepattern : %s : %s" % (
					pattern, self._filter.getDatePattern()[1], ) )

	def setMaxLines(self, v):
		if not self._maxlines_set:
			self._filter.setMaxLines(int(v))
			self._maxlines_set = True
			self.output( "Use         maxlines : %d" % self._filter.getMaxLines() )

	def setJournalMatch(self, v):
		self._journalmatch = v

	def _dumpRealOptions(self, reader, fltOpt):
		realopts = {}
		combopts = reader.getCombined()
		if isinstance(reader, FilterReader):
			_get_opt = lambda k: reader.get('Definition', k)
		elif reader.filter: # JailReader for jail with filter:
			_get_opt = lambda k: reader.filter.get('Definition', k)
		else: # JailReader for jail without filter:
			_get_opt = lambda k: None
		# output all options that are specified in filter-argument as well as some special (mostly interested):
		for k in ['logtype', 'datepattern'] + list(fltOpt.keys()):
			# combined options win, but they contain only a sub-set in filter expected keys,
			# so get the rest from definition section:
			try:
				realopts[k] = combopts[k] if k in combopts else _get_opt(k)
			except NoOptionError: # pragma: no cover
				pass
		self.output("Real  filter options : %r" % realopts)

	def readRegex(self, value, regextype):
		assert(regextype in ('fail', 'ignore'))
		regex = regextype + 'regex'
		# try to check - we've case filter?[options...]?:
		basedir = self._opts.config
		fltName = value
		fltFile = None
		fltOpt = {}
		jail = None
		if regextype == 'fail':
			if re.search(r'(?ms)^/{0,3}[\w/_\-.]+(?:\[.*\])?$', value):
				try:
					fltName, fltOpt = extractOptions(value)
					if re.search(r'(?ms)^[\w/_\-]+$', fltName): # name of jail?
						try:
							jail = JailReader(fltName, force_enable=True, 
								share_config=self.share_config, basedir=basedir)
							jail.read()
						except NoJailError:
							jail = None
					if "." in fltName[~5:]:
						tryNames = (fltName,)
					else:
						tryNames = (fltName, fltName + '.conf', fltName + '.local')
					for fltFile in tryNames:
						if os.path.dirname(fltFile) == 'filter.d':
							fltFile = os.path.join(basedir, fltFile)
						elif not "/" in fltFile:
							if os.path.basename(basedir) == 'filter.d':
								fltFile = os.path.join(basedir, fltFile)
							else:
								fltFile = os.path.join(basedir, 'filter.d', fltFile)
						else:
							basedir = os.path.dirname(fltFile)
						if os.path.isfile(fltFile):
							break
						fltFile = None
				except Exception as e:
					output("ERROR: Wrong filter name or options: %s" % (str(e),))
					output("       while parsing: %s" % (value,))
					if self._verbose: raise(e)
					return False
		
		readercommands = None
		# if it is jail:
		if jail:
			self.output( "Use %11s jail : %s" % ('', fltName) )
			if fltOpt:
				self.output( "Use jail/flt options : %r" % fltOpt )
			if not fltOpt: fltOpt = {}
			fltOpt['backend'] = self._backend
			ret = jail.getOptions(addOpts=fltOpt)
			if not ret:
				output('ERROR: Failed to get jail for %r' % (value,))
				return False
			# show real options if expected:
			if self._verbose > 1 or logSys.getEffectiveLevel()<=logging.DEBUG:
				self._dumpRealOptions(jail, fltOpt)
			readercommands = jail.convert(allow_no_files=True)
		# if it is filter file:
		elif fltFile is not None:
			if (basedir == self._opts.config
				or os.path.basename(basedir) == 'filter.d'
				or ("." not in fltName[~5:] and "/" not in fltName)
			):
				## within filter.d folder - use standard loading algorithm to load filter completely (with .local etc.):
				if os.path.basename(basedir) == 'filter.d':
					basedir = os.path.dirname(basedir)
				fltName = os.path.splitext(os.path.basename(fltName))[0]
				self.output( "Use %11s file : %s, basedir: %s" % ('filter', fltName, basedir) )
			else:
				## foreign file - readexplicit this file and includes if possible:
				self.output( "Use %11s file : %s" % ('filter', fltName) )
				basedir = None
				if not os.path.isabs(fltName): # avoid join with "filter.d" inside FilterReader
					fltName = os.path.abspath(fltName)
			if fltOpt:
				self.output( "Use   filter options : %r" % fltOpt )
			reader = FilterReader(fltName, 'fail2ban-regex-jail', fltOpt,
				share_config=self.share_config, basedir=basedir)
			ret = None
			try:
				if basedir is not None:
					ret = reader.read()
				else:
					## foreign file - readexplicit this file and includes if possible:
					reader.setBaseDir(None)
					ret = reader.readexplicit()
			except Exception as e:
				output("Wrong config file: %s" % (str(e),))
				if self._verbose: raise(e)
			if not ret:
				output( "ERROR: failed to load filter %s" % value )
				return False
			# set backend-related options (logtype):
			reader.applyAutoOptions(self._backend)
			# get, interpolate and convert options:
			reader.getOptions(None)
			# show real options if expected:
			if self._verbose > 1 or logSys.getEffectiveLevel()<=logging.DEBUG:
				self._dumpRealOptions(reader, fltOpt)
			# to stream:
			readercommands = reader.convert()

		if readercommands:
			regex_values = {}
			for opt in readercommands:
				if opt[0] == 'multi-set':
					optval = opt[3]
				elif opt[0] == 'set':
					optval = opt[3:]
				else: # pragma: no cover
					continue
				try:
					if opt[2] == "prefregex":
						for optval in optval:
							self._filter.prefRegex = optval
					elif opt[2] == "addfailregex":
						stor = regex_values.get('fail')
						if not stor: stor = regex_values['fail'] = list()
						for optval in optval:
							stor.append(RegexStat(optval))
							#self._filter.addFailRegex(optval)
					elif opt[2] == "addignoreregex":
						stor = regex_values.get('ignore')
						if not stor: stor = regex_values['ignore'] = list()
						for optval in optval:
							stor.append(RegexStat(optval))
							#self._filter.addIgnoreRegex(optval)
					elif opt[2] == "maxlines":
						for optval in optval:
							self.setMaxLines(optval)
					elif opt[2] == "datepattern":
						for optval in optval:
							self.setDatePattern(optval)
					elif opt[2] == "addjournalmatch": # pragma: no cover
						if self._opts.journalmatch is None:
							self.setJournalMatch(optval)
				except ValueError as e: # pragma: no cover
					output( "ERROR: Invalid value for %s (%r) " \
						  "read from %s: %s" % (opt[2], optval, value, e) )
					return False

		else:
			self.output( "Use %11s line : %s" % (regex, shortstr(value)) )
			regex_values = {regextype: [RegexStat(value)]}

		for regextype, regex_values in regex_values.items():
			regex = regextype + 'regex'
			setattr(self, "_" + regex, regex_values)
			for regex in regex_values:
				getattr(
					self._filter,
					'add%sRegex' % regextype.title())(regex.getFailRegex())
		return True

	def _onIgnoreRegex(self, idx, ignoreRegex):
		self._lineIgnored = True
		self._ignoreregex[idx].inc()

	def testRegex(self, line, date=None):
		orgLineBuffer = self._filter._Filter__lineBuffer
		# duplicate line buffer (list can be changed inplace during processLine):
		if self._filter.getMaxLines() > 1:
			orgLineBuffer = orgLineBuffer[:]
		fullBuffer = len(orgLineBuffer) >= self._filter.getMaxLines()
		is_ignored = self._lineIgnored = False
		try:
			found = self._filter.processLine(line, date)
			lines = []
			ret = []
			for match in found:
				if not self._opts.out:
					# Append True/False flag depending if line was matched by
					# more than one regex
					match.append(len(ret)>1)
					regex = self._failregex[match[0]]
					regex.inc()
					regex.appendIP(match)
				if not match[3].get('nofail'):
					ret.append(match)
				else:
					is_ignored = True
			if self._opts.out: # (formatted) output - don't need stats:
				return None, ret, None
			# prefregex stats:
			if self._filter.prefRegex:
				pre = self._filter.prefRegex
				if pre.hasMatched():
					self._prefREMatched += 1
					if self._verbose:
						if len(self._prefREGroups) < self._maxlines:
							self._prefREGroups.append(pre.getGroups())
						else:
							if len(self._prefREGroups) == self._maxlines:
								self._prefREGroups.append('...')
		except RegexException as e: # pragma: no cover
			output( 'ERROR: %s' % e )
			return None, 0, None
		if self._filter.getMaxLines() > 1:
			for bufLine in orgLineBuffer[int(fullBuffer):]:
				if bufLine not in self._filter._Filter__lineBuffer:
					try:
						self._line_stats.missed_lines.pop(
							self._line_stats.missed_lines.index("".join(bufLine)))
						if self._debuggex:
							self._line_stats.missed_lines_timeextracted.pop(
								self._line_stats.missed_lines_timeextracted.index(
									"".join(bufLine[::2])))
					except ValueError:
						pass
					# if buffering - add also another lines from match:
					if self._print_all_matched:
						if not self._debuggex:
							self._line_stats.matched_lines.append("".join(bufLine))
						else:
							lines.append(bufLine[0] + bufLine[2])
					self._line_stats.matched += 1
					self._line_stats.missed -= 1
		if lines: # pre-lines parsed in multiline mode (buffering)
			lines.append(self._filter.processedLine())
			line = "\n".join(lines)
		return line, ret, (is_ignored or self._lineIgnored)

	def _prepaireOutput(self):
		"""Prepares output- and fetch-function corresponding given '--out' option (format)"""
		ofmt = self._opts.out
		if ofmt in ('id', 'fid'):
			def _out(ret):
				for r in ret:
					output(r[1])
		elif ofmt == 'ip':
			def _out(ret):
				for r in ret:
					output(r[3].get('ip', r[1]))
		elif ofmt == 'msg':
			def _out(ret):
				for r in ret:
					for r in r[3].get('matches'):
						if not isinstance(r, str):
							r = ''.join(r for r in r)
						output(r)
		elif ofmt == 'row':
			def _out(ret):
				for r in ret:
					output('[%r,\t%r,\t%r],' % (r[1],r[2],dict((k,v) for k, v in r[3].items() if k != 'matches')))
		elif '<' not in ofmt:
			def _out(ret):
				for r in ret:
					output(r[3].get(ofmt))
		else: # extended format with tags substitution:
			from ..server.actions import Actions, CommandAction, BanTicket
			def _escOut(t, v):
				# use safe escape (avoid inject on pseudo tag "\x00msg\x00"):
				if t not in ('msg',):
					return v.replace('\x00', '\\x00')
				return v
			def _out(ret):
				rows = []
				wrap = {'NL':0}
				for r in ret:
					ticket = BanTicket(r[1], time=r[2], data=r[3])
					aInfo = Actions.ActionInfo(ticket)
					# if msg tag is used - output if single line (otherwise let it as is to wrap multilines later):
					def _get_msg(self):
						if not wrap['NL'] and len(r[3].get('matches', [])) <= 1:
							return self['matches']
						else: # pseudo tag for future replacement:
							wrap['NL'] = 1
							return "\x00msg\x00"
					aInfo['msg'] = _get_msg
					# not recursive interpolation (use safe escape):
					v = CommandAction.replaceDynamicTags(ofmt, aInfo, escapeVal=_escOut)
					if wrap['NL']: # contains multiline tags (msg):
						rows.append((r, v))
						continue
					output(v)
				# wrap multiline tag (msg) interpolations to single line:
				for r, v in rows:
					for r in r[3].get('matches'):
						if not isinstance(r, str):
							r = ''.join(r for r in r)
						r = v.replace("\x00msg\x00", r)
						output(r)
		return _out


	def process(self, test_lines):
		t0 = time.time()
		if self._opts.out: # get out function
			out = self._prepaireOutput()
		for line in test_lines:
			if isinstance(line, tuple):
				line_datetimestripped, ret, is_ignored = self.testRegex(line[0], line[1])
				line = "".join(line[0])
			else:
				line = line.rstrip('\r\n')
				if line.startswith('#') or not line:
					# skip comment and empty lines
					continue
				line_datetimestripped, ret, is_ignored = self.testRegex(line)

			if self._opts.out: # (formatted) output:
				if len(ret) > 0 and not is_ignored: out(ret)
				continue

			if is_ignored:
				self._line_stats.ignored += 1
				if not self._print_no_ignored and (self._print_all_ignored or self._line_stats.ignored <= self._maxlines + 1):
					self._line_stats.ignored_lines.append(line)
					if self._debuggex:
						self._line_stats.ignored_lines_timeextracted.append(line_datetimestripped)
			elif len(ret) > 0:
				self._line_stats.matched += 1
				if self._print_all_matched:
					self._line_stats.matched_lines.append(line)
					if self._debuggex:
						self._line_stats.matched_lines_timeextracted.append(line_datetimestripped)
			else:
				self._line_stats.missed += 1
				if not self._print_no_missed and (self._print_all_missed or self._line_stats.missed <= self._maxlines + 1):
					self._line_stats.missed_lines.append(line)
					if self._debuggex:
						self._line_stats.missed_lines_timeextracted.append(line_datetimestripped)
			self._line_stats.tested += 1

		self._time_elapsed = time.time() - t0

	def printLines(self, ltype):
		lstats = self._line_stats
		assert(lstats.missed == lstats.tested - (lstats.matched + lstats.ignored))
		lines = lstats[ltype]
		l = lstats[ltype + '_lines']
		multiline = self._filter.getMaxLines() > 1
		if lines:
			header = "%s line(s):" % (ltype.capitalize(),)
			if self._debuggex:
				if ltype == 'missed' or ltype == 'matched':
					regexlist = self._failregex
				else:
					regexlist = self._ignoreregex
				l = lstats[ltype + '_lines_timeextracted']
				if lines < self._maxlines or getattr(self, '_print_all_' + ltype):
					ans = [[]]
					for arg in [l, regexlist]:
						ans = [ x + [y] for x in ans for y in arg ]
					b = [a[0] +  ' | ' + a[1].getFailRegex() + ' |  ' + 
						debuggexURL(self.encode_line(a[0]), a[1].getFailRegex(), 
							multiline, self._opts.usedns) for a in ans]
					pprint_list([x.rstrip() for x in b], header)
				else:
					output( "%s too many to print.  Use --print-all-%s " \
						  "to print all %d lines" % (header, ltype, lines) )
			elif lines < self._maxlines or getattr(self, '_print_all_' + ltype):
				pprint_list([x.rstrip() for x in l], header)
			else:
				output( "%s too many to print.  Use --print-all-%s " \
					  "to print all %d lines" % (header, ltype, lines) )

	def printStats(self):
		if self._opts.out: return True
		output( "" )
		output( "Results" )
		output( "=======" )

		def print_failregexes(title, failregexes):
			# Print title
			total, out = 0, []
			for cnt, failregex in enumerate(failregexes):
				match = failregex.getStats()
				total += match
				if (match or self._verbose):
					out.append("%2d) [%d] %s" % (cnt+1, match, failregex.getFailRegex()))

				if self._verbose and len(failregex.getIPList()):
					for ip in failregex.getIPList():
						timeTuple = time.localtime(ip[2])
						timeString = time.strftime("%a %b %d %H:%M:%S %Y", timeTuple)
						out.append(
							"    %s  %s%s" % (
								ip[1],
								timeString,
								ip[-1] and " (multiple regex matched)" or ""))

			output( "\n%s: %d total" % (title, total) )
			pprint_list(out, " #) [# of hits] regular expression")
			return total

		# Print prefregex:
		if self._filter.prefRegex:
			#self._filter.prefRegex.hasMatched()
			pre = self._filter.prefRegex 
			out = [pre.getRegex()]
			if self._verbose:
				for grp in self._prefREGroups:
					out.append("    %s" % (grp,))
			output( "\n%s: %d total" % ("Prefregex", self._prefREMatched) )
			pprint_list(out)

		# Print regex's:
		total = print_failregexes("Failregex", self._failregex)
		_ = print_failregexes("Ignoreregex", self._ignoreregex)


		if self._filter.dateDetector is not None:
			output( "\nDate template hits:" )
			out = []
			for template in self._filter.dateDetector.templates:
				if self._verbose or template.hits:
					out.append("[%d] %s" % (template.hits, template.name))
					if self._verbose_date:
						out.append("    # weight: %.3f (%.3f), pattern: %s" % (
							template.weight, template.template.weight,
							getattr(template, 'pattern', ''),))
						out.append("    # regex:   %s" % (getattr(template, 'regex', ''),))
			pprint_list(out, "[# of hits] date format")

		output( "\nLines: %s" % self._line_stats, )
		if self._time_elapsed is not None:
			output( "[processed in %.2f sec]" % self._time_elapsed, )
		output( "" )

		if self._print_all_matched:
			self.printLines('matched')
		if not self._print_no_ignored:
			self.printLines('ignored')
		if not self._print_no_missed:
			self.printLines('missed')

		return True

	def start(self, args):

		cmd_log, cmd_regex = args[:2]

		if cmd_log.startswith("systemd-journal"): # pragma: no cover
			self._backend = 'systemd'

		try:
			if not self.readRegex(cmd_regex, 'fail'): # pragma: no cover
				return False
			if len(args) == 3 and not self.readRegex(args[2], 'ignore'): # pragma: no cover
				return False
		except RegexException as e:
			output( 'ERROR: %s' % e )
			return False

		if os.path.isfile(cmd_log):
			try:
				test_lines = FileContainer(cmd_log, self._encoding, doOpen=True)

				self.output( "Use         log file : %s" % cmd_log )
				self.output( "Use         encoding : %s" % self._encoding )
			except IOError as e: # pragma: no cover
				output( e )
				return False
		elif cmd_log.startswith("systemd-journal"): # pragma: no cover
			if not FilterSystemd:
				output( "Error: systemd library not found. Exiting..." )
				return False
			self.output( "Use         systemd journal" )
			self.output( "Use         encoding : %s" % self._encoding )
			backend, beArgs = extractOptions(cmd_log)
			flt = FilterSystemd(None, **beArgs)
			flt.setLogEncoding(self._encoding)
			myjournal = flt.getJournalReader()
			journalmatch = self._journalmatch
			self.setDatePattern(None)
			if journalmatch:
				flt.addJournalMatch(journalmatch)
				self.output( "Use    journal match : %s" % " ".join(journalmatch) )
			test_lines = journal_lines_gen(flt, myjournal)
		else:
			# if single line parsing (without buffering)
			if self._filter.getMaxLines() <= 1 and '\n' not in cmd_log:
				self.output( "Use      single line : %s" % shortstr(cmd_log.replace("\n", r"\n")) )
				test_lines = [ cmd_log ]
			else: # multi line parsing (with and without buffering)
				test_lines = cmd_log.split("\n")
				self.output( "Use      multi line : %s line(s)" % len(test_lines) )
				for i, l in enumerate(test_lines):
					if i >= 5:
						self.output( "| ..." ); break
					self.output( "| %2.2s: %s" % (i+1, shortstr(l)) )
				self.output( "`-" )
			
		self.output( "" )

		self.process(test_lines)

		if not self.printStats():
			return False

		return True


def _loc_except_hook(exctype, value, traceback):
	if (exctype != BrokenPipeError and exctype != IOError or value.errno != 32):
		return sys.__excepthook__(exctype, value, traceback)
	# pipe seems to be closed (head / tail / etc), thus simply exit:
	sys.exit(0)

def exec_command_line(*args):
	sys.excepthook = _loc_except_hook; # stop on closed/broken pipe

	logging.exitOnIOError = True
	parser = get_opt_parser()
	(opts, args) = parser.parse_args(*args)
	errors = []
	if opts.print_no_missed and opts.print_all_missed: # pragma: no cover
		errors.append("ERROR: --print-no-missed and --print-all-missed are mutually exclusive.")
	if opts.print_no_ignored and opts.print_all_ignored: # pragma: no cover
		errors.append("ERROR: --print-no-ignored and --print-all-ignored are mutually exclusive.")

	# We need 2 or 3 parameters
	if not len(args) in (2, 3):
		errors.append("ERROR: provide both <LOG> and <REGEX>.")
	if errors:
		parser.print_help()
		sys.stderr.write("\n" + "\n".join(errors) + "\n")
		sys.exit(255)

	if not opts.out:
		output( "" )
		output( "Running tests" )
		output( "=============" )
		output( "" )

	# Log level (default critical):
	opts.log_level = str2LogLevel(opts.log_level)
	logSys.setLevel(opts.log_level)

	# Add the default logging handler
	stdout = logging.StreamHandler(sys.stdout)

	fmt = '%(levelname)-1.1s: %(message)s' if opts.verbose <= 1 else ' %(message)s'

	if opts.log_traceback:
		Formatter = FormatterWithTraceBack
		fmt = (opts.full_traceback and ' %(tb)s' or ' %(tbc)s') + fmt
	else:
		Formatter = logging.Formatter

	# Custom log format for the verbose tests runs
	stdout.setFormatter(Formatter(getVerbosityFormat(opts.verbose, fmt)))
	logSys.addHandler(stdout)

	try:
		fail2banRegex = Fail2banRegex(opts)
	except Exception as e:
		if opts.verbose or logSys.getEffectiveLevel()<=logging.DEBUG:
			logSys.critical(e, exc_info=True)
		else:
			output( 'ERROR: %s' % e )
		sys.exit(255)

	if not fail2banRegex.start(args):
		sys.exit(255)
