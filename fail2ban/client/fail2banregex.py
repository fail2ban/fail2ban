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
__copyright__ = "Copyright (c) 2004-2008 Cyril Jaquier, 2012-2014 Yaroslav Halchenko"
__license__ = "GPL"

import getopt
import logging
import os
import shlex
import sys
import time
import time
import urllib
from optparse import OptionParser, Option

from ConfigParser import NoOptionError, NoSectionError, MissingSectionHeaderError

try: # pragma: no cover
	from ..server.filtersystemd import FilterSystemd
except ImportError:
	FilterSystemd = None

from ..version import version
from .jailreader import JailReader
from .filterreader import FilterReader
from ..server.filter import Filter, FileContainer
from ..server.failregex import Regex, RegexException

from ..helpers import str2LogLevel, getVerbosityFormat, FormatterWithTraceBack, getLogger, PREFER_ENC
# Gets the instance of the logger.
logSys = getLogger("fail2ban")

def debuggexURL(sample, regex, multiline=False, useDns="yes"):
	args = {
		're': Regex._resolveHostTag(regex, useDns=useDns),
		'str': sample,
		'flavor': 'python'
	}
	if multiline: args['flags'] = 'm'
	return 'https://www.debuggex.com/?' + urllib.urlencode(args)

def output(args): # pragma: no cover (overriden in test-cases)
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

def get_opt_parser():
	# use module docstring for help output
	p = OptionParser(
				usage="%s [OPTIONS] <LOG> <REGEX> [IGNOREREGEX]\n" % sys.argv[0] + __doc__
				+ """
LOG:
    string                  a string representing a log line
    filename                path to a log file (/var/log/auth.log)
    "systemd-journal"       search systemd journal (systemd-python required)

REGEX:
    string                  a string representing a 'failregex'
    filename                path to a filter file (filter.d/sshd.conf)

IGNOREREGEX:
    string                  a string representing an 'ignoreregex'
    filename                path to a filter file (filter.d/sshd.conf)

Copyright (c) 2004-2008 Cyril Jaquier, 2008- Fail2Ban Contributors
Copyright of modifications held by their respective authors.
Licensed under the GNU General Public License v2 (GPL).

Written by Cyril Jaquier <cyril.jaquier@fail2ban.org>.
Many contributions by Yaroslav O. Halchenko and Steven Hiscocks.

Report bugs to https://github.com/fail2ban/fail2ban/issues
""",
				version="%prog " + version)

	p.add_options([
		Option("-c", "--config", default='/etc/fail2ban',
			   help="set alternate config directory"),
		Option("-d", "--datepattern",
			   help="set custom pattern used to match date/times"),
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
		Option('-v', '--verbose', action="count", dest="verbose",
			   default=0,
			   help="Increase verbosity"),
		Option("--verbosity", action="store", dest="verbose", type=int,
			   help="Set numerical level of verbosity (0..4)"),
		Option("--verbose-date", "--VD", action='store_true',
			   help="Verbose date patterns/regex in output"),
		Option("-D", "--debuggex", action='store_true',
			   help="Produce debuggex.com urls for debugging there"),
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
		# set local protected memebers from given options:
		self.__dict__.update(dict(('_'+o,v) for o,v in opts.__dict__.iteritems()))
		self._maxlines_set = False		  # so we allow to override maxlines in cmdline
		self._datepattern_set = False
		self._journalmatch = None

		self.share_config=dict()
		self._filter = Filter(None)
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
		if opts.datepattern:
			self.setDatePattern(opts.datepattern)
		if opts.usedns:
			self._filter.setUseDns(opts.usedns)
		self._filter.returnRawHost = opts.raw
		self._filter.checkFindTime = False
		self._filter.checkAllRegex = True
		self._opts = opts

	def decode_line(self, line):
		return FileContainer.decode_line('<LOG>', self._encoding, line)

	def encode_line(self, line):
		return line.encode(self._encoding, 'ignore')

	def setDatePattern(self, pattern):
		if not self._datepattern_set:
			self._filter.setDatePattern(pattern)
			self._datepattern_set = True
			if pattern is not None:
				output( "Use      datepattern : %s" % (
					self._filter.getDatePattern()[1], ) )

	def setMaxLines(self, v):
		if not self._maxlines_set:
			self._filter.setMaxLines(int(v))
			self._maxlines_set = True
			output( "Use         maxlines : %d" % self._filter.getMaxLines() )

	def setJournalMatch(self, v):
		self._journalmatch = v

	def readRegex(self, value, regextype):
		assert(regextype in ('fail', 'ignore'))
		regex = regextype + 'regex'
		# try to check - we've case filter?[options...]?:
		basedir = self._opts.config
		fltFile = None
		fltOpt = {}
		if regextype == 'fail':
			fltName, fltOpt = JailReader.extractOptions(value)
			if fltName is not None:
				if "." in fltName[~5:]:
					tryNames = (fltName,)
				else:
					tryNames = (fltName, fltName + '.conf', fltName + '.local')
				for fltFile in tryNames:
					if not "/" in fltFile:
						if os.path.basename(basedir) == 'filter.d':
							fltFile = os.path.join(basedir, fltFile)
						else:
							fltFile = os.path.join(basedir, 'filter.d', fltFile)
					else:
						basedir = os.path.dirname(fltFile)
					if os.path.isfile(fltFile):
						break
					fltFile = None
		# if it is filter file:
		if fltFile is not None:
			if (basedir == self._opts.config
				or os.path.basename(basedir) == 'filter.d'
				or ("." not in fltName[~5:] and "/" not in fltName)
			):
				## within filter.d folder - use standard loading algorithm to load filter completely (with .local etc.):
				if os.path.basename(basedir) == 'filter.d':
					basedir = os.path.dirname(basedir)
				fltName = os.path.splitext(os.path.basename(fltName))[0]
				output( "Use %11s filter file : %s, basedir: %s" % (regex, fltName, basedir) )
			else:
				## foreign file - readexplicit this file and includes if possible:
				output( "Use %11s file : %s" % (regex, fltName) )
				basedir = None
			if fltOpt:
				output( "Use   filter options : %r" % fltOpt )
			reader = FilterReader(fltName, 'fail2ban-regex-jail', fltOpt, share_config=self.share_config, basedir=basedir)
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
			reader.getOptions(None)
			readercommands = reader.convert()

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
			output( "Use %11s line : %s" % (regex, shortstr(value)) )
			regex_values = {regextype: [RegexStat(value)]}

		for regextype, regex_values in regex_values.iteritems():
			regex = regextype + 'regex'
			setattr(self, "_" + regex, regex_values)
			for regex in regex_values:
				getattr(
					self._filter,
					'add%sRegex' % regextype.title())(regex.getFailRegex())
		return True

	def testIgnoreRegex(self, line):
		found = False
		try:
			ret = self._filter.ignoreLine([(line, "", "")])
			if ret is not None:
				found = True
				regex = self._ignoreregex[ret].inc()
		except RegexException as e: # pragma: no cover
			output( 'ERROR: %s' % e )
			return False
		return found

	def testRegex(self, line, date=None):
		orgLineBuffer = self._filter._Filter__lineBuffer
		fullBuffer = len(orgLineBuffer) >= self._filter.getMaxLines()
		try:
			ret = self._filter.processLine(line, date)
			lines = []
			line = self._filter.processedLine()
			for match in ret:
				# Append True/False flag depending if line was matched by
				# more than one regex
				match.append(len(ret)>1)
				regex = self._failregex[match[0]]
				regex.inc()
				regex.appendIP(match)
		except RegexException as e: # pragma: no cover
			output( 'ERROR: %s' % e )
			return False
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
			lines.append(line)
			line = "\n".join(lines)
		return line, ret

	def process(self, test_lines):
		t0 = time.time()
		for line in test_lines:
			if isinstance(line, tuple):
				line_datetimestripped, ret = self.testRegex(
					line[0], line[1])
				line = "".join(line[0])
			else:
				line = line.rstrip('\r\n')
				if line.startswith('#') or not line:
					# skip comment and empty lines
					continue
				line_datetimestripped, ret = self.testRegex(line)
			is_ignored = self.testIgnoreRegex(line_datetimestripped)

			if is_ignored:
				self._line_stats.ignored += 1
				if not self._print_no_ignored and (self._print_all_ignored or self._line_stats.ignored <= self._maxlines + 1):
					self._line_stats.ignored_lines.append(line)
					if self._debuggex:
						self._line_stats.ignored_lines_timeextracted.append(line_datetimestripped)

			if len(ret) > 0:
				assert(not is_ignored)
				self._line_stats.matched += 1
				if self._print_all_matched:
					self._line_stats.matched_lines.append(line)
					if self._debuggex:
						self._line_stats.matched_lines_timeextracted.append(line_datetimestripped)
			else:
				if not is_ignored:
					self._line_stats.missed += 1
					if not self._print_no_missed and (self._print_all_missed or self._line_stats.missed <= self._maxlines + 1):
						self._line_stats.missed_lines.append(line)
						if self._debuggex:
							self._line_stats.missed_lines_timeextracted.append(line_datetimestripped)
			self._line_stats.tested += 1

		self._time_elapsed = time.time() - t0

	def printLines(self, ltype):
		lstats = self._line_stats
		assert(self._line_stats.missed == lstats.tested - (lstats.matched + lstats.ignored))
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
					b = map(lambda a: a[0] +  ' | ' + a[1].getFailRegex() + ' |  ' + 
						debuggexURL(self.encode_line(a[0]), a[1].getFailRegex(), 
							multiline, self._opts.usedns), ans)
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

		# Print title
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

	def file_lines_gen(self, hdlr):
		for line in hdlr:
			yield self.decode_line(line)

	def start(self, args):

		cmd_log, cmd_regex = args[:2]

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
				hdlr = open(cmd_log, 'rb')
				output( "Use         log file : %s" % cmd_log )
				output( "Use         encoding : %s" % self._encoding )
				test_lines = self.file_lines_gen(hdlr)
			except IOError as e: # pragma: no cover
				output( e )
				return False
		elif cmd_log.startswith("systemd-journal"): # pragma: no cover
			if not FilterSystemd:
				output( "Error: systemd library not found. Exiting..." )
				return False
			output( "Use         systemd journal" )
			output( "Use         encoding : %s" % self._encoding )
			backend, beArgs = JailReader.extractOptions(cmd_log)
			flt = FilterSystemd(None, **beArgs)
			flt.setLogEncoding(self._encoding)
			myjournal = flt.getJournalReader()
			journalmatch = self._journalmatch
			self.setDatePattern(None)
			if journalmatch:
				flt.addJournalMatch(journalmatch)
			output( "Use    journal match : %s" % " ".join(journalmatch) )
			test_lines = journal_lines_gen(flt, myjournal)
		else:
			# if single line parsing (without buffering)
			if self._filter.getMaxLines() <= 1:
				output( "Use      single line : %s" % shortstr(cmd_log.replace("\n", r"\n")) )
				test_lines = [ cmd_log ]
			else: # multi line parsing (with buffering)
				test_lines = cmd_log.split("\n")
				output( "Use      multi line : %s line(s)" % len(test_lines) )
				for i, l in enumerate(test_lines):
					if i >= 5:
						output( "| ..." ); break
					output( "| %2.2s: %s" % (i+1, shortstr(l)) )
				output( "`-" )
			
		output( "" )

		self.process(test_lines)

		if not self.printStats():
			return False

		return True


def exec_command_line(*args):
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
		sys.stderr.write("\n".join(errors) + "\n\n")
		parser.print_help()
		sys.exit(-1)

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

	fail2banRegex = Fail2banRegex(opts)
	if not fail2banRegex.start(args):
		sys.exit(-1)
