#!/usr/bin/python
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
import locale
import logging
import os
import shlex
import sys
import time
import time
import urllib
from optparse import OptionParser, Option

from ConfigParser import NoOptionError, NoSectionError, MissingSectionHeaderError

try:
	from systemd import journal
	from ..server.filtersystemd import FilterSystemd
except ImportError:
	journal = None

from ..version import version
from .filterreader import FilterReader
from ..server.filter import Filter, FileContainer
from ..server.failregex import RegexException

from ..helpers import FormatterWithTraceBack, getLogger
# Gets the instance of the logger.
logSys = getLogger("fail2ban")

def debuggexURL(sample, regex):
	q = urllib.urlencode({ 're': regex.replace('<HOST>', '(?&.ipv4)'),
							'str': sample,
							'flavor': 'python' })
	return 'http://www.debuggex.com/?' + q

def output(args):
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

def journal_lines_gen(myjournal):
	while True:
		try:
			entry = myjournal.get_next()
		except OSError:
			continue
		if not entry:
			break
		yield FilterSystemd.formatJournalEntry(entry)

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
		Option("-d", "--datepattern",
			   help="set custom pattern used to match date/times"),
		Option("-e", "--encoding",
			   help="File encoding. Default: system locale"),
		Option("-L", "--maxlines", type=int, default=0,
			   help="maxlines for multi-line regex"),
		Option("-m", "--journalmatch",
			   help="journalctl style matches overriding filter file. "
			   "\"systemd-journal\" only"),
		Option('-l', "--log-level", type="choice",
			   dest="log_level",
			   choices=('heavydebug', 'debug', 'info', 'notice', 'warning', 'error', 'critical'),
			   default=None,
			   help="Log level for the Fail2Ban logger to use"),
		Option("-v", "--verbose", action='store_true',
			   help="Be verbose in output"),
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
	def __init__(self):
		self.tested = self.matched = 0
		self.matched_lines = []
		self.missed = 0
		self.missed_lines = []
		self.missed_lines_timeextracted = []
		self.ignored = 0
		self.ignored_lines = []
		self.ignored_lines_timeextracted = []

	def __str__(self):
		return "%(tested)d lines, %(ignored)d ignored, %(matched)d matched, %(missed)d missed" % self

	# just for convenient str
	def __getitem__(self, key):
		return getattr(self, key) if hasattr(self, key) else ''


class Fail2banRegex(object):

	def __init__(self, opts):
		self._verbose = opts.verbose
		self._debuggex = opts.debuggex
		self._maxlines = 20
		self._print_no_missed = opts.print_no_missed
		self._print_no_ignored = opts.print_no_ignored
		self._print_all_matched = opts.print_all_matched
		self._print_all_missed = opts.print_all_missed
		self._print_all_ignored = opts.print_all_ignored
		self._maxlines_set = False		  # so we allow to override maxlines in cmdline
		self._datepattern_set = False
		self._journalmatch = None

		self.share_config=dict()
		self._filter = Filter(None)
		self._ignoreregex = list()
		self._failregex = list()
		self._time_elapsed = None
		self._line_stats = LineStats()

		if opts.maxlines:
			self.setMaxLines(opts.maxlines)
		if opts.journalmatch is not None:
			self.setJournalMatch(opts.journalmatch.split())
		if opts.datepattern:
			self.setDatePattern(opts.datepattern)
		if opts.encoding:
			self.encoding = opts.encoding
		else:
			self.encoding = locale.getpreferredencoding()

	def decode_line(self, line):
		return FileContainer.decode_line('<LOG>', self.encoding, line)

	def encode_line(self, line):
		return line.encode(self.encoding, 'ignore')

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
		if self._journalmatch is None:
			self._journalmatch = v

	def readRegex(self, value, regextype):
		assert(regextype in ('fail', 'ignore'))
		regex = regextype + 'regex'
		if os.path.isfile(value) or os.path.isfile(value + '.conf'):
			if os.path.basename(os.path.dirname(value)) == 'filter.d':
				## within filter.d folder - use standard loading algorithm to load filter completely (with .local etc.):
				basedir = os.path.dirname(os.path.dirname(value))
				value = os.path.splitext(os.path.basename(value))[0]
				output( "Use %11s filter file : %s, basedir: %s" % (regex, value, basedir) )
				reader = FilterReader(value, 'fail2ban-regex-jail', {}, share_config=self.share_config, basedir=basedir)
				if not reader.read():
					output( "ERROR: failed to load filter %s" % value )
					return False
			else:
				## foreign file - readexplicit this file and includes if possible:
				output( "Use %11s file : %s" % (regex, value) )
				reader = FilterReader(value, 'fail2ban-regex-jail', {}, share_config=self.share_config)
				reader.setBaseDir(None)
				if not reader.readexplicit():
					output( "ERROR: failed to read %s" % value )
					return False
			reader.getOptions(None)
			readercommands = reader.convert()
			regex_values = [
				RegexStat(m[3])
				for m in filter(
					lambda x: x[0] == 'set' and x[2] == "add%sregex" % regextype,
					readercommands)]
			# Read out and set possible value of maxlines
			for command in readercommands:
				if command[2] == "maxlines":
					maxlines = int(command[3])
					try:
						self.setMaxLines(maxlines)
					except ValueError:
						output( "ERROR: Invalid value for maxlines (%(maxlines)r) " \
							  "read from %(value)s" % locals() )
						return False
				elif command[2] == 'addjournalmatch':
					journalmatch = command[3:]
					self.setJournalMatch(journalmatch)
				elif command[2] == 'datepattern':
					datepattern = command[3]
					self.setDatePattern(datepattern)
		else:
			output( "Use %11s line : %s" % (regex, shortstr(value)) )
			regex_values = [RegexStat(value)]

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
		except RegexException, e:
			output( e )
			return False
		return found

	def testRegex(self, line, date=None):
		orgLineBuffer = self._filter._Filter__lineBuffer
		fullBuffer = len(orgLineBuffer) >= self._filter.getMaxLines()
		try:
			line, ret = self._filter.processLine(line, date, checkAllRegex=True)
			for match in ret:
				# Append True/False flag depending if line was matched by
				# more than one regex
				match.append(len(ret)>1)
				regex = self._failregex[match[0]]
				regex.inc()
				regex.appendIP(match)
		except RegexException, e:
			output( e )
			return False
		except IndexError:
			output( "Sorry, but no <HOST> found in regex" )
			return False
		for bufLine in orgLineBuffer[int(fullBuffer):]:
			if bufLine not in self._filter._Filter__lineBuffer:
				try:
					self._line_stats.missed_lines.pop(
						self._line_stats.missed_lines.index("".join(bufLine)))
					self._line_stats.missed_lines_timeextracted.pop(
						self._line_stats.missed_lines_timeextracted.index(
							"".join(bufLine[::2])))
				except ValueError:
					pass
				else:
					self._line_stats.matched += 1
					self._line_stats.missed -= 1
		return line, ret

	def process(self, test_lines):
		t0 = time.time()
		for line_no, line in enumerate(test_lines):
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
					self._line_stats.ignored_lines_timeextracted.append(line_datetimestripped)

			if len(ret) > 0:
				assert(not is_ignored)
				self._line_stats.matched += 1
				if self._print_all_matched:
					self._line_stats.matched_lines.append(line)
			else:
				if not is_ignored:
					self._line_stats.missed += 1
					if not self._print_no_missed and (self._print_all_missed or self._line_stats.missed <= self._maxlines + 1):
						self._line_stats.missed_lines.append(line)
						self._line_stats.missed_lines_timeextracted.append(line_datetimestripped)
			self._line_stats.tested += 1

			if line_no % 10 == 0 and self._filter.dateDetector is not None:
				self._filter.dateDetector.sortTemplate()
		self._time_elapsed = time.time() - t0

	def printLines(self, ltype):
		lstats = self._line_stats
		assert(self._line_stats.missed == lstats.tested - (lstats.matched + lstats.ignored))
		lines = lstats[ltype]
		l = lstats[ltype + '_lines']
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
						debuggexURL(self.encode_line(a[0]), a[1].getFailRegex()), ans)
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
					out.append("[%d] %s" % (
						template.hits, template.name))
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

	def start(self, opts, args):

		cmd_log, cmd_regex = args[:2]

		if not self.readRegex(cmd_regex, 'fail'):
			return False

		if len(args) == 3 and not self.readRegex(args[2], 'ignore'):
			return False

		if os.path.isfile(cmd_log):
			try:
				hdlr = open(cmd_log, 'rb')
				output( "Use         log file : %s" % cmd_log )
				output( "Use         encoding : %s" % self.encoding )
				test_lines = self.file_lines_gen(hdlr)
			except IOError, e:
				output( e )
				return False
		elif cmd_log == "systemd-journal": # pragma: no cover
			if not journal:
				output( "Error: systemd library not found. Exiting..." )
				return False
			myjournal = journal.Reader(converters={'__CURSOR': lambda x: x})
			journalmatch = self._journalmatch
			self.setDatePattern(None)
			if journalmatch:
				try:
					for element in journalmatch:
						if element == "+":
							myjournal.add_disjunction()
						else:
							myjournal.add_match(element)
				except ValueError:
					output( "Error: Invalid journalmatch: %s" % shortstr(" ".join(journalmatch)) )
					return False
			output( "Use    journal match : %s" % " ".join(journalmatch) )
			test_lines = journal_lines_gen(myjournal)
		else:
			output( "Use      single line : %s" % shortstr(cmd_log) )
			test_lines = [ cmd_log ]
		output( "" )

		self.process(test_lines)

		if not self.printStats():
			return False

		return True


def exec_command_line():
	parser = get_opt_parser()
	(opts, args) = parser.parse_args()
	if opts.print_no_missed and opts.print_all_missed:
		sys.stderr.write("ERROR: --print-no-missed and --print-all-missed are mutually exclusive.\n\n")
		parser.print_help()
		sys.exit(-1)
	if opts.print_no_ignored and opts.print_all_ignored:
		sys.stderr.write("ERROR: --print-no-ignored and --print-all-ignored are mutually exclusive.\n\n")
		parser.print_help()
		sys.exit(-1)

	# We need 2 or 3 parameters
	if not len(args) in (2, 3):
		sys.stderr.write("ERROR: provide both <LOG> and <REGEX>.\n\n")
		parser.print_help()
		return False

	output( "" )
	output( "Running tests" )
	output( "=============" )
	output( "" )

	# TODO: taken from -testcases -- move common functionality somewhere
	if opts.log_level is not None:
		# so we had explicit settings
		logSys.setLevel(getattr(logging, opts.log_level.upper()))
	else:
		# suppress the logging but it would leave unittests' progress dots
		# ticking, unless like with '-l critical' which would be silent
		# unless error occurs
		logSys.setLevel(getattr(logging, 'CRITICAL'))

	# Add the default logging handler
	stdout = logging.StreamHandler(sys.stdout)

	fmt = 'D: %(message)s'

	if opts.log_traceback:
		Formatter = FormatterWithTraceBack
		fmt = (opts.full_traceback and ' %(tb)s' or ' %(tbc)s') + fmt
	else:
		Formatter = logging.Formatter

	# Custom log format for the verbose tests runs
	if opts.verbose:
		stdout.setFormatter(Formatter(' %(asctime)-15s %(thread)s' + fmt))
	else:
		# just prefix with the space
		stdout.setFormatter(Formatter(fmt))
	logSys.addHandler(stdout)

	fail2banRegex = Fail2banRegex(opts)
	if not fail2banRegex.start(opts, args):
		sys.exit(-1)
