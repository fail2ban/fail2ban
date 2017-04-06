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


__author__ = "Yaroslav Halchenko"
__copyright__ = "Copyright (c) 2013 Yaroslav Halchenko"
__license__ = "GPL"

import itertools
import logging
import optparse
import os
import re
import tempfile
import shutil
import sys
import time
import threading
import unittest

from cStringIO import StringIO
from functools import wraps

from ..helpers import getLogger, str2LogLevel, getVerbosityFormat, uni_decode
from ..server.ipdns import DNSUtils
from ..server.mytime import MyTime
from ..server.utils import Utils
# for action_d.test_smtp :
from ..server import asyncserver
from ..version import version


logSys = getLogger(__name__)

TEST_NOW = 1124013600

CONFIG_DIR = os.environ.get('FAIL2BAN_CONFIG_DIR', None)

if not CONFIG_DIR:
# Use heuristic to figure out where configuration files are
	if os.path.exists(os.path.join('config','fail2ban.conf')):
		CONFIG_DIR = 'config'
	else:
		CONFIG_DIR = '/etc/fail2ban'

# During the test cases (or setup) use fail2ban modules from main directory:
os.putenv('PYTHONPATH', os.path.dirname(os.path.dirname(os.path.dirname(
	os.path.abspath(__file__)))))

# Default options, if running from installer (setup.py):
class DefaultTestOptions(optparse.Values):
	def __init__(self):
		self.__dict__ = {
			'log_level': None, 'verbosity': None, 'log_lazy': True, 
			'log_traceback': None, 'full_traceback': None,
			'fast': False, 'memory_db': False, 'no_gamin': False,
			'no_network': False, 'negate_re': False
		}

#
# Initialization
#
def getOptParser(doc=""):
	Option = optparse.Option
	# use module docstring for help output
	p = optparse.OptionParser(
				usage="%s [OPTIONS] [regexps]\n" % sys.argv[0] + doc,
				version="%prog " + version)

	p.add_options([
		Option('-l', "--log-level",
			   dest="log_level",
			   default=None,
			   help="Log level for the logger to use during running tests"),
		Option('-v', action="count", dest="verbosity",
			   default=None,
			   help="Increase verbosity"),
		Option("--verbosity", action="store", dest="verbosity", type=int,
			   default=None,
			   help="Set numerical level of verbosity (0..4)"),
		Option("--log-direct", action="store_false",
			   dest="log_lazy",
			   default=True,
			   help="Prevent lazy logging inside tests"),
		Option('-n', "--no-network", action="store_true",
			   dest="no_network",
			   help="Do not run tests that require the network"),
		Option('-g', "--no-gamin", action="store_true",
			   dest="no_gamin",
			   help="Do not run tests that require the gamin"),
		Option('-m', "--memory-db", action="store_true",
			   dest="memory_db",
			   help="Run database tests using memory instead of file"),
		Option('-f', "--fast", action="store_true",
			   dest="fast",
			   help="Try to increase speed of the tests, decreasing of wait intervals, memory database"),
		Option('-i', "--ignore", action="store_true",
			   dest="negate_re",
			   help="negate [regexps] filter to ignore tests matched specified regexps"),
		Option("-t", "--log-traceback", action='store_true',
			   help="Enrich log-messages with compressed tracebacks"),
		Option("--full-traceback", action='store_true',
			   help="Either to make the tracebacks full, not compressed (as by default)"),
		])
	return p

def initProcess(opts):
	# Logger:
	global logSys
	logSys = getLogger("fail2ban")

	llev = None
	if opts.log_level is not None: # pragma: no cover
		# so we had explicit settings
		llev = str2LogLevel(opts.log_level)
		logSys.setLevel(llev)
	else: # pragma: no cover
		# suppress the logging but it would leave unittests' progress dots
		# ticking, unless like with '-l critical' which would be silent
		# unless error occurs
		logSys.setLevel(logging.CRITICAL)
	opts.log_level = logSys.level

	# Numerical level of verbosity corresponding to a given log "level"
	verbosity = opts.verbosity
	if verbosity is None:
		verbosity = (
			1 if llev is None else \
			4 if llev <= logging.HEAVYDEBUG else \
			3 if llev <= logging.DEBUG else \
			2 if llev <= min(logging.INFO, logging.NOTICE) else \
			1 if llev <= min(logging.WARNING, logging.ERROR) else \
			0 # if llev <= logging.CRITICAL
		)
		opts.verbosity = verbosity

	# Add the default logging handler
	stdout = logging.StreamHandler(sys.stdout)

	fmt = ' %(message)s'

	if opts.log_traceback: # pragma: no cover
		from ..helpers import FormatterWithTraceBack as Formatter
		fmt = (opts.full_traceback and ' %(tb)s' or ' %(tbc)s') + fmt
	else:
		Formatter = logging.Formatter

	# Custom log format for the verbose tests runs
	fmt = getVerbosityFormat(verbosity, fmt)

	#
	stdout.setFormatter(Formatter(fmt))
	logSys.addHandler(stdout)

	# Let know the version
	if opts.verbosity != 0:
		print("Fail2ban %s test suite. Python %s. Please wait..." \
				% (version, str(sys.version).replace('\n', '')))

	return opts;


class F2B(DefaultTestOptions):
	def __init__(self, opts):
		self.__dict__ = opts.__dict__
		if self.fast:
			self.memory_db = True
			self.no_gamin = True
		self.__dict__['share_config'] = {}
	def SkipIfFast(self):
		pass
	def SkipIfNoNetwork(self):
		pass
	def maxWaitTime(self,wtime):
		if self.fast:
			wtime = float(wtime) / 10
		return wtime


def with_tmpdir(f):
	"""Helper decorator to create a temporary directory

	Directory gets removed after function returns, regardless
	if exception was thrown of not
	"""
	@wraps(f)
	def wrapper(self, *args, **kwargs):
		tmp = tempfile.mkdtemp(prefix="f2b-temp")
		try:
			return f(self, tmp, *args, **kwargs)
		finally:
			# clean up
			shutil.rmtree(tmp)
	return wrapper


# backwards compatibility to python 2.6:
if not hasattr(unittest, 'SkipTest'): # pragma: no cover
	class SkipTest(Exception):
		pass
	unittest.SkipTest = SkipTest
	_org_AddError = unittest._TextTestResult.addError
	def addError(self, test, err):
		if err[0] is SkipTest: 
			if self.showAll:
				self.stream.writeln(str(err[1]))
			elif self.dots:
				self.stream.write('s')
				self.stream.flush()
			return
		_org_AddError(self, test, err)
	unittest._TextTestResult.addError = addError

def initTests(opts):
	## if running from installer (setup.py):
	if not opts:
		opts = initProcess(DefaultTestOptions())
	unittest.F2B = F2B(opts)
	# --fast :
	if unittest.F2B.fast: # pragma: no cover
		# racy decrease default sleep intervals to test it faster 
		# (prevent long sleeping during test cases ... less time goes to sleep):
		Utils.DEFAULT_SLEEP_TIME = 0.0025
		Utils.DEFAULT_SLEEP_INTERVAL = 0.0005
		Utils.DEFAULT_SHORT_INTERVAL = 0.0001
		def F2B_SkipIfFast():
			raise unittest.SkipTest('Skip test because of "--fast"')
		unittest.F2B.SkipIfFast = F2B_SkipIfFast
	else:
		# smaller inertance inside test-cases (litle speedup):
		Utils.DEFAULT_SLEEP_TIME = 0.25
		Utils.DEFAULT_SLEEP_INTERVAL = 0.025
		Utils.DEFAULT_SHORT_INTERVAL = 0.0005
		# sleep intervals are large - use replacement for sleep to check time to sleep:
		_org_sleep = time.sleep
		def _new_sleep(v):
			if v > max(1, Utils.DEFAULT_SLEEP_TIME): # pragma: no cover
				raise ValueError('[BAD-CODE] To long sleep interval: %s, try to use conditional Utils.wait_for instead' % v)
			_org_sleep(min(v, Utils.DEFAULT_SLEEP_TIME))
		time.sleep = _new_sleep
	# --no-network :
	if unittest.F2B.no_network: # pragma: no cover
		def F2B_SkipIfNoNetwork():
			raise unittest.SkipTest('Skip test because of "--no-network"')
		unittest.F2B.SkipIfNoNetwork = F2B_SkipIfNoNetwork

	# persistently set time zone to CET (used in zone-related test-cases),
	# yoh: we need to adjust TZ to match the one used by Cyril so all the timestamps match
	os.environ['TZ'] = 'Europe/Zurich'
	time.tzset()
	# set alternate now for time related test cases:
	MyTime.setAlternateNow(TEST_NOW)

	# precache all invalid ip's (TEST-NET-1, ..., TEST-NET-3 according to RFC 5737):
	c = DNSUtils.CACHE_ipToName
	# increase max count and max time (too many entries, long time testing):
	c.setOptions(maxCount=10000, maxTime=5*60)
	for i in xrange(256):
		c.set('192.0.2.%s' % i, None)
		c.set('198.51.100.%s' % i, None)
		c.set('203.0.113.%s' % i, None)
		c.set('2001:db8::%s' %i, 'test-host')
	# some legal ips used in our test cases (prevent slow dns-resolving and failures if will be changed later):
	c.set('87.142.124.10', 'test-host')
	if unittest.F2B.no_network: # pragma: no cover
		# precache all wrong dns to ip's used in test cases:
		c = DNSUtils.CACHE_nameToIp
		for i in (
			('999.999.999.999', []),
			('abcdef.abcdef', []),
			('192.168.0.', []),
			('failed.dns.ch', []),
		):
			c.set(*i)


def mtimesleep():
	# no sleep now should be necessary since polling tracks now not only
	# mtime but also ino and size
	pass

old_TZ = os.environ.get('TZ', None)


def setUpMyTime():
	# Set the time to a fixed, known value
	# Sun Aug 14 12:00:00 CEST 2005
	MyTime.setTime(TEST_NOW)


def tearDownMyTime():
	MyTime.myTime = None


def gatherTests(regexps=None, opts=None):
	initTests(opts)
	# Import all the test cases here instead of a module level to
	# avoid circular imports
	from . import banmanagertestcase
	from . import clientbeautifiertestcase
	from . import clientreadertestcase
	from . import tickettestcase
	from . import failmanagertestcase
	from . import filtertestcase
	from . import servertestcase
	from . import datedetectortestcase
	from . import actiontestcase
	from . import actionstestcase
	from . import sockettestcase
	from . import misctestcase
	from . import databasetestcase
	from . import samplestestcase
	from . import fail2banclienttestcase
	from . import fail2banregextestcase

	if not regexps: # pragma: no cover
		tests = unittest.TestSuite()
	else: # pragma: no cover
		class FilteredTestSuite(unittest.TestSuite):
			_regexps = [re.compile(r) for r in regexps]

			def addTest(self, suite):
				matched = []
				for test in suite:
					# test of suite loaded with loadTestsFromName may be a suite self:
					if isinstance(test, unittest.TestSuite): # pragma: no cover
						self.addTest(test)
						continue
					# filter by regexp:
					s = str(test)
					for r in self._regexps:
						m = r.search(s)
						if (m if not opts.negate_re else not m):
							matched.append(test)
							break
				for test in matched:
					super(FilteredTestSuite, self).addTest(test)

		tests = FilteredTestSuite()

	# Server
	#tests.addTest(unittest.makeSuite(servertestcase.StartStop))
	tests.addTest(unittest.makeSuite(servertestcase.Transmitter))
	tests.addTest(unittest.makeSuite(servertestcase.JailTests))
	tests.addTest(unittest.makeSuite(servertestcase.RegexTests))
	tests.addTest(unittest.makeSuite(servertestcase.LoggingTests))
	tests.addTest(unittest.makeSuite(servertestcase.ServerConfigReaderTests))
	tests.addTest(unittest.makeSuite(actiontestcase.CommandActionTest))
	tests.addTest(unittest.makeSuite(actionstestcase.ExecuteActions))
	# Ticket, BanTicket, FailTicket
	tests.addTest(unittest.makeSuite(tickettestcase.TicketTests))
	# FailManager
	tests.addTest(unittest.makeSuite(failmanagertestcase.AddFailure))
	tests.addTest(unittest.makeSuite(failmanagertestcase.FailmanagerComplex))
	# BanManager
	tests.addTest(unittest.makeSuite(banmanagertestcase.AddFailure))
	try:
		import dns
		tests.addTest(unittest.makeSuite(banmanagertestcase.StatusExtendedCymruInfo))
	except ImportError: # pragma: no cover
		pass
	
	# ClientBeautifier
	tests.addTest(unittest.makeSuite(clientbeautifiertestcase.BeautifierTest))

	# ClientReaders
	tests.addTest(unittest.makeSuite(clientreadertestcase.ConfigReaderTest))
	tests.addTest(unittest.makeSuite(clientreadertestcase.JailReaderTest))
	tests.addTest(unittest.makeSuite(clientreadertestcase.FilterReaderTest))
	tests.addTest(unittest.makeSuite(clientreadertestcase.JailsReaderTest))
	tests.addTest(unittest.makeSuite(clientreadertestcase.JailsReaderTestCache))
	# CSocket and AsyncServer
	tests.addTest(unittest.makeSuite(sockettestcase.Socket))
	tests.addTest(unittest.makeSuite(sockettestcase.ClientMisc))
	# Misc helpers
	tests.addTest(unittest.makeSuite(misctestcase.HelpersTest))
	tests.addTest(unittest.makeSuite(misctestcase.SetupTest))
	tests.addTest(unittest.makeSuite(misctestcase.TestsUtilsTest))
	tests.addTest(unittest.makeSuite(misctestcase.MyTimeTest))
	# Database
	tests.addTest(unittest.makeSuite(databasetestcase.DatabaseTest))

	# Filter
	tests.addTest(unittest.makeSuite(filtertestcase.IgnoreIP))
	tests.addTest(unittest.makeSuite(filtertestcase.BasicFilter))
	tests.addTest(unittest.makeSuite(filtertestcase.LogFile))
	tests.addTest(unittest.makeSuite(filtertestcase.LogFileMonitor))
	tests.addTest(unittest.makeSuite(filtertestcase.LogFileFilterPoll))
	# each test case class self will check no network, and skip it (we see it in log)
	tests.addTest(unittest.makeSuite(filtertestcase.IgnoreIPDNS))
	tests.addTest(unittest.makeSuite(filtertestcase.GetFailures))
	tests.addTest(unittest.makeSuite(filtertestcase.DNSUtilsTests))
	tests.addTest(unittest.makeSuite(filtertestcase.DNSUtilsNetworkTests))
	tests.addTest(unittest.makeSuite(filtertestcase.JailTests))

	# DateDetector
	tests.addTest(unittest.makeSuite(datedetectortestcase.DateDetectorTest))
	tests.addTest(unittest.makeSuite(datedetectortestcase.CustomDateFormatsTest))
	# Filter Regex tests with sample logs
	tests.addTest(unittest.makeSuite(samplestestcase.FilterSamplesRegex))

	# bin/fail2ban-client, bin/fail2ban-server
	tests.addTest(unittest.makeSuite(fail2banclienttestcase.Fail2banClientTest))
	tests.addTest(unittest.makeSuite(fail2banclienttestcase.Fail2banServerTest))
	# bin/fail2ban-regex
	tests.addTest(unittest.makeSuite(fail2banregextestcase.Fail2banRegexTest))

	#
	# Python action testcases
	#
	testloader = unittest.TestLoader()
	from . import action_d
	for file_ in os.listdir(
		os.path.abspath(os.path.dirname(action_d.__file__))):
		if file_.startswith("test_") and file_.endswith(".py"):
			tests.addTest(testloader.loadTestsFromName(
				"%s.%s" % (action_d.__name__, os.path.splitext(file_)[0])))

	#
	# Extensive use-tests of different available filters backends
	#

	from ..server.filterpoll import FilterPoll
	filters = [FilterPoll]					  # always available

	# Additional filters available only if external modules are available
	# yoh: Since I do not know better way for parametric tests
	#      with good old unittest
	try:
		# because gamin can be very slow on some platforms (and can produce many failures 
		# with fast sleep interval) - skip it by fast run:
		if unittest.F2B.fast or unittest.F2B.no_gamin: # pragma: no cover
			raise ImportError('Skip, fast: %s, no_gamin: %s' % (unittest.F2B.fast, unittest.F2B.no_gamin))
		from ..server.filtergamin import FilterGamin
		filters.append(FilterGamin)
	except ImportError as e: # pragma: no cover
		logSys.warning("Skipping gamin backend testing. Got exception '%s'" % e)

	try:
		from ..server.filterpyinotify import FilterPyinotify
		filters.append(FilterPyinotify)
	except ImportError as e: # pragma: no cover
		logSys.warning("I: Skipping pyinotify backend testing. Got exception '%s'" % e)

	for Filter_ in filters:
		tests.addTest(unittest.makeSuite(
			filtertestcase.get_monitor_failures_testcase(Filter_)))
	try: # pragma: systemd no cover
		from ..server.filtersystemd import FilterSystemd
		tests.addTest(unittest.makeSuite(filtertestcase.get_monitor_failures_journal_testcase(FilterSystemd)))
	except ImportError as e: # pragma: no cover
		logSys.warning("I: Skipping systemd backend testing. Got exception '%s'" % e)

	# Server test for logging elements which break logging used to support
	# testcases analysis
	tests.addTest(unittest.makeSuite(servertestcase.TransmitterLogging))

	return tests


#
# Forwards compatibility of unittest.TestCase for some early python versions
#

if not hasattr(unittest.TestCase, 'assertDictEqual'):
	import difflib, pprint
	def assertDictEqual(self, d1, d2, msg=None):
		self.assert_(isinstance(d1, dict), 'First argument is not a dictionary')
		self.assert_(isinstance(d2, dict), 'Second argument is not a dictionary')
		if d1 != d2:
			standardMsg = '%r != %r' % (d1, d2)
			diff = ('\n' + '\n'.join(difflib.ndiff(
				pprint.pformat(d1).splitlines(),
				pprint.pformat(d2).splitlines())))
			msg = msg or (standardMsg + diff)
			self.fail(msg)
	unittest.TestCase.assertDictEqual = assertDictEqual

if not hasattr(unittest.TestCase, 'assertRaisesRegexp'):
	def assertRaisesRegexp(self, exccls, regexp, fun, *args, **kwargs):
		try:
			fun(*args, **kwargs)
		except exccls as e:
			if re.search(regexp, str(e)) is None:
				self.fail('\"%s\" does not match \"%s\"' % (regexp, e))
		else:
			self.fail('%s not raised' % getattr(exccls, '__name__'))
	unittest.TestCase.assertRaisesRegexp = assertRaisesRegexp

# always custom following methods, because we use atm better version of both (support generators)
if True: ## if not hasattr(unittest.TestCase, 'assertIn'):
	def assertIn(self, a, b, msg=None):
		bb = b
		wrap = False
		if msg is None and hasattr(b, '__iter__') and not isinstance(b, basestring):
			b, bb = itertools.tee(b)
			wrap = True
		if a not in b:
			if wrap: bb = list(bb)
			msg = msg or "%r was not found in %r" % (a, bb)
			self.fail(msg)
	unittest.TestCase.assertIn = assertIn
	def assertNotIn(self, a, b, msg=None):
		bb = b
		wrap = False
		if msg is None and hasattr(b, '__iter__') and not isinstance(b, basestring):
			b, bb = itertools.tee(b)
			wrap = True
		if a in b:
			if wrap: bb = list(bb)
			msg = msg or "%r unexpectedly found in %r" % (a, bb)
			self.fail(msg)
	unittest.TestCase.assertNotIn = assertNotIn

_org_setUp = unittest.TestCase.setUp
def _customSetUp(self):
	# print('=='*10, self)
	# so if DEBUG etc -- show them (and log it in travis)!
	if unittest.F2B.log_level <= logging.DEBUG: # pragma: no cover
		sys.stderr.write("\n")
		logSys.debug('='*10 + ' %s ' + '='*20, self.id())
	_org_setUp(self)
	if unittest.F2B.verbosity > 2: # pragma: no cover
		self.__startTime = time.time()

_org_tearDown = unittest.TestCase.tearDown
def _customTearDown(self):
	if unittest.F2B.verbosity > 2: # pragma: no cover
		sys.stderr.write(" %.3fs -- " % (time.time() - self.__startTime,))

unittest.TestCase.setUp = _customSetUp
unittest.TestCase.tearDown = _customTearDown


class LogCaptureTestCase(unittest.TestCase):

	class _MemHandler(logging.Handler):
		"""Logging handler helper
		
		Affords not to delegate logging to StreamHandler at all,
		format lazily on demand in getvalue.
		Increases performance inside the LogCaptureTestCase tests, because there
		the log level set to DEBUG.
		"""

		def __init__(self, lazy=True):
			self._lock = threading.Lock()
			self._val = None
			self._recs = list()
			self._strm = StringIO()
			logging.Handler.__init__(self)
			if lazy:
				self.handle = self._handle_lazy
			
		def truncate(self, size=None):
			"""Truncate the internal buffer and records."""
			if size:
				raise Exception('invalid size argument: %r, should be None or 0' % size)
			with self._lock:
				self._strm.truncate(0)
				self._val = None
				self._recs = list()

		def __write(self, record):
			msg = record.getMessage() + '\n'
			try:
				self._strm.write(msg)
			except UnicodeEncodeError:
				self._strm.write(msg.encode('UTF-8'))

		def getvalue(self):
			"""Return current buffer as whole string."""
			with self._lock:
				# cached:
				if self._val is not None:
					return self._val
				# submit already emitted (delivered to handle) records:
				for record in self._recs:
					self.__write(record)
				self._recs = list()
				# cache and return:
				self._val = self._strm.getvalue()
				return self._val
			 
		def handle(self, record): # pragma: no cover
			"""Handle the specified record direct (not lazy)"""
			with self._lock:
				self._val = None
				self.__write(record)

		def _handle_lazy(self, record):
			"""Lazy handle the specified record on demand"""
			with self._lock:
				self._val = None
				self._recs.append(record)

	def setUp(self):

		# For extended testing of what gets output into logging
		# system, we will redirect it to a string
		logSys = getLogger("fail2ban")

		# Keep old settings
		self._old_level = logSys.level
		self._old_handlers = logSys.handlers
		# Let's log everything into a string
		self._log = LogCaptureTestCase._MemHandler(unittest.F2B.log_lazy)
		logSys.handlers = [self._log]
		if self._old_level <= logging.DEBUG:
			logSys.handlers += self._old_handlers
		else: # lowest log level to capture messages
			logSys.setLevel(logging.DEBUG)
		super(LogCaptureTestCase, self).setUp()

	def tearDown(self):
		"""Call after every test case."""
		# print "O: >>%s<<" % self._log.getvalue()
		self.pruneLog()
		logSys = getLogger("fail2ban")
		logSys.handlers = self._old_handlers
		logSys.level = self._old_level
		super(LogCaptureTestCase, self).tearDown()

	def _is_logged(self, *s, **kwargs):
		logged = self._log.getvalue()
		if not kwargs.get('all', False):
			# at least one entry should be found:
			for s_ in s:
				if s_ in logged:
					return True
			if True: # pragma: no cover
				return False
		else:
			# each entry should be found:
			for s_ in s:
				if s_ not in logged: # pragma: no cover
					return False
			return True

	def assertLogged(self, *s, **kwargs):
		"""Assert that one of the strings was logged

		Preferable to assertTrue(self._is_logged(..)))
		since provides message with the actual log.

		Parameters
		----------
		s : string or list/set/tuple of strings
		  Test should succeed if string (or any of the listed) is present in the log
		all : boolean (default False) if True should fail if any of s not logged
		"""
		wait = kwargs.get('wait', None)
		if wait:
			res = Utils.wait_for(lambda: self._is_logged(*s, **kwargs), wait)
		else:
			res = self._is_logged(*s, **kwargs)
		if not kwargs.get('all', False):
			# at least one entry should be found:
			if not res: # pragma: no cover
				logged = self._log.getvalue()
				self.fail("None among %r was found in the log: ===\n%s===" % (s, logged))
		else:
			# each entry should be found:
			if not res: # pragma: no cover
				logged = self._log.getvalue()
				for s_ in s:
					if s_ not in logged:
						self.fail("%r was not found in the log: ===\n%s===" % (s_, logged))

	def assertNotLogged(self, *s, **kwargs):
		"""Assert that strings were not logged

		Parameters
		----------
		s : string or list/set/tuple of strings
		  Test should succeed if the string (or at least one of the listed) is not
		  present in the log
		all : boolean (default False) if True should fail if any of s logged
		"""
		logged = self._log.getvalue()
		if not kwargs.get('all', False):
			for s_ in s:
				if s_ not in logged:
					return
			if True: # pragma: no cover
				self.fail("All of the %r were found present in the log: ===\n%s===" % (s, logged))
		else:
			for s_ in s:
				if s_ in logged: # pragma: no cover
					self.fail("%r was found in the log: ===\n%s===" % (s_, logged))

	def pruneLog(self, logphase=None):
		self._log.truncate(0)
		if logphase:
			logSys.debug('='*5 + ' %s ' + '='*5, logphase)

	def getLog(self):
		return self._log.getvalue()

	def printLog(self):
		print(self._log.getvalue())


pid_exists = Utils.pid_exists
