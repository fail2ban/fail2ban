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

import logging
import optparse
import os
import re
import tempfile
import shutil
import sys
import time
import unittest

from StringIO import StringIO
from functools import wraps

from ..helpers import getLogger
from ..server.ipdns import DNSUtils
from ..server.mytime import MyTime
from ..server.utils import Utils
# for action_d.test_smtp :
from ..server import asyncserver


logSys = getLogger(__name__)

CONFIG_DIR = os.environ.get('FAIL2BAN_CONFIG_DIR', None)

if not CONFIG_DIR:
# Use heuristic to figure out where configuration files are
	if os.path.exists(os.path.join('config','fail2ban.conf')):
		CONFIG_DIR = 'config'
	else:
		CONFIG_DIR = '/etc/fail2ban'

# In not installed env (setup, test-cases) use fail2ban modules from main directory:
if 1 or os.environ.get('PYTHONPATH', None) is None:
	os.putenv('PYTHONPATH', os.path.dirname(os.path.dirname(os.path.dirname(
		os.path.abspath(__file__)))))

class F2B(optparse.Values):
	def __init__(self, opts={}):
		self.__dict__ = opts.__dict__ if opts else {
			'fast': False, 'memory_db':False, 'no_gamin': False, 'no_network': False, 
			"negate_re": False,
		}
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


def initTests(opts):
	unittest.F2B = F2B(opts)
	# --fast :
	if unittest.F2B.fast: # pragma: no cover
		# racy decrease default sleep intervals to test it faster 
		# (prevent long sleeping during test cases ... less time goes to sleep):
		Utils.DEFAULT_SLEEP_TIME = 0.0025
		Utils.DEFAULT_SLEEP_INTERVAL = 0.0005
		def F2B_SkipIfFast():
			raise unittest.SkipTest('Skip test because of "--fast"')
		unittest.F2B.SkipIfFast = F2B_SkipIfFast
	else:
		# sleep intervals are large - use replacement for sleep to check time to sleep:
		_org_sleep = time.sleep
		def _new_sleep(v):
			if (v > Utils.DEFAULT_SLEEP_TIME): # pragma: no cover
				raise ValueError('[BAD-CODE] To long sleep interval: %s, try to use conditional Utils.wait_for instead' % v)
			_org_sleep(min(v, Utils.DEFAULT_SLEEP_TIME))
		time.sleep = _new_sleep
	# --no-network :
	if unittest.F2B.no_network: # pragma: no cover
		def F2B_SkipIfNoNetwork():
			raise unittest.SkipTest('Skip test because of "--no-network"')
		unittest.F2B.SkipIfNoNetwork = F2B_SkipIfNoNetwork
	# precache all invalid ip's (TEST-NET-1, ..., TEST-NET-3 according to RFC 5737):
	c = DNSUtils.CACHE_ipToName
	for i in xrange(255):
		c.set('192.0.2.%s' % i, None)
		c.set('198.51.100.%s' % i, None)
		c.set('203.0.113.%s' % i, None)
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
	# yoh: we need to adjust TZ to match the one used by Cyril so all the timestamps match
	os.environ['TZ'] = 'Europe/Zurich'
	time.tzset()
	MyTime.setTime(1124013600)


def tearDownMyTime():
	os.environ.pop('TZ')
	if old_TZ: # pragma: no cover
		os.environ['TZ'] = old_TZ
	time.tzset()
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
	tests.addTest(unittest.makeSuite(misctestcase.CustomDateFormatsTest))
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
			raise Exception('Skip, fast: %s, no_gamin: %s' % (unittest.F2B.fast, unittest.F2B.no_gamin))
		from ..server.filtergamin import FilterGamin
		filters.append(FilterGamin)
	except Exception, e: # pragma: no cover
		logSys.warning("Skipping gamin backend testing. Got exception '%s'" % e)

	try:
		from ..server.filterpyinotify import FilterPyinotify
		filters.append(FilterPyinotify)
	except Exception, e: # pragma: no cover
		logSys.warning("I: Skipping pyinotify backend testing. Got exception '%s'" % e)

	for Filter_ in filters:
		tests.addTest(unittest.makeSuite(
			filtertestcase.get_monitor_failures_testcase(Filter_)))
	try: # pragma: systemd no cover
		from ..server.filtersystemd import FilterSystemd
		tests.addTest(unittest.makeSuite(filtertestcase.get_monitor_failures_journal_testcase(FilterSystemd)))
	except Exception, e: # pragma: no cover
		logSys.warning("I: Skipping systemd backend testing. Got exception '%s'" % e)

	# Server test for logging elements which break logging used to support
	# testcases analysis
	tests.addTest(unittest.makeSuite(servertestcase.TransmitterLogging))

	return tests


# forwards compatibility of unittest.TestCase for some early python versions
if not hasattr(unittest.TestCase, 'assertIn'):
	def __assertIn(self, a, b, msg=None):
		if a not in b: # pragma: no cover
			self.fail(msg or "%r was not found in %r" % (a, b))
	unittest.TestCase.assertIn = __assertIn
	def __assertNotIn(self, a, b, msg=None):
		if a in b: # pragma: no cover
			self.fail(msg or "%r was found in %r" % (a, b))
	unittest.TestCase.assertNotIn = __assertNotIn


class LogCaptureTestCase(unittest.TestCase):

	def setUp(self):

		# For extended testing of what gets output into logging
		# system, we will redirect it to a string
		logSys = getLogger("fail2ban")

		# Keep old settings
		self._old_level = logSys.level
		self._old_handlers = logSys.handlers
		# Let's log everything into a string
		self._log = StringIO()
		logSys.handlers = [logging.StreamHandler(self._log)]
		if self._old_level <= logging.DEBUG: # so if DEBUG etc -- show them (and log it in travis)!
			print("")
			logSys.handlers += self._old_handlers
			logSys.debug('='*10 + ' %s ' + '='*20, self.id())
		logSys.setLevel(getattr(logging, 'DEBUG'))

	def tearDown(self):
		"""Call after every test case."""
		# print "O: >>%s<<" % self._log.getvalue()
		self.pruneLog()
		logSys = getLogger("fail2ban")
		logSys.handlers = self._old_handlers
		logSys.level = self._old_level

	def _is_logged(self, s):
		return s in self._log.getvalue()

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
		logged = self._log.getvalue()
		if not kwargs.get('all', False):
			# at least one entry should be found:
			for s_ in s:
				if s_ in logged:
					return
			if True: # pragma: no cover
				self.fail("None among %r was found in the log: ===\n%s===" % (s, logged))
		else:
			# each entry should be found:
			for s_ in s:
				if s_ not in logged: # pragma: no cover
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

	def pruneLog(self):
		self._log.truncate(0)

	def pruneLog(self):
		self._log.truncate(0)

	def getLog(self):
		return self._log.getvalue()

	def printLog(self):
		print(self._log.getvalue())


pid_exists = Utils.pid_exists

# Python 2.6 compatibility. in 2.7 assertDictEqual
def assert_dict_equal(a, b):
	assert isinstance(a, dict), "Object is not dictionary: %r" % a
	assert isinstance(b, dict), "Object is not dictionary: %r" % b
	assert a==b, "Dictionaries differ:\n%r !=\n%r" % (a, b)
