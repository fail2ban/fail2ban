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
import os
import re
import time
import unittest
from StringIO import StringIO

from ..server.mytime import MyTime

logSys = logging.getLogger(__name__)

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
	if old_TZ:
		os.environ['TZ'] = old_TZ
	time.tzset()
	MyTime.myTime = None

def gatherTests(regexps=None, no_network=False):
	# Import all the test cases here instead of a module level to
	# avoid circular imports
	from . import banmanagertestcase
	from . import clientreadertestcase
	from . import failmanagertestcase
	from . import filtertestcase
	from . import servertestcase
	from . import datedetectortestcase
	from . import actiontestcase
	from . import actionstestcase
	from . import sockettestcase
	from . import misctestcase
	from . import databasetestcase
	from . import observertestcase
	from . import samplestestcase

	if not regexps: # pragma: no cover
		tests = unittest.TestSuite()
	else: # pragma: no cover
		class FilteredTestSuite(unittest.TestSuite):
			_regexps = [re.compile(r) for r in regexps]
			def addTest(self, suite):
				suite_str = str(suite)
				for r in self._regexps:
					if r.search(suite_str):
						super(FilteredTestSuite, self).addTest(suite)
						return

		tests = FilteredTestSuite()

	# Server
	#tests.addTest(unittest.makeSuite(servertestcase.StartStop))
	tests.addTest(unittest.makeSuite(servertestcase.Transmitter))
	tests.addTest(unittest.makeSuite(servertestcase.JailTests))
	tests.addTest(unittest.makeSuite(servertestcase.RegexTests))
	tests.addTest(unittest.makeSuite(actiontestcase.CommandActionTest))
	tests.addTest(unittest.makeSuite(actionstestcase.ExecuteActions))
	# FailManager
	tests.addTest(unittest.makeSuite(failmanagertestcase.AddFailure))
	# BanManager
	tests.addTest(unittest.makeSuite(banmanagertestcase.AddFailure))
	# ClientReaders
	tests.addTest(unittest.makeSuite(clientreadertestcase.ConfigReaderTest))
	tests.addTest(unittest.makeSuite(clientreadertestcase.JailReaderTest))
	tests.addTest(unittest.makeSuite(clientreadertestcase.FilterReaderTest))
	tests.addTest(unittest.makeSuite(clientreadertestcase.JailsReaderTest))
	# CSocket and AsyncServer
	tests.addTest(unittest.makeSuite(sockettestcase.Socket))
	# Misc helpers
	tests.addTest(unittest.makeSuite(misctestcase.HelpersTest))
	tests.addTest(unittest.makeSuite(misctestcase.SetupTest))
	tests.addTest(unittest.makeSuite(misctestcase.TestsUtilsTest))
	tests.addTest(unittest.makeSuite(misctestcase.CustomDateFormatsTest))
	# Database
	tests.addTest(unittest.makeSuite(databasetestcase.DatabaseTest))
	# Observer
	tests.addTest(unittest.makeSuite(observertestcase.ObserverTest))
	tests.addTest(unittest.makeSuite(observertestcase.BanTimeIncr))
	tests.addTest(unittest.makeSuite(observertestcase.BanTimeIncrDB))

	# Filter
	tests.addTest(unittest.makeSuite(filtertestcase.IgnoreIP))
	tests.addTest(unittest.makeSuite(filtertestcase.BasicFilter))
	tests.addTest(unittest.makeSuite(filtertestcase.LogFile))
	tests.addTest(unittest.makeSuite(filtertestcase.LogFileMonitor))
	tests.addTest(unittest.makeSuite(filtertestcase.LogFileFilterPoll))
	if not no_network:
		tests.addTest(unittest.makeSuite(filtertestcase.IgnoreIPDNS))
		tests.addTest(unittest.makeSuite(filtertestcase.GetFailures))
		tests.addTest(unittest.makeSuite(filtertestcase.DNSUtilsTests))
	tests.addTest(unittest.makeSuite(filtertestcase.JailTests))

	# DateDetector
	tests.addTest(unittest.makeSuite(datedetectortestcase.DateDetectorTest))
	# Filter Regex tests with sample logs
	tests.addTest(unittest.makeSuite(samplestestcase.FilterSamplesRegex))

	#
	# Python action testcases
	#
	testloader = unittest.TestLoader()
	from . import action_d
	for file_ in os.listdir(
		os.path.abspath(os.path.dirname(action_d.__file__))):
		if file_.startswith("test_") and file_.endswith(".py"):
			if no_network and file_ in ['test_badips.py']: #pragma: no cover
				# Test required network
				continue
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

class LogCaptureTestCase(unittest.TestCase):

	def setUp(self):

		# For extended testing of what gets output into logging
		# system, we will redirect it to a string
		logSys = logging.getLogger("fail2ban")

		# Keep old settings
		self._old_level = logSys.level
		self._old_handlers = logSys.handlers
		# Let's log everything into a string
		self._log = StringIO()
		logSys.handlers = [logging.StreamHandler(self._log)]
		logSys.setLevel(getattr(logging, 'DEBUG'))

	def tearDown(self):
		"""Call after every test case."""
		# print "O: >>%s<<" % self._log.getvalue()
		logSys = logging.getLogger("fail2ban")
		logSys.handlers = self._old_handlers
		logSys.level = self._old_level

	def _is_logged(self, s):
		return s in self._log.getvalue()

	def printLog(self):
		print(self._log.getvalue())
