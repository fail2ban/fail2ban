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

# Fail2Ban developers

__copyright__ = "Copyright (c) 2013 Steven Hiscocks"
__license__ = "GPL"

import datetime
import fileinput
import inspect
import json
import os
import re
import sys
import time
import unittest
from ..server.filter import Filter
from ..client.filterreader import FilterReader
from .utils import setUpMyTime, tearDownMyTime, CONFIG_DIR

TEST_FILES_DIR = os.path.join(os.path.dirname(__file__), "files")


class FilterSamplesRegex(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""
		self.filter = Filter(None)
		self.filter.active = True

		setUpMyTime()

	def tearDown(self):
		"""Call after every test case."""
		tearDownMyTime()

	def testFiltersPresent(self):
		"""Check to ensure some tests exist"""
		self.assertTrue(
			len([test for test in inspect.getmembers(self)
				if test[0].startswith('testSampleRegexs')])
			>= 10,
			"Expected more FilterSampleRegexs tests")


def testSampleRegexsFactory(name):
	def testFilter(self):

		# Check filter exists
		filterConf = FilterReader(name, "jail", {}, basedir=CONFIG_DIR)
		self.assertEqual(filterConf.getFile(), name)
		self.assertEqual(filterConf.getJailName(), "jail")
		filterConf.read()
		filterConf.getOptions({})

		for opt in filterConf.convert():
			if opt[2] == "addfailregex":
				self.filter.addFailRegex(opt[3])
			elif opt[2] == "maxlines":
				self.filter.setMaxLines(opt[3])
			elif opt[2] == "addignoreregex":
				self.filter.addIgnoreRegex(opt[3])
			elif opt[2] == "datepattern":
				self.filter.setDatePattern(opt[3])

		self.assertTrue(
			os.path.isfile(os.path.join(TEST_FILES_DIR, "logs", name)),
			"No sample log file available for '%s' filter" % name)

		logFile = fileinput.FileInput(
			os.path.join(TEST_FILES_DIR, "logs", name))

		regexsUsed = set()
		for line in logFile:
			jsonREMatch = re.match("^# ?failJSON:(.+)$", line)
			if jsonREMatch:
				try:
					faildata = json.loads(jsonREMatch.group(1))
				except ValueError, e:
					raise ValueError("%s: %s:%i" %
						(e, logFile.filename(), logFile.filelineno()))
				line = next(logFile)
			elif line.startswith("#") or not line.strip():
				continue
			else:
				faildata = {}

			ret = self.filter.processLine(
				line, returnRawHost=True, checkAllRegex=True)[1]
			if not ret:
				# Check line is flagged as none match
				self.assertFalse(faildata.get('match', True),
					 "Line not matched when should have: %s:%i %r" %
					(logFile.filename(), logFile.filelineno(), line))
			elif ret:
				# Check line is flagged to match
				self.assertTrue(faildata.get('match', False),
					"Line matched when shouldn't have: %s:%i %r" %
					(logFile.filename(), logFile.filelineno(), line))
				self.assertEqual(len(ret), 1, "Multiple regexs matched %r - %s:%i" %
								 (map(lambda x: x[0], ret),logFile.filename(), logFile.filelineno()))

				# Verify timestamp and host as expected
				failregex, host, fail2banTime, lines = ret[0]
				self.assertEqual(host, faildata.get("host", None))

				t = faildata.get("time", None)
				try:
					jsonTimeLocal =	datetime.datetime.strptime(t, "%Y-%m-%dT%H:%M:%S")
				except ValueError:
					jsonTimeLocal =	datetime.datetime.strptime(t, "%Y-%m-%dT%H:%M:%S.%f")

				jsonTime = time.mktime(jsonTimeLocal.timetuple())
				
				jsonTime += jsonTimeLocal.microsecond / 1000000

				self.assertEqual(fail2banTime, jsonTime,
					"UTC Time  mismatch fail2ban %s (%s) != failJson %s (%s)  (diff %.3f seconds) on: %s:%i %r:" % 
					(fail2banTime, time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(fail2banTime)),
					jsonTime, time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(jsonTime)),
					fail2banTime - jsonTime, logFile.filename(), logFile.filelineno(), line ) )

				regexsUsed.add(failregex)

		for failRegexIndex, failRegex in enumerate(self.filter.getFailRegex()):
			self.assertTrue(
				failRegexIndex in regexsUsed,
				"Regex for filter '%s' has no samples: %i: %r" %
					(name, failRegexIndex, failRegex))

	return testFilter

for filter_ in filter(lambda x: not x.endswith('common.conf') and x.endswith('.conf'),
					  os.listdir(os.path.join(CONFIG_DIR, "filter.d"))):
	filterName = filter_.rpartition(".")[0]
	if not filterName.startswith('.'):
		setattr(
			FilterSamplesRegex,
			"testSampleRegexs%s" % filterName.upper(),
			testSampleRegexsFactory(filterName))
