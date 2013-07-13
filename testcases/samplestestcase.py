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

import unittest, os, fileinput, re, json, datetime

from server.filter import Filter
from client.filterreader import FilterReader

TEST_FILES_DIR = os.path.join(os.path.dirname(__file__), "files")
CONFIG_DIR = "config"

class FilterSamplesRegex(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""
		self.filter = Filter(None)
		self.filter.setActive(True)

	def tearDown(self):
		"""Call after every test case."""

def testSampleRegexsFactory(name):
	def testFilter(self):

		# Check filter exists
		filterConf = FilterReader(name, "jail", basedir=CONFIG_DIR)
		filterConf.read()
		filterConf.getOptions({})

		for opt in filterConf.convert():
			if opt[2] == "addfailregex":
				self.filter.addFailRegex(opt[3])

		logFile = fileinput.FileInput(
			os.path.join(TEST_FILES_DIR, "logs", name))
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

			ret = self.filter.processLine(line, returnRawHost=True)
			if not ret:
				# Check line is flagged as none match
				self.assertFalse(faildata.get('match', True),
					 "Line not matched when should have: %s:%i" %
					(logFile.filename(), logFile.filelineno()))
			elif ret:
				# Check line is flagged to match
				self.assertTrue(faildata.get('match', False),
					"Line matched when shouldn't have: %s:%i" %
					(logFile.filename(), logFile.filelineno()))
				self.assertEqual(len(ret), 1)
				# Verify timestamp and host as expected
				host, time = ret[0]
				self.assertEqual(host, faildata.get("host", None))
				self.assertEqual(
					datetime.datetime.fromtimestamp(time),
					datetime.datetime.strptime(
						faildata.get("time", None), "%Y-%m-%dT%H:%M:%S"))

	return testFilter

for filter_ in os.listdir(os.path.join(TEST_FILES_DIR, "logs")):
	if os.path.isfile(os.path.join(TEST_FILES_DIR, "logs", filter_)):
		setattr(
			FilterSamplesRegex,
			"testSampleRegexs%s" % filter_.upper(),
			testSampleRegexsFactory(filter_))
