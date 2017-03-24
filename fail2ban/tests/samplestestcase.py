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
from ..server.failregex import Regex
from ..server.filter import Filter
from ..client.filterreader import FilterReader
from .utils import setUpMyTime, tearDownMyTime, CONFIG_DIR

TEST_CONFIG_DIR = os.path.join(os.path.dirname(__file__), "config")
TEST_FILES_DIR = os.path.join(os.path.dirname(__file__), "files")

# regexp to test greedy catch-all should be not-greedy:
RE_HOST = Regex._resolveHostTag('<HOST>')
RE_WRONG_GREED = re.compile(r'\.[+\*](?!\?)[^\$\^]*' + re.escape(RE_HOST) + r'.*(?:\.[+\*].*|[^\$])$')


class FilterSamplesRegex(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""
		super(FilterSamplesRegex, self).setUp()
		self.filter = None
		setUpMyTime()

	def tearDown(self):
		"""Call after every test case."""
		super(FilterSamplesRegex, self).tearDown()
		tearDownMyTime()

	def testFiltersPresent(self):
		"""Check to ensure some tests exist"""
		self.assertTrue(
			len([test for test in inspect.getmembers(self)
				if test[0].startswith('testSampleRegexs')])
			>= 10,
			"Expected more FilterSampleRegexs tests")

	def testReWrongGreedyCatchAll(self):
		"""Tests regexp RE_WRONG_GREED is intact (positive/negative)"""
		self.assertTrue(
			RE_WRONG_GREED.search('greedy .* test' + RE_HOST + ' test not hard-anchored'))
		self.assertTrue(
			RE_WRONG_GREED.search('greedy .+ test' + RE_HOST + ' test vary .* anchored$'))
		self.assertFalse(
			RE_WRONG_GREED.search('greedy .* test' + RE_HOST + ' test no catch-all, hard-anchored$'))
		self.assertFalse(
			RE_WRONG_GREED.search('non-greedy .*? test' + RE_HOST + ' test not hard-anchored'))
		self.assertFalse(
			RE_WRONG_GREED.search('non-greedy .+? test' + RE_HOST + ' test vary catch-all .* anchored$'))


	def _readFilter(self, name, basedir, opts=None):
		self.filter = Filter(None)
		self.filter.returnRawHost = True
		self.filter.checkAllRegex = True
		self.filter.checkFindTime = False
		self.filter.active = True
		if opts is None: opts = dict()
		# Check filter exists
		filterConf = FilterReader(name, "jail", opts,
			basedir=basedir, share_config=unittest.F2B.share_config)
		self.assertEqual(filterConf.getFile(), name)
		self.assertEqual(filterConf.getJailName(), "jail")
		filterConf.read()
		filterConf.getOptions({})

		for opt in filterConf.convert():
			if opt[0] == 'multi-set':
				optval = opt[3]
			elif opt[0] == 'set':
				optval = [opt[3]]
			else: # pragma: no cover - unexpected
				self.fail('Unexpected config-token %r in stream' % (opt,))
			for optval in optval:
				if opt[2] == "prefregex":
					self.filter.prefRegex = optval
				elif opt[2] == "addfailregex":
					self.filter.addFailRegex(optval)
				elif opt[2] == "addignoreregex":
					self.filter.addIgnoreRegex(optval)
				elif opt[2] == "maxlines":
					self.filter.setMaxLines(optval)
				elif opt[2] == "datepattern":
					self.filter.setDatePattern(optval)

		# test regexp contains greedy catch-all before <HOST>, that is
		# not hard-anchored at end or has not precise sub expression after <HOST>:
		regexList = self.filter.getFailRegex()
		for fr in regexList:
			if RE_WRONG_GREED.search(fr): # pragma: no cover
				raise AssertionError("Following regexp of \"%s\" contains greedy catch-all before <HOST>, "
					"that is not hard-anchored at end or has not precise sub expression after <HOST>:\n%s" %
					(name, str(fr).replace(RE_HOST, '<HOST>')))
		return regexList

def testSampleRegexsFactory(name, basedir):
	def testFilter(self):

		self.assertTrue(
			os.path.isfile(os.path.join(TEST_FILES_DIR, "logs", name)),
			"No sample log file available for '%s' filter" % name)

		regexList = None
		regexsUsedIdx = set()
		regexsUsedRe = set()
		filenames = [name]

		def _testMissingSamples():
			for failRegexIndex, failRegex in enumerate(regexList):
				self.assertTrue(
					failRegexIndex in regexsUsedIdx or failRegex in regexsUsedRe,
					"Regex for filter '%s' has no samples: %i: %r" %
						(name, failRegexIndex, failRegex))
		i = 0
		while i < len(filenames):
			filename = filenames[i]; i += 1;
			logFile = fileinput.FileInput(os.path.join(TEST_FILES_DIR, "logs",
				filename))

			for line in logFile:
				jsonREMatch = re.match("^#+ ?(failJSON|filterOptions|addFILE):(.+)$", line)
				if jsonREMatch:
					try:
						faildata = json.loads(jsonREMatch.group(2))
						# filterOptions - dict in JSON to control filter options (e. g. mode, etc.):
						if jsonREMatch.group(1) == 'filterOptions':
							# another filter mode - we should check previous also:
							if self.filter is not None:
								_testMissingSamples()
								regexsUsedIdx = set() # clear used indices (possible overlapping by mode change)
							# read filter with another setting:
							self.filter = None
							regexList = self._readFilter(name, basedir, opts=faildata)
							continue
						# addFILE - filename to "include" test-files should be additionally parsed:
						if jsonREMatch.group(1) == 'addFILE':
							filenames.append(faildata)
							continue
						# failJSON - faildata contains info of the failure to check it.
					except ValueError as e: # pragma: no cover - we've valid json's
						raise ValueError("%s: %s:%i" %
							(e, logFile.filename(), logFile.filelineno()))
					line = next(logFile)
				elif line.startswith("#") or not line.strip():
					continue
				else: # pragma: no cover - normally unreachable
					faildata = {}

				if self.filter is None:
					regexList = self._readFilter(name, basedir, opts=None)

				try:
					ret = self.filter.processLine(line)
					if not ret:
						# Bypass if filter constraint specified:
						if faildata.get('filter') and name != faildata.get('filter'):
							continue
						# Check line is flagged as none match
						self.assertFalse(faildata.get('match', True),
							"Line not matched when should have")
						continue

					failregex, fid, fail2banTime, fail = ret[0]
					# Bypass no failure helpers-regexp:
					if not faildata.get('match', False) and (fid is None or fail.get('nofail')):
						regexsUsedIdx.add(failregex)
						regexsUsedRe.add(regexList[failregex])
						continue

					# Check line is flagged to match
					self.assertTrue(faildata.get('match', False), 
						"Line matched when shouldn't have")
					self.assertEqual(len(ret), 1,
						"Multiple regexs matched %r" % (map(lambda x: x[0], ret)))

					# Verify match captures (at least fid/host) and timestamp as expected
					for k, v in faildata.iteritems():
						if k not in ("time", "match", "desc", "filter"):
							fv = fail.get(k, None)
							# Fallback for backwards compatibility (previously no fid, was host only):
							if k == "host" and fv is None:
								fv = fid
							self.assertEqual(fv, v)

					t = faildata.get("time", None)
					try:
						jsonTimeLocal =	datetime.datetime.strptime(t, "%Y-%m-%dT%H:%M:%S")
					except ValueError:
						jsonTimeLocal =	datetime.datetime.strptime(t, "%Y-%m-%dT%H:%M:%S.%f")

					jsonTime = time.mktime(jsonTimeLocal.timetuple())
					
					jsonTime += jsonTimeLocal.microsecond / 1000000

					self.assertEqual(fail2banTime, jsonTime,
						"UTC Time  mismatch %s (%s) != %s (%s)  (diff %.3f seconds)" % 
						(fail2banTime, time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(fail2banTime)),
						jsonTime, time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(jsonTime)),
						fail2banTime - jsonTime) )

					regexsUsedIdx.add(failregex)
					regexsUsedRe.add(regexList[failregex])
				except AssertionError as e: # pragma: no cover
					raise AssertionError("%s on: %s:%i, line:\n%s" % (
								e, logFile.filename(), logFile.filelineno(), line))

		_testMissingSamples()

	return testFilter

for basedir_, filter_ in (
	(CONFIG_DIR, lambda x: not x.endswith('common.conf') and x.endswith('.conf')),
	(TEST_CONFIG_DIR, lambda x: x.startswith('zzz-') and x.endswith('.conf')),
):
	for filter_ in filter(filter_,
						  os.listdir(os.path.join(basedir_, "filter.d"))):
		filterName = filter_.rpartition(".")[0]
		if not filterName.startswith('.'):
			setattr(
				FilterSamplesRegex,
				"testSampleRegexs%s" % filterName.upper(),
				testSampleRegexsFactory(filterName, basedir_))
