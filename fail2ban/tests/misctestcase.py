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
import sys
import unittest
import tempfile
import shutil
import fnmatch
import datetime
from glob import glob
from StringIO import StringIO

from ..helpers import formatExceptionInfo, mbasename, TraceBack, FormatterWithTraceBack, getLogger
from ..helpers import splitcommaspace
from ..server.datetemplate import DatePatternRegex


class HelpersTest(unittest.TestCase):

	def testFormatExceptionInfoBasic(self):
		try:
			raise ValueError("Very bad exception")
		except:
			name, args = formatExceptionInfo()
			self.assertEqual(name, "ValueError")
			self.assertEqual(args, "Very bad exception")

	def testFormatExceptionConvertArgs(self):
		try:
			raise ValueError("Very bad", None)
		except:
			name, args = formatExceptionInfo()
			self.assertEqual(name, "ValueError")
			# might be fragile due to ' vs "
			self.assertEqual(args, "('Very bad', None)")

	def testsplitcommaspace(self):
		self.assertEqual(splitcommaspace(None), [])
		self.assertEqual(splitcommaspace(''), [])
		self.assertEqual(splitcommaspace('  '), [])
		self.assertEqual(splitcommaspace('1'), ['1'])
		self.assertEqual(splitcommaspace(' 1 2 '), ['1', '2'])
		self.assertEqual(splitcommaspace(' 1, 2 , '), ['1', '2'])


class SetupTest(unittest.TestCase):

	def setUp(self):
		setup = os.path.join(os.path.dirname(__file__), '..', '..', 'setup.py')
		self.setup = os.path.exists(setup) and setup or None
		if not self.setup and sys.version_info >= (2,7): # pragma: no cover - running not out of the source
			raise unittest.SkipTest(
				"Seems to be running not out of source distribution"
				" -- cannot locate setup.py")

	def testSetupInstallRoot(self):
		if not self.setup:
			return			  # if verbose skip didn't work out
		tmp = tempfile.mkdtemp()
		try:
			os.system("%s %s install --root=%s >/dev/null"
					  % (sys.executable, self.setup, tmp))

			def strippath(l):
				return [x[len(tmp)+1:] for x in l]

			got = strippath(sorted(glob('%s/*' % tmp)))
			need = ['etc', 'usr', 'var']

			# if anything is missing
			if set(need).difference(got): # pragma: no cover
				#  below code was actually to print out not missing but
				#  rather files in 'excess'.  Left in place in case we
				#  decide to revert to such more strict test

				# based on
				# http://stackoverflow.com/questions/2186525/use-a-glob-to-find-files-recursively-in-python
				def recursive_glob(treeroot, pattern):
					results = []
					for base, dirs, files in os.walk(treeroot):
						goodfiles = fnmatch.filter(dirs + files, pattern)
						results.extend(os.path.join(base, f) for f in goodfiles)
					return results

				files = {}
				for missing in set(got).difference(need):
					missing_full = os.path.join(tmp, missing)
					files[missing] = os.path.exists(missing_full) \
						and strippath(recursive_glob(missing_full, '*')) or None

				self.assertEqual(
					got, need,
					msg="Got: %s Needed: %s under %s. Files under new paths: %s"
					% (got, need, tmp, files))

			# Assure presence of some files we expect to see in the installation
			for f in ('etc/fail2ban/fail2ban.conf',
					  'etc/fail2ban/jail.conf'):
				self.assertTrue(os.path.exists(os.path.join(tmp, f)),
								msg="Can't find %s" % f)
		finally:
			# clean up
			shutil.rmtree(tmp)
			# remove build directory
			os.system("%s %s clean --all >/dev/null 2>&1"
					  % (sys.executable, self.setup))


class TestsUtilsTest(unittest.TestCase):

	def testmbasename(self):
		self.assertEqual(mbasename("sample.py"), 'sample')
		self.assertEqual(mbasename("/long/path/sample.py"), 'sample')
		# this one would include only the directory for the __init__ and base files
		self.assertEqual(mbasename("/long/path/__init__.py"), 'path.__init__')
		self.assertEqual(mbasename("/long/path/base.py"), 'path.base')
		self.assertEqual(mbasename("/long/path/base"), 'path.base')

	def testTraceBack(self):
		# pretty much just a smoke test since tests runners swallow all the detail

		for compress in True, False:
			tb = TraceBack(compress=compress)

			def func_raise():
				raise ValueError()

			def deep_function(i):
				if i:
					deep_function(i-1)
				else:
					func_raise()

			try:
				print deep_function(3)
			except ValueError:
				s = tb()

			# if we run it through 'coverage' (e.g. on travis) then we
			# would get a traceback
			if not ('fail2ban-testcases' in s):
				# we must be calling it from setup or nosetests but using at least
				# nose's core etc
				self.assertTrue('>' in s, msg="no '>' in %r" % s)
			elif not ('coverage' in s):
				# There is only "fail2ban-testcases" in this case, no true traceback
				self.assertFalse('>' in s, msg="'>' present in %r" % s)

			self.assertTrue(':' in s, msg="no ':' in %r" % s)

	def testFormatterWithTraceBack(self):
		strout = StringIO()
		Formatter = FormatterWithTraceBack

		# and both types of traceback at once
		fmt = ' %(tb)s | %(tbc)s : %(message)s'
		logSys = getLogger("fail2ban_tests")
		out = logging.StreamHandler(strout)
		out.setFormatter(Formatter(fmt))
		logSys.addHandler(out)
		logSys.error("XXX")

		s = strout.getvalue()
		self.assertTrue(s.rstrip().endswith(': XXX'))
		pindex = s.index('|')

		# in this case compressed and not should be the same (?)
		self.assertTrue(pindex > 10)	  # we should have some traceback
		self.assertEqual(s[:pindex], s[pindex+1:pindex*2 + 1])

iso8601 = DatePatternRegex("%Y-%m-%d[T ]%H:%M:%S(?:\.%f)?%z")


class CustomDateFormatsTest(unittest.TestCase):

	def testIso8601(self):
		date = datetime.datetime.utcfromtimestamp(
			iso8601.getDate("2007-01-25T12:00:00Z")[0])
		self.assertEqual(
			date,
			datetime.datetime(2007, 1, 25, 12, 0))
		self.assertRaises(TypeError, iso8601.getDate, None)
		self.assertRaises(TypeError, iso8601.getDate, date)

		self.assertEqual(iso8601.getDate(""), None)
		self.assertEqual(iso8601.getDate("Z"), None)

		self.assertEqual(iso8601.getDate("2007-01-01T120:00:00Z"), None)
		self.assertEqual(iso8601.getDate("2007-13-01T12:00:00Z"), None)
		date = datetime.datetime.utcfromtimestamp(
			iso8601.getDate("2007-01-25T12:00:00+0400")[0])
		self.assertEqual(
			date,
			datetime.datetime(2007, 1, 25, 8, 0))
		date = datetime.datetime.utcfromtimestamp(
			iso8601.getDate("2007-01-25T12:00:00+04:00")[0])
		self.assertEqual(
			date,
			datetime.datetime(2007, 1, 25, 8, 0))
		date = datetime.datetime.utcfromtimestamp(
			iso8601.getDate("2007-01-25T12:00:00-0400")[0])
		self.assertEqual(
			date,
			datetime.datetime(2007, 1, 25, 16, 0))
		date = datetime.datetime.utcfromtimestamp(
			iso8601.getDate("2007-01-25T12:00:00-04")[0])
		self.assertEqual(
			date,
			datetime.datetime(2007, 1, 25, 16, 0))
