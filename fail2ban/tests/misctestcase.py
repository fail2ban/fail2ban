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
import sys
import unittest
import tempfile
import shutil
import fnmatch
import datetime
from glob import glob
from StringIO import StringIO

from utils import LogCaptureTestCase, logSys as DefLogSys

from ..helpers import formatExceptionInfo, mbasename, TraceBack, FormatterWithTraceBack, getLogger
from ..helpers import splitwords
from ..server.datedetector import DateDetector
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

	def testsplitwords(self):
		self.assertEqual(splitwords(None), [])
		self.assertEqual(splitwords(''), [])
		self.assertEqual(splitwords('  '), [])
		self.assertEqual(splitwords('1'), ['1'])
		self.assertEqual(splitwords(' 1 2 '), ['1', '2'])
		self.assertEqual(splitwords(' 1, 2 , '), ['1', '2'])
		self.assertEqual(splitwords(' 1\n  2'), ['1', '2'])
		self.assertEqual(splitwords(' 1\n  2, 3'), ['1', '2', '3'])


if sys.version_info >= (2,7):
	def _sh_call(cmd):
		import subprocess, locale
		ret = subprocess.check_output(cmd, shell=True)
		if sys.version_info >= (3,):
			ret = ret.decode(locale.getpreferredencoding(), 'replace')
		return str(ret).rstrip()
else:
	def _sh_call(cmd):
		import subprocess
		ret = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout.read()
		return str(ret).rstrip()

def _getSysPythonVersion():
	return _sh_call("fail2ban-python -c 'import sys; print(tuple(sys.version_info))'")

class SetupTest(unittest.TestCase):

	def setUp(self):
		setup = os.path.join(os.path.dirname(__file__), '..', '..', 'setup.py')
		self.setup = os.path.exists(setup) and setup or None
		if not self.setup and sys.version_info >= (2,7): # pragma: no cover - running not out of the source
			raise unittest.SkipTest(
				"Seems to be running not out of source distribution"
				" -- cannot locate setup.py")
		# compare current version of python installed resp. active one:
		sysVer = _getSysPythonVersion()
		if sysVer != str(tuple(sys.version_info)):
			raise unittest.SkipTest(
				"Seems to be running with python distribution %s"
				" -- install can be tested only with system distribution %s" % (str(tuple(sys.version_info)), sysVer))

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
			# Because the install (test) path in virtual-env differs from some development-env,
			# it is not a `tmp + '/usr/local/bin/'`, so search for it:
			installedPath = _sh_call('find ' + tmp+ ' -name fail2ban-python').split('\n')
			self.assertTrue(len(installedPath) > 0)
			for installedPath in installedPath:
				self.assertEqual(
					os.path.realpath(installedPath), os.path.realpath(sys.executable))

		finally:
			# clean up
			shutil.rmtree(tmp)
			# remove build directory
			os.system("%s %s clean --all >/dev/null 2>&1"
					  % (sys.executable, self.setup))


class TestsUtilsTest(LogCaptureTestCase):

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
				self.assertIn('>', s)
			elif not ('coverage' in s):
				# There is only "fail2ban-testcases" in this case, no true traceback
				self.assertNotIn('>', s)

			self.assertIn(':', s)

	def _testAssertionErrorRE(self, regexp, fun, *args, **kwargs):
		self.assertRaisesRegexp(AssertionError, regexp, fun, *args, **kwargs)
	
	def testExtendedAssertRaisesRE(self):
		## test _testAssertionErrorRE several fail cases:
		def _key_err(msg):
			raise KeyError(msg)			
		self.assertRaises(KeyError,
			self._testAssertionErrorRE, r"^failed$", 
				_key_err, 'failed')
		self.assertRaises(AssertionError,
			self._testAssertionErrorRE, r"^failed$",
				self.fail, '__failed__')
		self._testAssertionErrorRE(r'failed.* does not match .*__failed__',
			lambda: self._testAssertionErrorRE(r"^failed$",
				self.fail, '__failed__')
		)
		## no exception in callable:
		self.assertRaises(AssertionError,
			self._testAssertionErrorRE, r"", int, 1)
		self._testAssertionErrorRE(r'0 AssertionError not raised X.* does not match .*AssertionError not raised',
			lambda: self._testAssertionErrorRE(r"^0 AssertionError not raised X$",
				lambda: self._testAssertionErrorRE(r"", int, 1))
		)

	def testExtendedAssertMethods(self):
		## assertIn, assertNotIn positive case:
		self.assertIn('a', ['a', 'b', 'c', 'd'])
		self.assertIn('a', ('a', 'b', 'c', 'd',))
		self.assertIn('a', 'cba')
		self.assertIn('a', (c for c in 'cba' if c != 'b'))
		self.assertNotIn('a', ['b', 'c', 'd'])
		self.assertNotIn('a', ('b', 'c', 'd',))
		self.assertNotIn('a', 'cbd')
		self.assertNotIn('a', (c.upper() for c in 'cba' if c != 'b'))
		## assertIn, assertNotIn negative case:
		self._testAssertionErrorRE(r"'a' unexpectedly found in 'cba'",
			self.assertNotIn, 'a', 'cba')
		self._testAssertionErrorRE(r"1 unexpectedly found in \[0, 1, 2\]",
			self.assertNotIn, 1, xrange(3))
		self._testAssertionErrorRE(r"'A' unexpectedly found in \['C', 'A'\]",
			self.assertNotIn, 'A', (c.upper() for c in 'cba' if c != 'b'))
		self._testAssertionErrorRE(r"'a' was not found in 'xyz'",
			self.assertIn, 'a', 'xyz')
		self._testAssertionErrorRE(r"5 was not found in \[0, 1, 2\]",
			self.assertIn, 5, xrange(3))
		self._testAssertionErrorRE(r"'A' was not found in \['C', 'B'\]",
			self.assertIn, 'A', (c.upper() for c in 'cba' if c != 'a'))
		## assertLogged, assertNotLogged positive case:
		logSys = DefLogSys
		self.pruneLog()
		logSys.debug('test "xyz"')
		self.assertLogged('test "xyz"')
		self.assertLogged('test', 'xyz', all=True)
		self.assertNotLogged('test', 'zyx', all=False)
		self.assertNotLogged('test_zyx', 'zyx', all=True)
		self.assertLogged('test', 'zyx', all=False)
		self.pruneLog()
		logSys.debug('xxxx "xxx"')
		self.assertNotLogged('test "xyz"')
		self.assertNotLogged('test', 'xyz', all=False)
		self.assertNotLogged('test', 'xyz', 'zyx', all=True)
		## assertLogged, assertNotLogged negative case:
		self.pruneLog()
		logSys.debug('test "xyz"')
		self._testAssertionErrorRE(r"All of the .* were found present in the log",
			self.assertNotLogged, 'test "xyz"')
		self._testAssertionErrorRE(r"was found in the log",
			self.assertNotLogged, 'test', 'xyz', all=True)
		self._testAssertionErrorRE(r"was not found in the log",
			self.assertLogged, 'test', 'zyx', all=True)
		self._testAssertionErrorRE(r"None among .* was found in the log",
			self.assertLogged, 'test_zyx', 'zyx', all=False)
		self._testAssertionErrorRE(r"All of the .* were found present in the log",
			self.assertNotLogged, 'test', 'xyz', all=False)

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

	def testAmbiguousDatePattern(self):
		defDD = DateDetector()
		defDD.addDefaultTemplate()
		logSys = DefLogSys
		for (matched, dp, line) in (
			# positive case:
			('Jan 23 21:59:59',   None, 'Test failure Jan 23 21:59:59 for 192.0.2.1'),
			# ambiguous "unbound" patterns (missed):
			(False,               None, 'Test failure TestJan 23 21:59:59.011 2015 for 192.0.2.1'),
			(False,               None, 'Test failure Jan 23 21:59:59123456789 for 192.0.2.1'),
			# ambiguous "no optional year" patterns (matched):
			('Aug 8 11:25:50',      None, 'Aug 8 11:25:50 14430f2329b8 Authentication failed from 192.0.2.1'),
			('Aug 8 11:25:50',      None, '[Aug 8 11:25:50] 14430f2329b8 Authentication failed from 192.0.2.1'),
			('Aug 8 11:25:50 2014', None, 'Aug 8 11:25:50 2014 14430f2329b8 Authentication failed from 192.0.2.1'),
			# direct specified patterns:
			('20:00:00 01.02.2003',    r'%H:%M:%S %d.%m.%Y$', '192.0.2.1 at 20:00:00 01.02.2003'),
			('[20:00:00 01.02.2003]',  r'\[%H:%M:%S %d.%m.%Y\]', '192.0.2.1[20:00:00 01.02.2003]'),
			('[20:00:00 01.02.2003]',  r'\[%H:%M:%S %d.%m.%Y\]', '[20:00:00 01.02.2003]192.0.2.1'),
			('[20:00:00 01.02.2003]',  r'\[%H:%M:%S %d.%m.%Y\]$', '192.0.2.1[20:00:00 01.02.2003]'),
			('[20:00:00 01.02.2003]',  r'^\[%H:%M:%S %d.%m.%Y\]', '[20:00:00 01.02.2003]192.0.2.1'),
			('[17/Jun/2011 17:00:45]', r'^\[%d/%b/%Y %H:%M:%S\]', '[17/Jun/2011 17:00:45] Attempt, IP address 192.0.2.1'),
			('[17/Jun/2011 17:00:45]', r'\[%d/%b/%Y %H:%M:%S\]', 'Attempt [17/Jun/2011 17:00:45] IP address 192.0.2.1'),
			('[17/Jun/2011 17:00:45]', r'\[%d/%b/%Y %H:%M:%S\]', 'Attempt IP address 192.0.2.1, date: [17/Jun/2011 17:00:45]'),
			# direct specified patterns (begin/end, missed):
			(False,                 r'%H:%M:%S %d.%m.%Y', '192.0.2.1x20:00:00 01.02.2003'),
			(False,                 r'%H:%M:%S %d.%m.%Y', '20:00:00 01.02.2003x192.0.2.1'),
			# direct specified patterns (begin/end, matched):
			('20:00:00 01.02.2003', r'%H:%M:%S %d.%m.%Y', '192.0.2.1 20:00:00 01.02.2003'),
			('20:00:00 01.02.2003', r'%H:%M:%S %d.%m.%Y', '20:00:00 01.02.2003 192.0.2.1'),
		):
			logSys.debug('== test: %r', (matched, dp, line))
			if dp is None:
				dd = defDD
			else:
				dp = DatePatternRegex(dp)
				dd = DateDetector()
				dd.appendTemplate(dp)
			date = dd.getTime(line)
			if matched:
				self.assertTrue(date)
				self.assertEqual(matched, date[1].group())
			else:
				self.assertEqual(date, None)
