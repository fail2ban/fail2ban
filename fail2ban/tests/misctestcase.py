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
from glob import glob
from StringIO import StringIO

from utils import LogCaptureTestCase, logSys as DefLogSys

from ..helpers import formatExceptionInfo, mbasename, TraceBack, FormatterWithTraceBack, getLogger, \
	getVerbosityFormat, splitwords, uni_decode, uni_string
from ..server.mytime import MyTime


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
		# string as unicode:
		self.assertEqual(splitwords(u' 1\n  2, 3'), ['1', '2', '3'])


if sys.version_info >= (2,7):
	def _sh_call(cmd):
		import subprocess
		ret = subprocess.check_output(cmd, shell=True)
		return uni_decode(ret).rstrip()
else:
	def _sh_call(cmd):
		import subprocess
		ret = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout.read()
		return uni_decode(ret).rstrip()

def _getSysPythonVersion():
	return _sh_call("fail2ban-python -c 'import sys; print(tuple(sys.version_info))'")


class SetupTest(unittest.TestCase):

	def setUp(self):
		super(SetupTest, self).setUp()
		unittest.F2B.SkipIfFast()
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

	def testSetupInstallDryRun(self):
		if not self.setup:
			return			  # if verbose skip didn't work out
		tmp = tempfile.mkdtemp()
		# suppress stdout (and stderr) if not heavydebug
		supdbgout = ' >/dev/null 2>&1' if unittest.F2B.log_level >= logging.DEBUG else '' # HEAVYDEBUG
		try:
			# try dry-run:
			os.system("%s %s --dry-run install --disable-2to3 --root=%s%s"
					  % (sys.executable, self.setup , tmp, supdbgout))
			# check nothing was created:
			self.assertTrue(not os.listdir(tmp))
		finally:
			# clean up
			shutil.rmtree(tmp)

	def testSetupInstallRoot(self):
		if not self.setup:
			return			  # if verbose skip didn't work out
		tmp = tempfile.mkdtemp()
		remove_build = not os.path.exists('build')
		# suppress stdout (and stderr) if not heavydebug
		supdbgout = ' >/dev/null' if unittest.F2B.log_level >= logging.DEBUG else '' # HEAVYDEBUG
		try:
			self.assertEqual(os.system("%s %s install --disable-2to3 --root=%s%s"
					  % (sys.executable, self.setup, tmp, supdbgout)), 0)

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
			os.system("%s %s clean --all%s"
					  % (sys.executable, self.setup, (supdbgout + ' 2>&1') if supdbgout else ''))
			if remove_build and os.path.exists('build'):
				shutil.rmtree('build')


class TestsUtilsTest(LogCaptureTestCase):

	def testmbasename(self):
		self.assertEqual(mbasename("sample.py"), 'sample')
		self.assertEqual(mbasename("/long/path/sample.py"), 'sample')
		# this one would include only the directory for the __init__ and base files
		self.assertEqual(mbasename("/long/path/__init__.py"), 'path.__init__')
		self.assertEqual(mbasename("/long/path/base.py"), 'path.base')
		self.assertEqual(mbasename("/long/path/base"), 'path.base')

	def testUniConverters(self):
		self.assertRaises(Exception, uni_decode, 
			(b'test' if sys.version_info >= (3,) else u'test'), 'f2b-test::non-existing-encoding')
		uni_decode((b'test\xcf' if sys.version_info >= (3,) else u'test\xcf'))
		uni_string(b'test\xcf')
		uni_string('test\xcf')
		if sys.version_info < (3,) and 'PyPy' not in sys.version:
			uni_string(u'test\xcf')

	def testSafeLogging(self):
		# logging should be exception-safe, to avoid possible errors (concat, str. conversion, representation failures, etc)
		logSys = DefLogSys
		class Test:
			def __init__(self, err=1):
				self.err = err
			def __repr__(self):
				if self.err:
					raise Exception('no represenation for test!')
				else:
					return u'conv-error (\xf2\xf0\xe5\xf2\xe8\xe9), unterminated utf \xcf'
		test = Test()
		logSys.log(logging.NOTICE, "test 1a: %r", test)
		self.assertLogged("Traceback", "no represenation for test!")
		self.pruneLog()
		logSys.notice("test 1b: %r", test)
		self.assertLogged("Traceback", "no represenation for test!")

		self.pruneLog('[phase 2] test error conversion by encoding %s' % sys.getdefaultencoding())
		test = Test(0)
		# this may produce coversion error on ascii default encoding:
		#str(test)
		logSys.log(logging.NOTICE, "test 2a: %r, %s", test, test)
		self.assertLogged("test 2a", "Error by logging handler", all=False)
		logSys.notice("test 2b: %r, %s", test, test)
		self.assertLogged("test 2b", "Error by logging handler", all=False)

		self.pruneLog('[phase 3] test unexpected error in handler')
		class _ErrorHandler(logging.Handler):
			def handle(self, record):
				raise Exception('error in handler test!')
		_org_handler = logSys.handlers
		try:
			logSys.handlers = list(logSys.handlers)
			logSys.handlers += [_ErrorHandler()]
			logSys.log(logging.NOTICE, "test 3a")
			logSys.notice("test 3b")
		finally:
			logSys.handlers = _org_handler
		# we should reach this line without errors!
		self.pruneLog('OK')

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
		## maxWaitTime:
		orgfast, unittest.F2B.fast = unittest.F2B.fast, False
		self.assertFalse(isinstance(unittest.F2B.maxWaitTime(True), bool))
		self.assertEqual(unittest.F2B.maxWaitTime(lambda: 50)(), 50)
		self.assertEqual(unittest.F2B.maxWaitTime(25), 25)
		self.assertEqual(unittest.F2B.maxWaitTime(25.), 25.0)
		unittest.F2B.fast = True
		try:
			self.assertEqual(unittest.F2B.maxWaitTime(lambda: 50)(), 50)
			self.assertEqual(unittest.F2B.maxWaitTime(25), 2.5)
			self.assertEqual(unittest.F2B.maxWaitTime(25.), 25.0)
		finally:
			unittest.F2B.fast = orgfast
		self.assertFalse(unittest.F2B.maxWaitTime(False))
		## assertLogged, assertNotLogged negative case:
		self.pruneLog()
		logSys.debug('test "xyz"')
		self._testAssertionErrorRE(r".* was found in the log",
			self.assertNotLogged, 'test "xyz"')
		self._testAssertionErrorRE(r"All of the .* were found present in the log",
			self.assertNotLogged, 'test "xyz"', 'test')
		self._testAssertionErrorRE(r"was found in the log",
			self.assertNotLogged, 'test', 'xyz', all=True)
		self._testAssertionErrorRE(r"was not found in the log",
			self.assertLogged, 'test', 'zyx', all=True)
		self._testAssertionErrorRE(r"was not found in the log, waited 1e-06",
			self.assertLogged, 'test', 'zyx', all=True, wait=1e-6)
		self._testAssertionErrorRE(r"None among .* was found in the log",
			self.assertLogged, 'test_zyx', 'zyx', all=False)
		self._testAssertionErrorRE(r"None among .* was found in the log, waited 1e-06",
			self.assertLogged, 'test_zyx', 'zyx', all=False, wait=1e-6)
		self._testAssertionErrorRE(r"All of the .* were found present in the log",
			self.assertNotLogged, 'test', 'xyz', all=False)
		## assertDictEqual:
		self.assertDictEqual({'A': [1, 2]}, {'A': [1, 2]})
		self.assertRaises(AssertionError, self.assertDictEqual, 
			{'A': [1, 2]}, {'A': [2, 1]})
		## assertSortedEqual:
		self.assertSortedEqual(['A', 'B'], ['B', 'A'])
		self.assertSortedEqual([['A', 'B']], [['B', 'A']], level=2)
		self.assertSortedEqual([['A', 'B']], [['B', 'A']], nestedOnly=False)
		self.assertRaises(AssertionError, lambda: self.assertSortedEqual(
			[['A', 'B']], [['B', 'A']], level=1, nestedOnly=True))
		self.assertSortedEqual({'A': ['A', 'B']}, {'A': ['B', 'A']}, nestedOnly=False)
		self.assertRaises(AssertionError, lambda: self.assertSortedEqual(
			{'A': ['A', 'B']}, {'A': ['B', 'A']}, level=1, nestedOnly=True))
		self.assertSortedEqual(['Z', {'A': ['B', 'C'], 'B': ['E', 'F']}], [{'B': ['F', 'E'], 'A': ['C', 'B']}, 'Z'],
			nestedOnly=False)
		self.assertSortedEqual(['Z', {'A': ['B', 'C'], 'B': ['E', 'F']}], [{'B': ['F', 'E'], 'A': ['C', 'B']}, 'Z'],
			level=-1)
		self.assertRaises(AssertionError, lambda: self.assertSortedEqual(
			['Z', {'A': ['B', 'C'], 'B': ['E', 'F']}], [{'B': ['F', 'E'], 'A': ['C', 'B']}, 'Z'],
			nestedOnly=True))
		self.assertSortedEqual(
			(0, [['A1'], ['A2', 'A1'], []]),
			(0, [['A1'], ['A1', 'A2'], []]),
		)
		self.assertSortedEqual(list('ABC'), list('CBA'))
		self.assertRaises(AssertionError, self.assertSortedEqual, ['ABC'], ['CBA'])
		self.assertRaises(AssertionError, self.assertSortedEqual, [['ABC']], [['CBA']])
		self._testAssertionErrorRE(r"\['A'\] != \['C', 'B'\]",
			self.assertSortedEqual, ['A'], ['C', 'B'])
		self._testAssertionErrorRE(r"\['A', 'B'\] != \['B', 'C'\]",
			self.assertSortedEqual, ['A', 'B'], ['C', 'B'])

	def testVerbosityFormat(self):
		self.assertEqual(getVerbosityFormat(1),
			'%(asctime)s %(name)-24s[%(process)d]: %(levelname)-7s %(message)s')
		self.assertEqual(getVerbosityFormat(1, padding=False),
			'%(asctime)s %(name)s[%(process)d]: %(levelname)s %(message)s')
		self.assertEqual(getVerbosityFormat(1, addtime=False, padding=False),
			'%(name)s[%(process)d]: %(levelname)s %(message)s')

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

	def testLazyLogging(self):
		logSys = DefLogSys
		logSys.debug('lazy logging: %r', unittest.F2B.log_lazy)
		# wrong logging syntax will don't throw an error anymore (logged now):
		logSys.notice('test', 1, 2, 3)
		self.assertLogged('not all arguments converted')


class MyTimeTest(unittest.TestCase):

	def testStr2Seconds(self):
		# several formats / write styles:
		str2sec = MyTime.str2seconds
		self.assertEqual(str2sec('1y6mo30w15d12h35m25s'), 66821725)
		self.assertEqual(str2sec('2yy 3mo 4ww 10dd 5hh 30mm 20ss'), 74307620)
		self.assertEqual(str2sec('2 years 3 months 4 weeks 10 days 5 hours 30 minutes 20 seconds'), 74307620)
		self.assertEqual(str2sec('1 year + 1 month - 1 week + 1 day'), 33669000)
		self.assertEqual(str2sec('2 * 0.5 yea + 1*1 mon - 3*1/3 wee + 2/2 day - (2*12 hou 3*20 min 80 sec) '), 33578920.0)
		self.assertEqual(str2sec('2*.5y+1*1mo-3*1/3w+2/2d-(2*12h3*20m80s) '), 33578920.0)
		self.assertEqual(str2sec('1ye -2mo -3we -4da -5ho -6mi -7se'), 24119633)
		# month and year in days :
		self.assertEqual(float(str2sec("1 month")) / 60 / 60 / 24, 30.4375)
		self.assertEqual(float(str2sec("1 year")) / 60 / 60 / 24, 365.25)

