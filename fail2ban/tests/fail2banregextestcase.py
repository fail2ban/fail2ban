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

__author__ = "Serg Brester"
__copyright__ = "Copyright (c) 2015 Serg G. Brester (sebres), 2008- Fail2Ban Contributors"
__license__ = "GPL"

from __builtin__ import open as fopen
import unittest
import getpass
import os
import sys
import time
import tempfile
import uuid

try:
	from systemd import journal
except ImportError:
	journal = None

from ..client import fail2banregex
from ..client.fail2banregex import Fail2banRegex, get_opt_parser, output
from .utils import LogCaptureTestCase, logSys


fail2banregex.logSys = logSys
def _test_output(*args):
	logSys.info(args[0])

fail2banregex.output = _test_output

CONF_FILES_DIR = os.path.abspath(
	os.path.join(os.path.dirname(__file__),"..", "..", "config"))
TEST_FILES_DIR = os.path.join(os.path.dirname(__file__), "files")


def _Fail2banRegex(*args):
	parser = get_opt_parser()
	(opts, args) = parser.parse_args(list(args))
	return (opts, args, Fail2banRegex(opts))

class Fail2banRegexTest(LogCaptureTestCase):

	RE_00 = r"(?:(?:Authentication failure|Failed [-/\w+]+) for(?: [iI](?:llegal|nvalid) user)?|[Ii](?:llegal|nvalid) user|ROOT LOGIN REFUSED) .*(?: from|FROM) <HOST>"

	FILENAME_01 = os.path.join(TEST_FILES_DIR, "testcase01.log")
	FILENAME_02 = os.path.join(TEST_FILES_DIR, "testcase02.log")
	FILENAME_WRONGCHAR = os.path.join(TEST_FILES_DIR, "testcase-wrong-char.log")

	FILTER_SSHD = os.path.join(CONF_FILES_DIR, 'filter.d', 'sshd.conf')

	def setUp(self):
		"""Call before every test case."""
		LogCaptureTestCase.setUp(self)

	def tearDown(self):
		"""Call after every test case."""
		LogCaptureTestCase.tearDown(self)

	def testWrongRE(self):
		(opts, args, fail2banRegex) = _Fail2banRegex(
			"test", r".** from <HOST>$"
		)
		self.assertRaises(Exception, lambda: fail2banRegex.start(opts, args))
		self.assertLogged("Unable to compile regular expression")

	def testWrongIngnoreRE(self):
		(opts, args, fail2banRegex) = _Fail2banRegex(
			"test", r".*? from <HOST>$", r".**"
		)
		self.assertRaises(Exception, lambda: fail2banRegex.start(opts, args))
		self.assertLogged("Unable to compile regular expression")

	def testDirectFound(self):
		(opts, args, fail2banRegex) = _Fail2banRegex(
			"--print-all-matched", "--print-no-missed",
			"Dec 31 11:59:59 [sshd] error: PAM: Authentication failure for kevin from 192.0.2.0",
			r"Authentication failure for .*? from <HOST>$"
		)
		self.assertTrue(fail2banRegex.start(opts, args))
		self.assertLogged('Lines: 1 lines, 0 ignored, 1 matched, 0 missed')

	def testDirectNotFound(self):
		(opts, args, fail2banRegex) = _Fail2banRegex(
			"--print-all-missed",
			"Dec 31 11:59:59 [sshd] error: PAM: Authentication failure for kevin from 192.0.2.0",
			r"XYZ from <HOST>$"
		)
		self.assertTrue(fail2banRegex.start(opts, args))
		self.assertLogged('Lines: 1 lines, 0 ignored, 0 matched, 1 missed')

	def testDirectIgnored(self):
		(opts, args, fail2banRegex) = _Fail2banRegex(
			"--print-all-ignored",
			"Dec 31 11:59:59 [sshd] error: PAM: Authentication failure for kevin from 192.0.2.0",
			r"Authentication failure for .*? from <HOST>$",
			r"kevin from 192.0.2.0$"
		)
		self.assertTrue(fail2banRegex.start(opts, args))
		self.assertLogged('Lines: 1 lines, 1 ignored, 0 matched, 0 missed')

	def testDirectRE_1(self):
		(opts, args, fail2banRegex) = _Fail2banRegex(
			"--print-all-matched",
			Fail2banRegexTest.FILENAME_01, 
			Fail2banRegexTest.RE_00
		)
		self.assertTrue(fail2banRegex.start(opts, args))
		self.assertLogged('Lines: 19 lines, 0 ignored, 13 matched, 6 missed')

		self.assertLogged('Error decoding line');
		self.assertLogged('Continuing to process line ignoring invalid characters')

		self.assertLogged('Dez 31 11:59:59 [sshd] error: PAM: Authentication failure for kevin from 193.168.0.128')
		self.assertLogged('Dec 31 11:59:59 [sshd] error: PAM: Authentication failure for kevin from 87.142.124.10')

	def testDirectRE_2(self):
		(opts, args, fail2banRegex) = _Fail2banRegex(
			"--print-all-matched",
			Fail2banRegexTest.FILENAME_02, 
			Fail2banRegexTest.RE_00
		)
		self.assertTrue(fail2banRegex.start(opts, args))
		self.assertLogged('Lines: 13 lines, 0 ignored, 5 matched, 8 missed')

	def testVerbose(self):
		(opts, args, fail2banRegex) = _Fail2banRegex(
			"--verbose", "--print-no-missed",
			Fail2banRegexTest.FILENAME_02, 
			Fail2banRegexTest.RE_00
		)
		self.assertTrue(fail2banRegex.start(opts, args))
		self.assertLogged('Lines: 13 lines, 0 ignored, 5 matched, 8 missed')

		self.assertLogged('141.3.81.106  Fri Aug 14 11:53:59 2015')
		self.assertLogged('141.3.81.106  Fri Aug 14 11:54:59 2015')

	def testWronChar(self):
		(opts, args, fail2banRegex) = _Fail2banRegex(
			Fail2banRegexTest.FILENAME_WRONGCHAR, Fail2banRegexTest.FILTER_SSHD
		)
		self.assertTrue(fail2banRegex.start(opts, args))
		self.assertLogged('Lines: 4 lines, 0 ignored, 2 matched, 2 missed')

		self.assertLogged('Error decoding line');
		self.assertLogged('Continuing to process line ignoring invalid characters:', '2015-01-14 20:00:58 user ');
		self.assertLogged('Continuing to process line ignoring invalid characters:', '2015-01-14 20:00:59 user ');

		self.assertLogged('Nov  8 00:16:12 main sshd[32548]: input_userauth_request: invalid user llinco')
		self.assertLogged('Nov  8 00:16:12 main sshd[32547]: pam_succeed_if(sshd:auth): error retrieving information about user llinco')

	def testWronCharDebuggex(self):
		(opts, args, fail2banRegex) = _Fail2banRegex(
			"--debuggex", "--print-all-matched",
			Fail2banRegexTest.FILENAME_WRONGCHAR, Fail2banRegexTest.FILTER_SSHD
		)
		self.assertTrue(fail2banRegex.start(opts, args))
		self.assertLogged('Lines: 4 lines, 0 ignored, 2 matched, 2 missed')

		self.assertLogged('http://')


