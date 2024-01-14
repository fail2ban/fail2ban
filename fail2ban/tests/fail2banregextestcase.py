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

import os
import sys
import tempfile
import unittest

from ..client import fail2banregex
from ..client.fail2banregex import Fail2banRegex, get_opt_parser, exec_command_line, output, str2LogLevel
from .utils import setUpMyTime, tearDownMyTime, LogCaptureTestCase, logSys
from .utils import CONFIG_DIR


fail2banregex.logSys = logSys
def _test_output(*args):
	logSys.notice('output: %s', args[0])

fail2banregex.output = _test_output

TEST_CONFIG_DIR = os.path.join(os.path.dirname(__file__), "config")
TEST_FILES_DIR = os.path.join(os.path.dirname(__file__), "files")

DEV_NULL = None

def _Fail2banRegex(*args):
	parser = get_opt_parser()
	(opts, args) = parser.parse_args(list(args))
	# put down log-level if expected, because of too many debug-messages:
	if opts.log_level in ("notice", "warning"):
		logSys.setLevel(str2LogLevel(opts.log_level))
	return (opts, args, Fail2banRegex(opts))

def _test_exec(*args):
	(opts, args, fail2banRegex) = _Fail2banRegex(*args)
	return fail2banRegex.start(args)

class ExitException(Exception):
	def __init__(self, code):
		self.code = code
		self.msg = 'Exit with code: %s' % code

def _test_exec_command_line(*args):
	def _exit(code=0):
		raise ExitException(code)
	global DEV_NULL
	_org = {'exit': sys.exit, 'stdout': sys.stdout, 'stderr': sys.stderr}
	_exit_code = 0
	sys.exit = _exit
	if not DEV_NULL: DEV_NULL = open(os.devnull, "w")
	sys.stderr = sys.stdout = DEV_NULL
	try:
		exec_command_line(list(args))
	except ExitException as e:
		_exit_code = e.code
	finally:
		sys.exit = _org['exit']
		sys.stdout = _org['stdout']
		sys.stderr = _org['stderr']
	return _exit_code

def _reset():
	# reset global warn-counter:
	from ..server.filter import _decode_line_warn
	_decode_line_warn.clear()

STR_00 = "Dec 31 11:59:59 [sshd] error: PAM: Authentication failure for kevin from 192.0.2.0"
STR_00_NODT = "[sshd] error: PAM: Authentication failure for kevin from 192.0.2.0"

RE_00 = r"(?:(?:Authentication failure|Failed [-/\w+]+) for(?: [iI](?:llegal|nvalid) user)?|[Ii](?:llegal|nvalid) user|ROOT LOGIN REFUSED) .*(?: from|FROM) <HOST>"
RE_00_ID = r"Authentication failure for <F-ID>.*?</F-ID> from <ADDR>$"
RE_00_USER = r"Authentication failure for <F-USER>.*?</F-USER> from <ADDR>$"

FILENAME_01 = os.path.join(TEST_FILES_DIR, "testcase01.log")
FILENAME_02 = os.path.join(TEST_FILES_DIR, "testcase02.log")
FILENAME_WRONGCHAR = os.path.join(TEST_FILES_DIR, "testcase-wrong-char.log")

# STR_ML_SSHD -- multiline log-excerpt with two sessions:
#   192.0.2.1 (sshd[32307]) makes 2 failed attempts using public keys (without "Disconnecting: Too many authentication"),
#     and delayed success on accepted (STR_ML_SSHD_OK) or no success by close on preauth phase (STR_ML_SSHD_FAIL)
#   192.0.2.2 (sshd[32310]) makes 2 failed attempts using public keys (with "Disconnecting: Too many authentication"),
#     and closed on preauth phase
STR_ML_SSHD = """Nov 28 09:16:03 srv sshd[32307]: Failed publickey for git from 192.0.2.1 port 57904 ssh2: ECDSA 0e:ff:xx:xx:xx:xx:xx:xx:xx:xx:xx:...
Nov 28 09:16:03 srv sshd[32307]: Failed publickey for git from 192.0.2.1 port 57904 ssh2: RSA 04:bc:xx:xx:xx:xx:xx:xx:xx:xx:xx:...
Nov 28 09:16:03 srv sshd[32307]: Postponed publickey for git from 192.0.2.1 port 57904 ssh2 [preauth]
Nov 28 09:16:05 srv sshd[32310]: Failed publickey for git from 192.0.2.2 port 57910 ssh2: ECDSA 1e:fe:xx:xx:xx:xx:xx:xx:xx:xx:xx:...
Nov 28 09:16:05 srv sshd[32310]: Failed publickey for git from 192.0.2.2 port 57910 ssh2: RSA 14:ba:xx:xx:xx:xx:xx:xx:xx:xx:xx:...
Nov 28 09:16:05 srv sshd[32310]: Disconnecting: Too many authentication failures for git [preauth]
Nov 28 09:16:05 srv sshd[32310]: Connection closed by 192.0.2.2 [preauth]"""
STR_ML_SSHD_OK   = "Nov 28 09:16:06 srv sshd[32307]: Accepted publickey for git from 192.0.2.1 port 57904 ssh2: DSA 36:48:xx:xx:xx:xx:xx:xx:xx:xx:xx:..."
STR_ML_SSHD_FAIL = "Nov 28 09:16:06 srv sshd[32307]: Connection closed by 192.0.2.1 [preauth]"


FILENAME_SSHD = os.path.join(TEST_FILES_DIR, "logs", "sshd")
FILTER_SSHD = os.path.join(CONFIG_DIR, 'filter.d', 'sshd.conf')
FILENAME_ZZZ_SSHD = os.path.join(TEST_FILES_DIR, 'zzz-sshd-obsolete-multiline.log')
FILTER_ZZZ_SSHD = os.path.join(TEST_CONFIG_DIR, 'filter.d', 'zzz-sshd-obsolete-multiline.conf')

FILENAME_ZZZ_GEN = os.path.join(TEST_FILES_DIR, "logs", "zzz-generic-example")
FILTER_ZZZ_GEN = os.path.join(TEST_CONFIG_DIR, 'filter.d', 'zzz-generic-example.conf')


class Fail2banRegexTest(LogCaptureTestCase):

	def setUp(self):
		"""Call before every test case."""
		LogCaptureTestCase.setUp(self)
		setUpMyTime()
		_reset()

	def tearDown(self):
		"""Call after every test case."""
		LogCaptureTestCase.tearDown(self)
		tearDownMyTime()

	def testWrongRE(self):
		self.assertFalse(_test_exec(
			"test", r".** from <HOST>$"
		))
		self.assertLogged("Unable to compile regular expression")
		self.assertLogged("multiple repeat", "at position 2", all=False); # details of failed compilation
		self.pruneLog()
		self.assertFalse(_test_exec(
			"test", r"^(?:(?P<type>A)|B)? (?(typo)...) from <ADDR>"
		))
		self.assertLogged("Unable to compile regular expression")
		self.assertLogged("unknown group name", "at position 23", all=False); # details of failed compilation

	def testWrongIngnoreRE(self):
		self.assertFalse(_test_exec(
			"--datepattern", "{^LN-BEG}EPOCH",
			"test", r".*? from <HOST>$", r".**"
		))
		self.assertLogged("Unable to compile regular expression")
		self.assertLogged("multiple repeat", "at position 2", all=False); # details of failed compilation

	def testWrongFilterOptions(self):
		self.assertFalse(_test_exec(
			"test", "flt[a='x,y,z',b=z,y,x]"
		))
		self.assertLogged("Wrong filter name or options", "wrong syntax at 14: y,x", all=True)

	def testDirectFound(self):
		self.assertTrue(_test_exec(
			"--datepattern", r"^(?:%a )?%b %d %H:%M:%S(?:\.%f)?(?: %ExY)?",
			"--print-all-matched", "--print-no-missed",
			STR_00,
			r"Authentication failure for .*? from <HOST>$"
		))
		self.assertLogged('Lines: 1 lines, 0 ignored, 1 matched, 0 missed')

	def testDirectNotFound(self):
		self.assertTrue(_test_exec(
			"--print-all-missed",
			STR_00,
			r"XYZ from <HOST>$"
		))
		self.assertLogged('Lines: 1 lines, 0 ignored, 0 matched, 1 missed')

	def testDirectIgnored(self):
		self.assertTrue(_test_exec(
			"--print-all-ignored",
			STR_00,
			r"Authentication failure for .*? from <HOST>$",
			r"kevin from 192.0.2.0$"
		))
		self.assertLogged('Lines: 1 lines, 1 ignored, 0 matched, 0 missed')

	def testDirectRE_1(self):
		self.assertTrue(_test_exec(
			"--datepattern", r"^(?:%a )?%b %d %H:%M:%S(?:\.%f)?(?: %ExY)?",
			"--print-all-matched",
			FILENAME_01, RE_00
		))
		self.assertLogged('Lines: 19 lines, 0 ignored, 16 matched, 3 missed')

		self.assertLogged('Error decoding line');
		self.assertLogged('Continuing to process line ignoring invalid characters')

		self.assertLogged('Dez 31 11:59:59 [sshd] error: PAM: Authentication failure for kevin from 193.168.0.128')
		self.assertLogged('Dec 31 11:59:59 [sshd] error: PAM: Authentication failure for kevin from 87.142.124.10')

	def testDirectRE_1raw(self):
		self.assertTrue(_test_exec(
			"--datepattern", r"^(?:%a )?%b %d %H:%M:%S(?:\.%f)?(?: %ExY)?",
			"--print-all-matched", "--raw",
			FILENAME_01, RE_00
		))
		self.assertLogged('Lines: 19 lines, 0 ignored, 19 matched, 0 missed')

	def testDirectRE_1raw_noDns(self):
		self.assertTrue(_test_exec(
			"--datepattern", r"^(?:%a )?%b %d %H:%M:%S(?:\.%f)?(?: %ExY)?",
			"--print-all-matched", "--raw", "--usedns=no",
			FILENAME_01, RE_00
		))
		self.assertLogged('Lines: 19 lines, 0 ignored, 16 matched, 3 missed')
		# usage of <F-ID>\S+</F-ID> causes raw handling automatically:
		self.pruneLog()
		self.assertTrue(_test_exec(
			"-d", "^Epoch",
			"1490349000 test failed.dns.ch", r"^\s*test <F-ID>\S+</F-ID>"
		))
		self.assertLogged('Lines: 1 lines, 0 ignored, 1 matched, 0 missed', all=True)
		self.assertNotLogged('Unable to find a corresponding IP address')
		# no confusion to IP/CIDR
		self.pruneLog()
		self.assertTrue(_test_exec(
			"-d", "^Epoch", "-o", "id",
			"1490349000 test this/is/some/path/32", r"^\s*test <F-ID>\S+</F-ID>"
		))
		self.assertLogged('this/is/some/path/32', all=True)

	def testDirectRE_2(self):
		self.assertTrue(_test_exec(
			"--datepattern", r"^(?:%a )?%b %d %H:%M:%S(?:\.%f)?(?: %ExY)?",
			"--print-all-matched",
			FILENAME_02, RE_00
		))
		self.assertLogged('Lines: 13 lines, 0 ignored, 5 matched, 8 missed')

	def testVerbose(self):
		self.assertTrue(_test_exec(
			"--datepattern", r"^(?:%a )?%b %d %H:%M:%S(?:\.%f)?(?: %ExY)?",
			"--timezone", "UTC+0200",
			"--verbose", "--verbose-date", "--print-no-missed",
			FILENAME_02, RE_00
		))
		self.assertLogged('Lines: 13 lines, 0 ignored, 5 matched, 8 missed')

		self.assertLogged('141.3.81.106  Sun Aug 14 11:53:59 2005')
		self.assertLogged('141.3.81.106  Sun Aug 14 11:54:59 2005')

	def testVerboseFullSshd(self):
		self.assertTrue(_test_exec(
		"-l", "notice", # put down log-level, because of too many debug-messages
			"-v", "--verbose-date", "--print-all-matched", "--print-all-ignored",
			"-c", CONFIG_DIR,
			FILENAME_SSHD, "sshd.conf"
		))
		# test failure line and not-failure lines both presents:
		self.assertLogged("[29116]: User root not allowed because account is locked",
			"[29116]: Received disconnect from 1.2.3.4", all=True)
		self.pruneLog()
		# show real options:
		self.assertTrue(_test_exec(
		"-l", "notice", # put down log-level, because of too many debug-messages
			"-vv", "-c", CONFIG_DIR,
			"Dec 31 11:59:59 [sshd] error: PAM: Authentication failure for kevin from 192.0.2.1",
			"filter.d/sshd[logtype=short]"
		))
		# tet logtype is specified and set in real options:
		self.assertLogged("Real  filter options :", "'logtype': 'short'", all=True)
		self.assertNotLogged("'logtype': 'file'", "'logtype': 'journal'", all=True)

	def testFastSshd(self):
		self.assertTrue(_test_exec(
		"-l", "notice", # put down log-level, because of too many debug-messages
			"--print-all-matched",
			"-c", CONFIG_DIR,
			FILENAME_ZZZ_SSHD, "sshd.conf[mode=normal]"
		))
		# test failure line and all not-failure lines presents:
		self.assertLogged(
			"[29116]: Connection from 192.0.2.4",
			"[29116]: User root not allowed because account is locked",
			"[29116]: Received disconnect from 192.0.2.4", all=True)

	def testLoadFromJail(self):
		self.assertTrue(_test_exec(
		"-l", "notice", # put down log-level, because of too many debug-messages
			"-c", CONFIG_DIR, '-vv',
			FILENAME_ZZZ_SSHD, "sshd[logtype=short]"
		))
		# test it was jail not filter:
		self.assertLogged(
			"Use %11s jail : %s" % ('','sshd'))

	def testMultilineSshd(self):
		# by the way test of missing lines by multiline in `for bufLine in orgLineBuffer[int(fullBuffer):]`
		self.assertTrue(_test_exec(
		"-l", "notice", # put down log-level, because of too many debug-messages
			"--print-all-matched", "--print-all-missed",
			"-c", os.path.dirname(FILTER_ZZZ_SSHD),
			FILENAME_ZZZ_SSHD, os.path.basename(FILTER_ZZZ_SSHD)
		))
		# test "failure" line presents (2nd part only, because multiline fewer precise):
		self.assertLogged(
			"[29116]: Received disconnect from 192.0.2.4", all=True)

	def testFullGeneric(self):
		# by the way test of ignoreregex (specified in filter file)...
		self.assertTrue(_test_exec(
		"-l", "notice", # put down log-level, because of too many debug-messages
			FILENAME_ZZZ_GEN, FILTER_ZZZ_GEN+"[mode=test]"
		))

	def testDirectMultilineBuf(self):
		# test it with some pre-lines also to cover correct buffer scrolling (all multi-lines printed):
		for preLines in (0, 20):
			self.pruneLog("[test-phase %s]" % preLines)
			self.assertTrue(_test_exec(
				"--usedns", "no", "-d", "^Epoch", "--print-all-matched", "--maxlines", "5", 
				("1490349000 TEST-NL\n"*preLines) + 
				"1490349000 FAIL\n1490349000 TEST1\n1490349001 TEST2\n1490349001 HOST 192.0.2.34",
				r"^\s*FAIL\s*$<SKIPLINES>^\s*HOST <HOST>\s*$"
			))
			self.assertLogged('Lines: %s lines, 0 ignored, 2 matched, %s missed' % (preLines+4, preLines+2))
			# both matched lines were printed:
			self.assertLogged("|  1490349000 FAIL", "|  1490349001 HOST 192.0.2.34", all=True)


	def testDirectMultilineBufDebuggex(self):
		self.assertTrue(_test_exec(
			"--usedns", "no", "-d", "^Epoch", "--debuggex", "--print-all-matched", "--maxlines", "5",
			"1490349000 FAIL\n1490349000 TEST1\n1490349001 TEST2\n1490349001 HOST 192.0.2.34",
			r"^\s*FAIL\s*$<SKIPLINES>^\s*HOST <HOST>\s*$"
		))
		self.assertLogged('Lines: 4 lines, 0 ignored, 2 matched, 2 missed')
		# the sequence in args-dict is currently undefined (so can be 1st argument)
		self.assertLogged("&flags=m", "?flags=m")

	def testSinglelineWithNLinContent(self):
		# 
		self.assertTrue(_test_exec(
			"--usedns", "no", "-d", "^Epoch", "--print-all-matched",
			"-L", "2", "1490349000 FAIL: failure\nhost: 192.0.2.35",
			r"^\s*FAIL:\s*.*\nhost:\s+<HOST>$"
		))
		self.assertLogged('Lines: 2 lines, 0 ignored, 2 matched, 0 missed')

	def testRegexEpochPatterns(self):
		self.assertTrue(_test_exec(
			"-r", "-d", r"^\[{LEPOCH}\]\s+", "--maxlines", "5",
			"[1516469849] 192.0.2.1 FAIL: failure\n"
			"[1516469849551] 192.0.2.2 FAIL: failure\n"
			"[1516469849551000] 192.0.2.3 FAIL: failure\n"
			"[1516469849551.000] 192.0.2.4 FAIL: failure",
			r"^<HOST> FAIL\b"
		))
		self.assertLogged('Lines: 4 lines, 0 ignored, 4 matched, 0 missed')

	def testRegexSubnet(self):
		self.assertTrue(_test_exec(
			"-vv", "-d", r"^\[{LEPOCH}\]\s+", "--maxlines", "5",
			"[1516469849] 192.0.2.1 FAIL: failure\n"
			"[1516469849] 192.0.2.1/24 FAIL: failure\n"
			"[1516469849] 2001:DB8:FF:FF::1 FAIL: failure\n"
			"[1516469849] 2001:DB8:FF:FF::1/60 FAIL: failure\n",
			r"^<SUBNET> FAIL\b"
		))
		self.assertLogged('Lines: 4 lines, 0 ignored, 4 matched, 0 missed')
		self.assertLogged('192.0.2.0/24', '2001:db8:ff:f0::/60', all=True)

	def testFrmtOutput(self):
		# id/ip only:
		self.assertTrue(_test_exec('-o', 'id', STR_00, RE_00_ID))
		self.assertLogged('output: %s' % 'kevin')
		self.pruneLog()
		# multiple id combined to a tuple (id, tuple_id):
		self.assertTrue(_test_exec('-o', 'id', '-d', '{^LN-BEG}EPOCH',
			'1591983743.667 192.0.2.1 192.0.2.2',
			r'^\s*<F-ID/> <F-TUPLE_ID>\S+</F-TUPLE_ID>'))
		self.assertLogged('output: %s' % str(('192.0.2.1', '192.0.2.2')))
		self.pruneLog()
		# multiple id combined to a tuple, id first - (id, tuple_id_1, tuple_id_2):
		self.assertTrue(_test_exec('-o', 'id', '-d', '{^LN-BEG}EPOCH',
			'1591983743.667 left 192.0.2.3 right',
			r'^\s*<F-TUPLE_ID_1>\S+</F-TUPLE_ID_1> <F-ID/> <F-TUPLE_ID_2>\S+</F-TUPLE_ID_2>'))
		self.assertLogged('output: %s' % str(('192.0.2.3', 'left', 'right')))
		self.pruneLog()
		# id had higher precedence as ip-address:
		self.assertTrue(_test_exec('-o', 'id', '-d', '{^LN-BEG}EPOCH',
			'1591983743.667 left [192.0.2.4]:12345 right',
			r'^\s*<F-TUPLE_ID_1>\S+</F-TUPLE_ID_1> <F-ID><ADDR>:<F-PORT/></F-ID> <F-TUPLE_ID_2>\S+</F-TUPLE_ID_2>'))
		self.assertLogged('output: %s' % str(('[192.0.2.4]:12345', 'left', 'right')))
		self.pruneLog()
		# ip is not id anymore (if IP-address deviates from ID):
		self.assertTrue(_test_exec('-o', 'ip', '-d', '{^LN-BEG}EPOCH',
			'1591983743.667 left [192.0.2.4]:12345 right',
			r'^\s*<F-TUPLE_ID_1>\S+</F-TUPLE_ID_1> <F-ID><ADDR>:<F-PORT/></F-ID> <F-TUPLE_ID_2>\S+</F-TUPLE_ID_2>'))
		self.assertNotLogged('output: %s' % str(('[192.0.2.4]:12345', 'left', 'right')))
		self.assertLogged('output: %s' % '192.0.2.4')
		self.pruneLog()
		self.assertTrue(_test_exec('-o', 'ID:<fid> | IP:<ip>', '-d', '{^LN-BEG}EPOCH',
			'1591983743.667 left [192.0.2.4]:12345 right',
			r'^\s*<F-TUPLE_ID_1>\S+</F-TUPLE_ID_1> <F-ID><ADDR>:<F-PORT/></F-ID> <F-TUPLE_ID_2>\S+</F-TUPLE_ID_2>'))
		self.assertLogged('output: %s' % 'ID:'+str(('[192.0.2.4]:12345', 'left', 'right'))+' | IP:192.0.2.4')
		self.pruneLog()
		# row with id :
		self.assertTrue(_test_exec('-o', 'row', STR_00, RE_00_ID))
		self.assertLogged('output: %s' % "['kevin'", "'ip4': '192.0.2.0'", "'fid': 'kevin'", all=True)
		self.pruneLog()
		# row with ip :
		self.assertTrue(_test_exec('-o', 'row', STR_00, RE_00_USER))
		self.assertLogged('output: %s' % "['192.0.2.0'", "'ip4': '192.0.2.0'", "'user': 'kevin'", all=True)
		self.pruneLog()
		# log msg :
		self.assertTrue(_test_exec('-o', 'msg', STR_00, RE_00_USER))
		self.assertLogged('output: %s' % STR_00)
		self.pruneLog()
		# item of match (user):
		self.assertTrue(_test_exec('-o', 'user', STR_00, RE_00_USER))
		self.assertLogged('output: %s' % 'kevin')
		self.pruneLog()
		# complex substitution using tags (ip, user, family):
		self.assertTrue(_test_exec('-o', '<ip>, <F-USER>, <family>', STR_00, RE_00_USER))
		self.assertLogged('output: %s' % '192.0.2.0, kevin, inet4')
		self.pruneLog()

	def testStalledIPByNoFailFrmtOutput(self):
		opts = (
			'-c', CONFIG_DIR,
			"-d", r"^(?:%a )?%b %d %H:%M:%S(?:\.%f)?(?: %ExY)?",
		)
		log = (
			'May 27 00:16:33 host sshd[2364]: User root not allowed because account is locked\n'
			'May 27 00:16:33 host sshd[2364]: Received disconnect from 192.0.2.76 port 58846:11: Bye Bye [preauth]'
		)
		_test = lambda *args: _test_exec(*(opts + args))
		# with MLFID from prefregex and IP after failure obtained from F-NOFAIL RE:
		self.assertTrue(_test('-o', 'IP:<ip>', log, 'sshd.conf'))
		self.assertLogged('IP:192.0.2.76')
		self.pruneLog()
		# test diverse ID/IP constellations:
		def _test_variants(flt="sshd.conf", prefix=""):
			# with different ID/IP from failregex (ID/User from first, IP from second message):
			self.assertTrue(_test('-o', 'ID:"<fid>" | IP:<ip> | U:<F-USER>', log, 
				flt+'[failregex="'
				  '^'+prefix+r'<F-ID>User <F-USER>\S+</F-USER></F-ID> not allowed'+'\n'
				  '^'+prefix+r'Received disconnect from <ADDR>'
				'"]'))
			self.assertLogged('ID:"User root" | IP:192.0.2.76 | U:root')
			self.pruneLog()
			# with different ID/IP from failregex (User from first, ID and IP from second message):
			self.assertTrue(_test('-o', 'ID:"<fid>" | IP:<ip> | U:<F-USER>', log, 
				flt+'[failregex="'
				  '^'+prefix+r'User <F-USER>\S+</F-USER> not allowed'+'\n'
				  '^'+prefix+r'Received disconnect from <F-ID><ADDR> port \d+</F-ID>'
				'"]'))
			self.assertLogged('ID:"192.0.2.76 port 58846" | IP:192.0.2.76 | U:root')
			self.pruneLog()
		# first with sshd and prefregex:
		_test_variants()
		# the same without prefregex and MLFID directly in failregex (no merge with prefregex groups):
		_test_variants('common.conf', prefix=r"\s*\S+ sshd\[<F-MLFID>\d+</F-MLFID>\]:\s+")

	def testNoDateTime(self):
		# datepattern doesn't match:
		self.assertTrue(_test_exec('-d', '{^LN-BEG}EPOCH', '-o', 'Found-ID:<F-ID>', STR_00_NODT, RE_00_ID))
		self.assertLogged(
			"Found a match but no valid date/time found",
			"Match without a timestamp:",
			"Found-ID:kevin", all=True)
		self.pruneLog()
		# explicitly no datepattern:
		self.assertTrue(_test_exec('-d', '{NONE}', '-o', 'Found-ID:<F-ID>', STR_00_NODT, RE_00_ID))
		self.assertLogged(
			"Found-ID:kevin", all=True)
		self.assertNotLogged(
			"Found a match but no valid date/time found",
			"Match without a timestamp:", all=True)

	def testIncompleteDateTime(self):
		# datepattern in followed lines doesn't match previously known pattern + line is too short
		# (logging break-off, no flush, etc):
		self.assertTrue(_test_exec(
			'-o', 'Found-ADDR:<ip>',
			'192.0.2.1 - - [02/May/2021:18:40:55 +0100] "GET / HTTP/1.1" 302 328 "-" "Mozilla/5.0" "-"\n'
			'192.0.2.2 - - [02/May/2021:18:40:55 +0100\n'
			'192.0.2.3 - - [02/May/2021:18:40:55',
			'^<ADDR>'))
		self.assertLogged(
			"Found-ADDR:192.0.2.1", "Found-ADDR:192.0.2.2", "Found-ADDR:192.0.2.3", all=True)	

	def testFrmtOutputWrapML(self):
		unittest.F2B.SkipIfCfgMissing(stock=True)
		# complex substitution using tags and message (ip, user, msg):
		self.assertTrue(_test_exec('-o', '<ip>, <F-USER>, <msg>',
			'-c', CONFIG_DIR, '--usedns', 'no',
			STR_ML_SSHD + "\n" + STR_ML_SSHD_OK, 'sshd.conf[logtype=short, publickey=invalid]'))
		# be sure we don't have IP in one line and have it in another:
		lines = STR_ML_SSHD.split("\n")
		self.assertTrue('192.0.2.2' not in lines[-2] and '192.0.2.2' in lines[-1])
		# but both are in output "merged" with IP and user:
		self.assertLogged(
			'192.0.2.2, git, '+lines[-2],
			'192.0.2.2, git, '+lines[-1],
			all=True)
		# nothing should be found for 192.0.2.1 (mode is not aggressive):
		self.assertNotLogged('192.0.2.1, git, ')

		# test with publickey (nofail) - would not produce output for 192.0.2.1 because accepted:
		self.pruneLog("[test-phase 1] mode=aggressive & publickey=nofail + OK (accepted)")
		self.assertTrue(_test_exec('-o', '<ip>, <F-USER>, <msg>',
			'-c', CONFIG_DIR, '--usedns', 'no',
			STR_ML_SSHD + "\n" + STR_ML_SSHD_OK, 'sshd.conf[logtype=short, mode=aggressive]'))
		self.assertLogged(
			'192.0.2.2, git, '+lines[-4],
			'192.0.2.2, git, '+lines[-3],
			'192.0.2.2, git, '+lines[-2],
			'192.0.2.2, git, '+lines[-1],
			all=True)
		# nothing should be found for 192.0.2.1 (access gained so failures ignored):
		self.assertNotLogged('192.0.2.1, git, ')

		# now same test but "accepted" replaced with "closed" on preauth phase:
		self.pruneLog("[test-phase 2] mode=aggressive & publickey=nofail + FAIL (closed on preauth)")
		self.assertTrue(_test_exec('-o', '<ip>, <F-USER>, <msg>',
			'-c', CONFIG_DIR, '--usedns', 'no',
			STR_ML_SSHD + "\n" + STR_ML_SSHD_FAIL, 'sshd.conf[logtype=short, mode=aggressive]'))
		# 192.0.2.1 should be found for every failure (2x failed key + 1x closed):
		lines = STR_ML_SSHD.split("\n")[0:2] + STR_ML_SSHD_FAIL.split("\n")[-1:]
		self.assertLogged(
			'192.0.2.1, git, '+lines[-3],
			'192.0.2.1, git, '+lines[-2],
			'192.0.2.1, git, '+lines[-1],
			all=True)

	def testOutputNoPendingFailuresAfterGained(self):
		unittest.F2B.SkipIfCfgMissing(stock=True)
		# connect finished without authorization must generate a failure, because
		# connect started will produce pending failure which gets reset by gained
		# connect authorized.
		self.assertTrue(_test_exec('-o', 'failure from == <ip> ==',
			'-c', CONFIG_DIR, '-d', '{NONE}',
			'svc[1] connect started 192.0.2.3\n'
			'svc[1] connect finished 192.0.2.3\n'
			'svc[2] connect started 192.0.2.4\n'
			'svc[2] connect authorized 192.0.2.4\n'
			'svc[2] connect finished 192.0.2.4\n',
			r'common.conf[prefregex="^svc\[<F-MLFID>\d+</F-MLFID>\] connect <F-CONTENT>.+</F-CONTENT>$"'
			', failregex="'
			'^started\n'
			'^<F-NOFAIL><F-MLFFORGET>finished</F-MLFFORGET></F-NOFAIL> <ADDR>\n'
			'^<F-MLFGAINED>authorized</F-MLFGAINED> <ADDR>'
			'", maxlines=1]'
		))
		self.assertLogged('failure from == 192.0.2.3 ==')
		self.assertNotLogged('failure from == 192.0.2.4 ==')

	def testWrongFilterFile(self):
		# use test log as filter file to cover error cases...
		self.assertFalse(_test_exec(
			FILENAME_ZZZ_GEN, FILENAME_ZZZ_GEN
		))

	def testWronChar(self):
		unittest.F2B.SkipIfCfgMissing(stock=True)
		self.assertTrue(_test_exec(
		"-l", "notice", # put down log-level, because of too many debug-messages
			"--datepattern", r"^(?:%a )?%b %d %H:%M:%S(?:\.%f)?(?: %ExY)?",
			FILENAME_WRONGCHAR, FILTER_SSHD
		))
		self.assertLogged('Lines: 4 lines, 0 ignored, 2 matched, 2 missed')

		self.assertLogged('Error decoding line')
		self.assertLogged('Continuing to process line ignoring invalid characters:')

		self.assertLogged('Nov  8 00:16:12 main sshd[32548]: input_userauth_request: invalid user llinco')
		self.assertLogged('Nov  8 00:16:12 main sshd[32547]: pam_succeed_if(sshd:auth): error retrieving information about user llinco')

	def testWronCharDebuggex(self):
		unittest.F2B.SkipIfCfgMissing(stock=True)
		self.assertTrue(_test_exec(
		"-l", "notice", # put down log-level, because of too many debug-messages
			"--datepattern", r"^(?:%a )?%b %d %H:%M:%S(?:\.%f)?(?: %ExY)?",
			"--debuggex", "--print-all-matched",
			FILENAME_WRONGCHAR, FILTER_SSHD,
			r"llinco[^\\]"
		))
		self.assertLogged('Error decoding line')
		self.assertLogged('Lines: 4 lines, 1 ignored, 2 matched, 1 missed')

		self.assertLogged('https://')

	def testNLCharAsPartOfUniChar(self):
		fname = tempfile.mktemp(prefix='tmp_fail2ban', suffix='uni')
		# test two multi-byte encodings (both contains `\x0A` in either \x02\x0A or \x0A\x02):
		for enc in ('utf-16be', 'utf-16le'):
			self.pruneLog("[test-phase encoding=%s]" % enc)
			try:
				fout = open(fname, 'wb')
				# test on unicode string containing \x0A as part of uni-char,
				# it must produce exactly 2 lines (both are failures):
				for l in (
					'1490349000 \u20AC Failed auth: invalid user Test\u020A from 192.0.2.1\n',
					'1490349000 \u20AC Failed auth: invalid user TestI from 192.0.2.2\n'
				):
					fout.write(l.encode(enc))
				fout.close()

				self.assertTrue(_test_exec(
				"-l", "notice", # put down log-level, because of too many debug-messages
					"--encoding", enc,
					"--datepattern", r"^EPOCH",
					fname, r"Failed .* from <HOST>",
				))

				self.assertLogged(" encoding : %s" % enc,
					"Lines: 2 lines, 0 ignored, 2 matched, 0 missed", all=True)
				self.assertNotLogged("Missed line(s)")
			finally:
				fout.close()
				os.unlink(fname)

	def testExecCmdLine_Usage(self):
		self.assertNotEqual(_test_exec_command_line(), 0)
		self.pruneLog()
		self.assertEqual(_test_exec_command_line('-V'), 0)
		self.assertLogged(fail2banregex.normVersion())
		self.pruneLog()
		self.assertEqual(_test_exec_command_line('--version'), 0)

	def testExecCmdLine_Direct(self):
		self.assertEqual(_test_exec_command_line(
			'-l', 'info',
			STR_00, r"Authentication failure for .*? from <HOST>$"
		), 0)
		self.assertLogged('Lines: 1 lines, 0 ignored, 1 matched, 0 missed')
		
	def testExecCmdLine_MissFailID(self):
		self.assertNotEqual(_test_exec_command_line(
			'-l', 'info',
			STR_00, r"Authentication failure"
		), 0)
		self.assertLogged('No failure-id group in ')

	def testExecCmdLine_ErrorParam(self):
		# single line error:
		self.assertNotEqual(_test_exec_command_line(
			'-l', 'notice', '-d', '%:%.%-', 'LOG', 'RE'
		), 0)
		self.assertLogged('ERROR: Failed to set datepattern')
		# verbose (traceback/callstack):
		self.pruneLog()
		self.assertNotEqual(_test_exec_command_line(
			'-v', '-d', '%:%.%-', 'LOG', 'RE'
		), 0)
		self.assertLogged('Failed to set datepattern')

	def testLogtypeSystemdJournal(self): # pragma: no cover
		if not fail2banregex.FilterSystemd:
			raise unittest.SkipTest('Skip test because no systemd backend available')
		self.assertTrue(_test_exec(
			"systemd-journal", FILTER_ZZZ_GEN
			  +'[journalmatch="SYSLOG_IDENTIFIER=\x01\x02dummy\x02\x01",'
				+' failregex="^\x00\x01\x02dummy regex, never match <F-ID>xxx</F-ID>"]'
		))
		self.assertLogged("'logtype': 'journal'")
		self.assertNotLogged("'logtype': 'file'")
		self.assertLogged('Lines: 0 lines, 0 ignored, 0 matched, 0 missed')
		self.pruneLog()
		# logtype specified explicitly (should win in filter):
		self.assertTrue(_test_exec(
			"systemd-journal", FILTER_ZZZ_GEN
			  +'[logtype=file,'
			  +' journalmatch="SYSLOG_IDENTIFIER=\x01\x02dummy\x02\x01",'
				+' failregex="^\x00\x01\x02dummy regex, never match <F-ID>xxx</F-ID>"]'
		))
		self.assertLogged("'logtype': 'file'")
		self.assertNotLogged("'logtype': 'journal'")
