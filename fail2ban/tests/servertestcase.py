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

# Author: Cyril Jaquier
# 

__author__ = "Cyril Jaquier"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import unittest
import time
import tempfile
import os
import locale
import sys
import platform

from ..server.failregex import Regex, FailRegex, RegexException
from ..server.server import Server
from ..server.jail import Jail
from ..server.jailthread import JailThread
from .utils import LogCaptureTestCase
from ..helpers import getLogger
from .. import version

try:
	from ..server import filtersystemd
except ImportError: # pragma: no cover
	filtersystemd = None

TEST_FILES_DIR = os.path.join(os.path.dirname(__file__), "files")


class TestServer(Server):
	def setLogLevel(self, *args, **kwargs):
		pass

	def setLogTarget(self, *args, **kwargs):
		pass


class TransmitterBase(unittest.TestCase):
	
	def setUp(self):
		"""Call before every test case."""
		self.transm = self.server._Server__transm
		sock_fd, sock_name = tempfile.mkstemp('fail2ban.sock', 'transmitter')
		os.close(sock_fd)
		pidfile_fd, pidfile_name = tempfile.mkstemp(
			'fail2ban.pid', 'transmitter')
		os.close(pidfile_fd)
		self.server.start(sock_name, pidfile_name, force=False)
		self.jailName = "TestJail1"
		self.server.addJail(self.jailName, "auto")

	def tearDown(self):
		"""Call after every test case."""
		self.server.quit()

	def setGetTest(self, cmd, inValue, outValue=None, outCode=0, jail=None, repr_=False):
		setCmd = ["set", cmd, inValue]
		getCmd = ["get", cmd]
		if jail is not None:
			setCmd.insert(1, jail)
			getCmd.insert(1, jail)

		if outValue is None:
			outValue = inValue

		def v(x):
			"""Prepare value for comparison"""
			return (repr(x) if repr_ else x)

		self.assertEqual(v(self.transm.proceed(setCmd)), v((outCode, outValue)))
		if not outCode:
			# if we expected to get it set without problem, check new value
			self.assertEqual(v(self.transm.proceed(getCmd)), v((0, outValue)))

	def setGetTestNOK(self, cmd, inValue, jail=None):
		setCmd = ["set", cmd, inValue]
		getCmd = ["get", cmd]
		if jail is not None:
			setCmd.insert(1, jail)
			getCmd.insert(1, jail)

		# Get initial value before trying invalid value
		initValue = self.transm.proceed(getCmd)[1]
		self.assertEqual(self.transm.proceed(setCmd)[0], 1)
		# Check after failed set that value is same as previous
		self.assertEqual(self.transm.proceed(getCmd), (0, initValue))

	def jailAddDelTest(self, cmd, values, jail):
		cmdAdd = "add" + cmd
		cmdDel = "del" + cmd

		self.assertEqual(
			self.transm.proceed(["get", jail, cmd]), (0, []))
		for n, value in enumerate(values):
			ret = self.transm.proceed(["set", jail, cmdAdd, value])
			self.assertEqual((ret[0], sorted(ret[1])), (0, sorted(values[:n+1])))
			ret = self.transm.proceed(["get", jail, cmd])
			self.assertEqual((ret[0], sorted(ret[1])), (0, sorted(values[:n+1])))
		for n, value in enumerate(values):
			ret = self.transm.proceed(["set", jail, cmdDel, value])
			self.assertEqual((ret[0], sorted(ret[1])), (0, sorted(values[n+1:])))
			ret = self.transm.proceed(["get", jail, cmd])
			self.assertEqual((ret[0], sorted(ret[1])), (0, sorted(values[n+1:])))

	def jailAddDelRegexTest(self, cmd, inValues, outValues, jail):
		cmdAdd = "add" + cmd
		cmdDel = "del" + cmd

		self.assertEqual(
			self.transm.proceed(["get", jail, cmd]), (0, []))
		for n, value in enumerate(inValues):
			self.assertEqual(
				self.transm.proceed(["set", jail, cmdAdd, value]),
				(0, outValues[:n+1]))
			self.assertEqual(
				self.transm.proceed(["get", jail, cmd]),
				(0, outValues[:n+1]))
		for n, value in enumerate(inValues):
			self.assertEqual(
				self.transm.proceed(["set", jail, cmdDel, 0]), # First item
				(0, outValues[n+1:]))
			self.assertEqual(
				self.transm.proceed(["get", jail, cmd]),
				(0, outValues[n+1:]))


class Transmitter(TransmitterBase):

	def setUp(self):
		self.server = TestServer()
		super(Transmitter, self).setUp()

	def testStopServer(self):
		self.assertEqual(self.transm.proceed(["stop"]), (0, None))

	def testPing(self):
		self.assertEqual(self.transm.proceed(["ping"]), (0, "pong"))

	def testVersion(self):
		self.assertEqual(self.transm.proceed(["version"]), (0, version.version))

	def testSleep(self):
		t0 = time.time()
		self.assertEqual(self.transm.proceed(["sleep", "1"]), (0, None))
		t1 = time.time()
		# Approx 1 second delay but not faster
		dt = t1 - t0
		self.assertTrue(0.99 < dt < 1.1, msg="Sleep was %g sec" % dt)

	def testDatabase(self):
		tmp, tmpFilename = tempfile.mkstemp(".db", "fail2ban_")
		# Jails present, can't change database
		self.setGetTestNOK("dbfile", tmpFilename)
		self.server.delJail(self.jailName)
		self.setGetTest("dbfile", tmpFilename)
		# the same file name (again no jails / not changed):
		self.setGetTest("dbfile", tmpFilename)
		self.setGetTest("dbpurgeage", "600", 600)
		self.setGetTestNOK("dbpurgeage", "LIZARD")
		# the same file name (again with jails / not changed):
		self.server.addJail(self.jailName, "auto")
		self.setGetTest("dbfile", tmpFilename)
		self.server.delJail(self.jailName)

		# Disable database
		self.assertEqual(self.transm.proceed(
			["set", "dbfile", "None"]),
			(0, None))
		self.assertEqual(self.transm.proceed(
			["get", "dbfile"]),
			(0, None))
		self.assertEqual(self.transm.proceed(
			["set", "dbpurgeage", "500"]),
			(0, None))
		self.assertEqual(self.transm.proceed(
			["get", "dbpurgeage"]),
			(0, None))
		# the same (again with jails / not changed):
		self.server.addJail(self.jailName, "auto")
		self.assertEqual(self.transm.proceed(
			["set", "dbfile", "None"]),
			(0, None))
		os.close(tmp)
		os.unlink(tmpFilename)

	def testAddJail(self):
		jail2 = "TestJail2"
		jail3 = "TestJail3"
		jail4 = "TestJail4"
		self.assertEqual(
			self.transm.proceed(["add", jail2, "polling"]), (0, jail2))
		self.assertEqual(self.transm.proceed(["add", jail3]), (0, jail3))
		self.assertEqual(
			self.transm.proceed(["add", jail4, "invalid backend"])[0], 1)
		self.assertEqual(
			self.transm.proceed(["add", jail4, "auto"]), (0, jail4))
		# Duplicate Jail
		self.assertEqual(
			self.transm.proceed(["add", self.jailName, "polling"])[0], 1)
		# All name is reserved
		self.assertEqual(
			self.transm.proceed(["add", "all", "polling"])[0], 1)

	def testStartStopJail(self):
		self.assertEqual(
			self.transm.proceed(["start", self.jailName]), (0, None))
		time.sleep(1)
		self.assertEqual(
			self.transm.proceed(["stop", self.jailName]), (0, None))
		self.assertTrue(self.jailName not in self.server._Server__jails)

	def testStartStopAllJail(self):
		self.server.addJail("TestJail2", "auto")
		self.assertEqual(
			self.transm.proceed(["start", self.jailName]), (0, None))
		self.assertEqual(
			self.transm.proceed(["start", "TestJail2"]), (0, None))
		# yoh: workaround for gh-146.  I still think that there is some
		#      race condition and missing locking somewhere, but for now
		#      giving it a small delay reliably helps to proceed with tests
		time.sleep(0.1)
		self.assertEqual(self.transm.proceed(["stop", "all"]), (0, None))
		time.sleep(1)
		self.assertTrue(self.jailName not in self.server._Server__jails)
		self.assertTrue("TestJail2" not in self.server._Server__jails)

	def testJailIdle(self):
		self.assertEqual(
			self.transm.proceed(["set", self.jailName, "idle", "on"]),
			(0, True))
		self.assertEqual(
			self.transm.proceed(["set", self.jailName, "idle", "off"]),
			(0, False))
		self.assertEqual(
			self.transm.proceed(["set", self.jailName, "idle", "CAT"])[0],
			1)

	def testJailFindTime(self):
		self.setGetTest("findtime", "120", 120, jail=self.jailName)
		self.setGetTest("findtime", "60", 60, jail=self.jailName)
		self.setGetTest("findtime", "-60", -60, jail=self.jailName)
		self.setGetTestNOK("findtime", "Dog", jail=self.jailName)

	def testJailBanTime(self):
		self.setGetTest("bantime", "600", 600, jail=self.jailName)
		self.setGetTest("bantime", "50", 50, jail=self.jailName)
		self.setGetTest("bantime", "-50", -50, jail=self.jailName)
		self.setGetTestNOK("bantime", "Cat", jail=self.jailName)

	def testDatePattern(self):
		self.setGetTest("datepattern", "%%%Y%m%d%H%M%S",
			("%%%Y%m%d%H%M%S", "%YearMonthDay24hourMinuteSecond"),
			jail=self.jailName)
		self.setGetTest(
			"datepattern", "Epoch", (None, "Epoch"), jail=self.jailName)
		self.setGetTest(
			"datepattern", "TAI64N", (None, "TAI64N"), jail=self.jailName)
		self.setGetTestNOK("datepattern", "%Cat%a%%%g", jail=self.jailName)

	def testJailUseDNS(self):
		self.setGetTest("usedns", "yes", jail=self.jailName)
		self.setGetTest("usedns", "warn", jail=self.jailName)
		self.setGetTest("usedns", "no", jail=self.jailName)

		# Safe default should be "no"
		value = "Fish"
		self.assertEqual(
			self.transm.proceed(["set", self.jailName, "usedns", value]),
			(0, "no"))

	def testJailBanIP(self):
		self.server.startJail(self.jailName) # Jail must be started

		self.assertEqual(
			self.transm.proceed(["set", self.jailName, "banip", "127.0.0.1"]),
			(0, "127.0.0.1"))
		time.sleep(1) # Give chance to ban
		self.assertEqual(
			self.transm.proceed(["set", self.jailName, "banip", "Badger"]),
			(0, "Badger")) #NOTE: Is IP address validated? Is DNS Lookup done?
		time.sleep(1) # Give chance to ban
		# Unban IP
		self.assertEqual(
			self.transm.proceed(
				["set", self.jailName, "unbanip", "127.0.0.1"]),
			(0, "127.0.0.1"))
		# Unban IP which isn't banned
		self.assertEqual(
			self.transm.proceed(
				["set", self.jailName, "unbanip", "192.168.1.1"])[0],1)

	def testJailMaxRetry(self):
		self.setGetTest("maxretry", "5", 5, jail=self.jailName)
		self.setGetTest("maxretry", "2", 2, jail=self.jailName)
		self.setGetTest("maxretry", "-2", -2, jail=self.jailName)
		self.setGetTestNOK("maxretry", "Duck", jail=self.jailName)

	def testJailMaxLines(self):
		self.setGetTest("maxlines", "5", 5, jail=self.jailName)
		self.setGetTest("maxlines", "2", 2, jail=self.jailName)
		self.setGetTestNOK("maxlines", "-2", jail=self.jailName)
		self.setGetTestNOK("maxlines", "Duck", jail=self.jailName)

	def testJailLogEncoding(self):
		self.setGetTest("logencoding", "UTF-8", jail=self.jailName)
		self.setGetTest("logencoding", "ascii", jail=self.jailName)
		self.setGetTest("logencoding", "auto", locale.getpreferredencoding(),
			jail=self.jailName)
		self.setGetTestNOK("logencoding", "Monkey", jail=self.jailName)

	def testJailLogPath(self):
		self.jailAddDelTest(
			"logpath",
			[
				os.path.join(TEST_FILES_DIR, "testcase01.log"),
				os.path.join(TEST_FILES_DIR, "testcase02.log"),
				os.path.join(TEST_FILES_DIR, "testcase03.log"),
			],
			self.jailName
		)
		# Try duplicates
		value = os.path.join(TEST_FILES_DIR, "testcase04.log")
		self.assertEqual(
			self.transm.proceed(["set", self.jailName, "addlogpath", value]),
			(0, [value]))
		# Will silently ignore duplicate
		self.assertEqual(
			self.transm.proceed(["set", self.jailName, "addlogpath", value]),
			(0, [value]))
		self.assertEqual(
			self.transm.proceed(["get", self.jailName, "logpath"]),
			(0, [value]))
		self.assertEqual(
			self.transm.proceed(["set", self.jailName, "dellogpath", value]),
			(0, []))
		self.assertEqual(
			self.transm.proceed(
				["set", self.jailName, "addlogpath", value, "tail"]),
			(0, [value]))
		self.assertEqual(
			self.transm.proceed(
				["set", self.jailName, "addlogpath", value, "head"]),
			(0, [value]))
		self.assertEqual(
			self.transm.proceed(
				["set", self.jailName, "addlogpath", value, "badger"])[0],
			1)
		self.assertEqual(
			self.transm.proceed(
				["set", self.jailName, "addlogpath", value, value, value])[0],
			1)

	def testJailLogPathInvalidFile(self):
		# Invalid file
		value = "this_file_shouldn't_exist"
		result = self.transm.proceed(
			["set", self.jailName, "addlogpath", value])
		self.assertTrue(isinstance(result[1], IOError))

	def testJailLogPathBrokenSymlink(self):
		# Broken symlink
		name = tempfile.mktemp(prefix='tmp_fail2ban_broken_symlink')
		sname = name + '.slink'
		os.symlink(name, sname)
		result = self.transm.proceed(
			["set", self.jailName, "addlogpath", sname])
		self.assertTrue(isinstance(result[1], IOError))
		os.unlink(sname)

	def testJailIgnoreIP(self):
		self.jailAddDelTest(
			"ignoreip",
			[
				"127.0.0.1",
				"192.168.1.1",
				"8.8.8.8",
			],
			self.jailName
		)

		# Try duplicates
		value = "127.0.0.1"
		self.assertEqual(
			self.transm.proceed(["set", self.jailName, "addignoreip", value]),
			(0, [value]))
		# Will allow duplicate
		#NOTE: Should duplicates be allowed, or silent ignore like logpath?
		self.assertEqual(
			self.transm.proceed(["set", self.jailName, "addignoreip", value]),
			(0, [value, value]))
		self.assertEqual(
			self.transm.proceed(["get", self.jailName, "ignoreip"]),
			(0, [value, value]))
		self.assertEqual(
			self.transm.proceed(["set", self.jailName, "delignoreip", value]),
			(0, [value]))

	def testJailIgnoreCommand(self):
		self.setGetTest("ignorecommand", "bin ", jail=self.jailName)

	def testJailRegex(self):
		self.jailAddDelRegexTest("failregex",
			[
				"user john at <HOST>",
				"Admin user login from <HOST>",
				"failed attempt from <HOST> again",
			],
			[
				"user john at (?:::f{4,6}:)?(?P<host>[\w\-.^_]*\\w)",
				"Admin user login from (?:::f{4,6}:)?(?P<host>[\w\-.^_]*\\w)",
				"failed attempt from (?:::f{4,6}:)?(?P<host>[\w\-.^_]*\\w) again",
			],
			self.jailName
		)

		self.assertEqual(
			self.transm.proceed(
				["set", self.jailName, "addfailregex", "No host regex"])[0],
			1)
		self.assertEqual(
			self.transm.proceed(
				["set", self.jailName, "addfailregex", 654])[0],
			1)

	def testJailIgnoreRegex(self):
		self.jailAddDelRegexTest("ignoreregex",
			[
				"user john",
				"Admin user login from <HOST>",
				"Dont match me!",
			],
			[
				"user john",
				"Admin user login from (?:::f{4,6}:)?(?P<host>[\w\-.^_]*\\w)",
				"Dont match me!",
			],
			self.jailName
		)

		self.assertEqual(
			self.transm.proceed(
				["set", self.jailName, "addignoreregex", "Invalid [regex"])[0],
			1)
		self.assertEqual(
			self.transm.proceed(
				["set", self.jailName, "addignoreregex", 50])[0],
			1)

	def testStatus(self):
		jails = [self.jailName]
		self.assertEqual(self.transm.proceed(["status"]),
			(0, [('Number of jail', len(jails)), ('Jail list', ", ".join(jails))]))
		self.server.addJail("TestJail2", "auto")
		jails.append("TestJail2")
		self.assertEqual(self.transm.proceed(["status"]),
			(0, [('Number of jail', len(jails)), ('Jail list', ", ".join(jails))]))

	def testJailStatus(self):
		self.assertEqual(self.transm.proceed(["status", self.jailName]),
			(0,
				[
					('Filter', [
						('Currently failed', 0),
						('Total failed', 0),
						('File list', [])]
					),
					('Actions', [
						('Currently banned', 0),
						('Total banned', 0),
						('Banned IP list', [])]
					)
				]
			)
		)

	def testJailStatusBasic(self):
		self.assertEqual(self.transm.proceed(["status", self.jailName, "basic"]),
			(0,
				[
					('Filter', [
						('Currently failed', 0),
						('Total failed', 0),
						('File list', [])]
					),
					('Actions', [
						('Currently banned', 0),
						('Total banned', 0),
						('Banned IP list', [])]
					)
				]
			)
		)

	def testJailStatusBasicKwarg(self):
		self.assertEqual(self.transm.proceed(["status", self.jailName, "INVALID"]),
			(0,
				[
					('Filter', [
						('Currently failed', 0),
						('Total failed', 0),
						('File list', [])]
					),
					('Actions', [
						('Currently banned', 0),
						('Total banned', 0),
						('Banned IP list', [])]
					)
				]
			)
		)

	def testJailStatusCymru(self):
		try:
			import dns.exception
			import dns.resolver
		except ImportError:
			value = ['error']
		else:
			value = []

		self.assertEqual(self.transm.proceed(["status", self.jailName, "cymru"]),
			(0,
				[
					('Filter', [
						('Currently failed', 0),
						('Total failed', 0),
						('File list', [])]
					),
					('Actions', [
						('Currently banned', 0),
						('Total banned', 0),
						('Banned IP list', []),
						('Banned ASN list', value),
						('Banned Country list', value),
						('Banned RIR list', value)]
					)
				]
			)
		)

	def testAction(self):
		action = "TestCaseAction"
		cmdList = [
			"actionstart",
			"actionstop",
			"actioncheck",
			"actionban",
			"actionunban",
		]
		cmdValueList = [
			"Action Start",
			"Action Stop",
			"Action Check",
			"Action Ban",
			"Action Unban",
		]

		self.assertEqual(
			self.transm.proceed(["set", self.jailName, "addaction", action]),
			(0, action))
		self.assertEqual(
			self.transm.proceed(
				["get", self.jailName, "actions"])[1][0],
			action)
		for cmd, value in zip(cmdList, cmdValueList):
			self.assertEqual(
				self.transm.proceed(
					["set", self.jailName, "action", action, cmd, value]),
				(0, value))
		for cmd, value in zip(cmdList, cmdValueList):
			self.assertEqual(
				self.transm.proceed(["get", self.jailName, "action", action, cmd]),
				(0, value))
		self.assertEqual(
			self.transm.proceed(
				["set", self.jailName, "action", action, "KEY", "VALUE"]),
			(0, "VALUE"))
		self.assertEqual(
			self.transm.proceed(
				["get", self.jailName, "action", action, "KEY"]),
			(0, "VALUE"))
		self.assertEqual(
			self.transm.proceed(
				["get", self.jailName, "action", action, "InvalidKey"])[0],
			1)
		self.assertEqual(
			self.transm.proceed(
				["set", self.jailName, "action", action, "timeout", "10"]),
			(0, 10))
		self.assertEqual(
			self.transm.proceed(
				["get", self.jailName, "action", action, "timeout"]),
			(0, 10))
		self.assertEqual(
			self.transm.proceed(["set", self.jailName, "delaction", action]),
			(0, None))
		self.assertEqual(
			self.transm.proceed(
				["set", self.jailName, "delaction", "Doesn't exist"])[0],1)

	def testPythonActionMethodsAndProperties(self):
		action = "TestCaseAction"
		try:
			out = self.transm.proceed(
				["set", self.jailName, "addaction", action,
				 os.path.join(TEST_FILES_DIR, "action.d", "action.py"),
				'{"opt1": "value"}'])
			self.assertEqual(out, (0, action))
		except AssertionError:
			if ((2, 6) <= sys.version_info < (2, 6, 5)) \
				and '__init__() keywords must be strings' in out[1]:
				# known issue http://bugs.python.org/issue2646 in 2.6 series
				# since general Fail2Ban warnings are suppressed in normal
				# operation -- let's issue Python's native warning here
				import warnings
				warnings.warn(
					"Your version of Python %s seems to experience a known "
					"issue forbidding correct operation of Fail2Ban: "
					"http://bugs.python.org/issue2646  Upgrade your Python and "
					"meanwhile other intestPythonActionMethodsAndProperties will "
					"be skipped" % (sys.version))
				return
			raise
		self.assertEqual(
			sorted(self.transm.proceed(["get", self.jailName,
				"actionproperties", action])[1]),
			['opt1', 'opt2'])
		self.assertEqual(
			self.transm.proceed(["get", self.jailName, "action", action,
				"opt1"]),
			(0, 'value'))
		self.assertEqual(
			self.transm.proceed(["get", self.jailName, "action", action,
				"opt2"]),
			(0, None))
		self.assertEqual(
			sorted(self.transm.proceed(["get", self.jailName, "actionmethods",
				action])[1]),
			['ban', 'start', 'stop', 'testmethod', 'unban'])
		self.assertEqual(
			self.transm.proceed(["set", self.jailName, "action", action,
				"testmethod", '{"text": "world!"}']),
			(0, 'Hello world! value'))
		self.assertEqual(
			self.transm.proceed(["set", self.jailName, "action", action,
				"opt1", "another value"]),
			(0, 'another value'))
		self.assertEqual(
			self.transm.proceed(["set", self.jailName, "action", action,
				"testmethod", '{"text": "world!"}']),
			(0, 'Hello world! another value'))

	def testNOK(self):
		self.assertEqual(self.transm.proceed(["INVALID", "COMMAND"])[0],1)

	def testSetNOK(self):
		self.assertEqual(
			self.transm.proceed(["set", "INVALID", "COMMAND"])[0],1)

	def testGetNOK(self):
		self.assertEqual(
			self.transm.proceed(["get", "INVALID", "COMMAND"])[0],1)

	def testStatusNOK(self):
		self.assertEqual(
			self.transm.proceed(["status", "INVALID", "COMMAND"])[0],1)

	def testJournalMatch(self):
		if not filtersystemd: # pragma: no cover
			if sys.version_info >= (2, 7):
				raise unittest.SkipTest(
					"systemd python interface not available")
			return
		jailName = "TestJail2"
		self.server.addJail(jailName, "systemd")
		values = [
			"_SYSTEMD_UNIT=sshd.service",
			"TEST_FIELD1=ABC",
			"_HOSTNAME=example.com",
		]
		for n, value in enumerate(values):
			self.assertEqual(
				self.transm.proceed(
					["set", jailName, "addjournalmatch", value]),
				(0, [[val] for val in values[:n+1]]))
		for n, value in enumerate(values):
			self.assertEqual(
				self.transm.proceed(
					["set", jailName, "deljournalmatch", value]),
				(0, [[val] for val in values[n+1:]]))

		# Try duplicates
		value = "_COMM=sshd"
		self.assertEqual(
			self.transm.proceed(
				["set", jailName, "addjournalmatch", value]),
			(0, [[value]]))
		# Duplicates are accepted, as automatically OR'd, and journalctl
		# also accepts them without issue.
		self.assertEqual(
			self.transm.proceed(
				["set", jailName, "addjournalmatch", value]),
			(0, [[value], [value]]))
		# Remove first instance
		self.assertEqual(
			self.transm.proceed(
				["set", jailName, "deljournalmatch", value]),
			(0, [[value]]))
		# Remove second instance
		self.assertEqual(
			self.transm.proceed(
				["set", jailName, "deljournalmatch", value]),
			(0, []))

		value = [
			"_COMM=sshd", "+", "_SYSTEMD_UNIT=sshd.service", "_UID=0"]
		self.assertEqual(
			self.transm.proceed(
				["set", jailName, "addjournalmatch"] + value),
			(0, [["_COMM=sshd"], ["_SYSTEMD_UNIT=sshd.service", "_UID=0"]]))
		self.assertEqual(
			self.transm.proceed(
				["set", jailName, "deljournalmatch"] + value[:1]),
			(0, [["_SYSTEMD_UNIT=sshd.service", "_UID=0"]]))
		self.assertEqual(
			self.transm.proceed(
				["set", jailName, "deljournalmatch"] + value[2:]),
			(0, []))

		# Invalid match
		value = "This isn't valid!"
		result = self.transm.proceed(
			["set", jailName, "addjournalmatch", value])
		self.assertTrue(isinstance(result[1], ValueError))

		# Delete invalid match
		value = "FIELD=NotPresent"
		result = self.transm.proceed(
			["set", jailName, "deljournalmatch", value])
		self.assertTrue(isinstance(result[1], ValueError))


class TransmitterLogging(TransmitterBase):

	def setUp(self):
		self.server = Server()
		self.server.setLogTarget("/dev/null")
		self.server.setLogLevel("CRITICAL")
		self.server.setSyslogSocket("auto")
		super(TransmitterLogging, self).setUp()

	def testLogTarget(self):
		logTargets = []
		for _ in xrange(3):
			tmpFile = tempfile.mkstemp("fail2ban", "transmitter")
			logTargets.append(tmpFile[1])
			os.close(tmpFile[0])
		for logTarget in logTargets:
			self.setGetTest("logtarget", logTarget)

		# If path is invalid, do not change logtarget
		value = "/this/path/should/not/exist"
		self.setGetTestNOK("logtarget", value)

		self.transm.proceed(["set", "logtarget", "/dev/null"])
		for logTarget in logTargets:
			os.remove(logTarget)

		self.setGetTest("logtarget", "STDOUT")
		self.setGetTest("logtarget", "STDERR")

	def testLogTargetSYSLOG(self):
		if not os.path.exists("/dev/log") and sys.version_info >= (2, 7):
			raise unittest.SkipTest("'/dev/log' not present")
		elif not os.path.exists("/dev/log"):
			return
		self.assertTrue(self.server.getSyslogSocket(), "auto")
		self.setGetTest("logtarget", "SYSLOG")
		self.assertTrue(self.server.getSyslogSocket(), "/dev/log")

	def testSyslogSocket(self):
		self.setGetTest("syslogsocket", "/dev/log/NEW/PATH")

	def testSyslogSocketNOK(self):
		self.setGetTest("syslogsocket", "/this/path/should/not/exist")
		self.setGetTestNOK("logtarget", "SYSLOG")
		# set back for other tests
		self.setGetTest("syslogsocket", "/dev/log")
		self.setGetTest("logtarget", "SYSLOG",
			**{True: {},    # should work on Linux
			   False: dict( # expect to fail otherwise
				   outCode=1,
				   outValue=Exception('Failed to change log target'),
				   repr_=True # Exceptions are not comparable apparently
                                  )
			  }[platform.system() in ('Linux',) and os.path.exists('/dev/log')]
		)

	def testLogLevel(self):
		self.setGetTest("loglevel", "HEAVYDEBUG")
		self.setGetTest("loglevel", "DEBUG")
		self.setGetTest("loglevel", "INFO")
		self.setGetTest("loglevel", "NOTICE")
		self.setGetTest("loglevel", "WARNING")
		self.setGetTest("loglevel", "ERROR")
		self.setGetTest("loglevel", "CRITICAL")
		self.setGetTest("loglevel", "cRiTiCaL", "CRITICAL")
		self.setGetTestNOK("loglevel", "Bird")

	def testFlushLogs(self):
		self.assertEqual(self.transm.proceed(["flushlogs"]), (0, "rolled over"))
		try:
			f, fn = tempfile.mkstemp("fail2ban.log")
			os.close(f)
			self.server.setLogLevel("WARNING")
			self.assertEqual(self.transm.proceed(["set", "logtarget", fn]), (0, fn))
			l = getLogger('fail2ban')
			l.warning("Before file moved")
			try:
				f2, fn2 = tempfile.mkstemp("fail2ban.log")
				os.close(f2)
				os.rename(fn, fn2)
				l.warning("After file moved")
				self.assertEqual(self.transm.proceed(["flushlogs"]), (0, "rolled over"))
				l.warning("After flushlogs")
				with open(fn2,'r') as f:
					line1 = f.next()
					if line1.find('Changed logging target to') >= 0:
						line1 = f.next()
					self.assertTrue(line1.endswith("Before file moved\n"))
					line2 = f.next()
					self.assertTrue(line2.endswith("After file moved\n"))
					try:
						n = f.next()
						if n.find("Command: ['flushlogs']") >=0:
							self.assertRaises(StopIteration, f.next)
						else:
							self.fail("Exception StopIteration or Command: ['flushlogs'] expected. Got: %s" % n)
					except StopIteration:
						pass # on higher debugging levels this is expected
				with open(fn,'r') as f:
					line1 = f.next()
					if line1.find('rollover performed on') >= 0:
						line1 = f.next()
					self.assertTrue(line1.endswith("After flushlogs\n"))
					self.assertRaises(StopIteration, f.next)
					f.close()
			finally:
				os.remove(fn2)
		finally:
			try:
				os.remove(fn)
			except OSError:
				pass
		self.assertEqual(self.transm.proceed(["set", "logtarget", "STDERR"]), (0, "STDERR"))
		self.assertEqual(self.transm.proceed(["flushlogs"]), (0, "flushed"))


class JailTests(unittest.TestCase):

	def testLongName(self):
		# Just a smoke test for now
		longname = "veryveryverylongname"
		jail = Jail(longname)
		self.assertEqual(jail.name, longname)


class RegexTests(unittest.TestCase):

	def testInit(self):
		# Should raise an Exception upon empty regex
		self.assertRaises(RegexException, Regex, '')
		self.assertRaises(RegexException, Regex, ' ')
		self.assertRaises(RegexException, Regex, '\t')

	def testStr(self):
		# .replace just to guarantee uniform use of ' or " in the %r
		self.assertEqual(str(Regex('a')).replace('"', "'"), "Regex('a')")
		# Class name should be proper
		self.assertTrue(str(FailRegex('<HOST>')).startswith("FailRegex("))

	def testHost(self):
		self.assertRaises(RegexException, FailRegex, '')
		# Testing obscure case when host group might be missing in the matched pattern,
		# e.g. if we made it optional.
		fr = FailRegex('%%<HOST>?')
		self.assertFalse(fr.hasMatched())
		fr.search([('%%',"","")])
		self.assertTrue(fr.hasMatched())
		self.assertRaises(RegexException, fr.getHost)


class _BadThread(JailThread):
	def run(self):
		raise RuntimeError('run bad thread exception')


class LoggingTests(LogCaptureTestCase):

	def testGetF2BLogger(self):
		testLogSys = getLogger("fail2ban.some.string.with.name")
		self.assertEqual(testLogSys.parent.name, "fail2ban")
		self.assertEqual(testLogSys.name, "fail2ban.name")

	def testFail2BanExceptHook(self):
		prev_exchook = sys.__excepthook__
		x = []
		sys.__excepthook__ = lambda *args: x.append(args)
		try:
			badThread = _BadThread()
			badThread.start()
			badThread.join()
			self.assertLogged("Unhandled exception")
		finally:
			sys.__excepthook__ = prev_exchook
		self.assertEqual(len(x), 1)
		self.assertEqual(x[0][0], RuntimeError)
