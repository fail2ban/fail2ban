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
import re
import sys
import platform

from ..server.failregex import Regex, FailRegex, RegexException
from ..server import actions as _actions
from ..server.server import Server
from ..server.ipdns import IPAddr
from ..server.jail import Jail
from ..server.jailthread import JailThread
from ..server.ticket import BanTicket
from ..server.utils import Utils
from .dummyjail import DummyJail
from .utils import LogCaptureTestCase
from ..helpers import getLogger, PREFER_ENC
from .. import version

try:
	from ..server import filtersystemd
except ImportError: # pragma: no cover
	filtersystemd = None

TEST_FILES_DIR = os.path.join(os.path.dirname(__file__), "files")
FAST_BACKEND = "polling"

logSys = getLogger("fail2ban")


class TestServer(Server):
	def setLogLevel(self, *args, **kwargs):
		pass

	def setLogTarget(self, *args, **kwargs):
		pass


class TransmitterBase(unittest.TestCase):
	
	def setUp(self):
		"""Call before every test case."""
		super(TransmitterBase, self).setUp()
		self.transm = self.server._Server__transm
		# To test thransmitter we don't need to start server...
		#self.server.start('/dev/null', '/dev/null', force=False)
		self.jailName = "TestJail1"
		self.server.addJail(self.jailName, FAST_BACKEND)

	def tearDown(self):
		"""Call after every test case."""
		# stop jails, etc.
		self.server.quit()
		super(TransmitterBase, self).tearDown()

	def setGetTest(self, cmd, inValue, outValue=(None,), outCode=0, jail=None, repr_=False):
		"""Process set/get commands and compare both return values 
		with outValue if it was given otherwise with inValue"""
		setCmd = ["set", cmd, inValue]
		getCmd = ["get", cmd]
		if jail is not None:
			setCmd.insert(1, jail)
			getCmd.insert(1, jail)

		# if outValue was not given (now None is allowed return/compare value also)
		if outValue == (None,):
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
			self.assertEqual((ret[0], sorted(map(str, ret[1]))), (0, sorted(map(str, values[:n+1]))))
			ret = self.transm.proceed(["get", jail, cmd])
			self.assertEqual((ret[0], sorted(map(str, ret[1]))), (0, sorted(map(str, values[:n+1]))))
		for n, value in enumerate(values):
			ret = self.transm.proceed(["set", jail, cmdDel, value])
			self.assertEqual((ret[0], sorted(map(str, ret[1]))), (0, sorted(map(str, values[n+1:]))))
			ret = self.transm.proceed(["get", jail, cmd])
			self.assertEqual((ret[0], sorted(map(str, ret[1]))), (0, sorted(map(str, values[n+1:]))))

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

	def testServerIsNotStarted(self):
		# so far isStarted only tested but not used otherwise
		# and here we don't really .start server
		self.assertFalse(self.server.isStarted())

	def testStopServer(self):
		self.assertEqual(self.transm.proceed(["stop"]), (0, None))

	def testPing(self):
		self.assertEqual(self.transm.proceed(["ping"]), (0, "pong"))

	def testVersion(self):
		self.assertEqual(self.transm.proceed(["version"]), (0, version.version))

	def testSleep(self):
		if not unittest.F2B.fast:
			t0 = time.time()
			self.assertEqual(self.transm.proceed(["sleep", "0.1"]), (0, None))
			t1 = time.time()
			# Approx 0.1 second delay but not faster
			dt = t1 - t0
			self.assertTrue(0.09 < dt < 0.2, msg="Sleep was %g sec" % dt)
		else: # pragma: no cover
			self.assertEqual(self.transm.proceed(["sleep", "0.0001"]), (0, None))

	def testDatabase(self):
		if not unittest.F2B.memory_db:
			tmp, tmpFilename = tempfile.mkstemp(".db", "fail2ban_")
		else: # pragma: no cover
			tmpFilename = ':memory:'
		# Jails present, can't change database
		self.setGetTestNOK("dbfile", tmpFilename)
		self.server.delJail(self.jailName)
		self.setGetTest("dbfile", tmpFilename)
		# the same file name (again no jails / not changed):
		self.setGetTest("dbfile", tmpFilename)
		self.setGetTest("dbpurgeage", "600", 600)
		self.setGetTestNOK("dbpurgeage", "LIZARD")
		# the same file name (again with jails / not changed):
		self.server.addJail(self.jailName, FAST_BACKEND)
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
		self.server.addJail(self.jailName, FAST_BACKEND)
		self.assertEqual(self.transm.proceed(
			["set", "dbfile", "None"]),
			(0, None))
		if not unittest.F2B.memory_db:
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
			self.transm.proceed(["add", "--all", "polling"])[0], 1)

	def testStartStopJail(self):
		self.assertEqual(
			self.transm.proceed(["start", self.jailName]), (0, None))
		time.sleep(Utils.DEFAULT_SLEEP_TIME)
		# wait until not started (3 seconds as long as any RuntimeError, ex.: RuntimeError('cannot join thread before it is started',)):
		self.assertTrue( Utils.wait_for(
			lambda: self.server.isAlive(1) and not isinstance(self.transm.proceed(["status", self.jailName]), RuntimeError),
			3) )
		self.assertEqual(
			self.transm.proceed(["stop", self.jailName]), (0, None))
		self.assertNotIn(self.jailName, self.server._Server__jails)

	def testStartStopAllJail(self):
		self.server.addJail("TestJail2", FAST_BACKEND)
		self.assertEqual(
			self.transm.proceed(["start", self.jailName]), (0, None))
		self.assertEqual(
			self.transm.proceed(["start", "TestJail2"]), (0, None))
		# yoh: workaround for gh-146.  I still think that there is some
		#      race condition and missing locking somewhere, but for now
		#      giving it a small delay reliably helps to proceed with tests
		time.sleep(Utils.DEFAULT_SLEEP_TIME)
		self.assertTrue( Utils.wait_for(
			lambda: self.server.isAlive(2) and not isinstance(self.transm.proceed(["status", self.jailName]), RuntimeError),
			3) )
		self.assertEqual(self.transm.proceed(["stop", "--all"]), (0, None))
		self.assertTrue( Utils.wait_for( lambda: not len(self.server._Server__jails), 3) )
		self.assertNotIn(self.jailName, self.server._Server__jails)
		self.assertNotIn("TestJail2", self.server._Server__jails)

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
		self.setGetTest("findtime", "30m", 30*60, jail=self.jailName)
		self.setGetTest("findtime", "-60", -60, jail=self.jailName)
		self.setGetTestNOK("findtime", "Dog", jail=self.jailName)

	def testJailBanTime(self):
		self.setGetTest("bantime", "600", 600, jail=self.jailName)
		self.setGetTest("bantime", "50", 50, jail=self.jailName)
		self.setGetTest("bantime", "-50", -50, jail=self.jailName)
		self.setGetTest("bantime", "15d 5h 30m", 1315800, jail=self.jailName)
		self.setGetTestNOK("bantime", "Cat", jail=self.jailName)

	def testDatePattern(self):
		self.setGetTest("datepattern", "%%%Y%m%d%H%M%S",
			("%%%Y%m%d%H%M%S", "%YearMonthDay24hourMinuteSecond"),
			jail=self.jailName)
		self.setGetTest(
			"datepattern", "Epoch", (None, "Epoch"), jail=self.jailName)
		self.setGetTest(
			"datepattern", "^Epoch", (None, "{^LN-BEG}Epoch"), jail=self.jailName)
		self.setGetTest(
			"datepattern", "TAI64N", (None, "TAI64N"), jail=self.jailName)
		self.setGetTestNOK("datepattern", "%Cat%a%%%g", jail=self.jailName)

	def testLogTimeZone(self):
		self.setGetTest("logtimezone", "UTC+0400", "UTC+0400", jail=self.jailName)
		self.setGetTestNOK("logtimezone", "not-a-time-zone", jail=self.jailName)

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
		time.sleep(Utils.DEFAULT_SLEEP_TIME) # Give chance to ban
		self.assertEqual(
			self.transm.proceed(["set", self.jailName, "banip", "Badger"]),
			(0, "Badger")) #NOTE: Is IP address validated? Is DNS Lookup done?
		time.sleep(Utils.DEFAULT_SLEEP_TIME) # Give chance to ban
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
		self.setGetTest("logencoding", "auto", PREFER_ENC,
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

		self.assertEqual(
			self.transm.proceed(["get", self.jailName, "ignoreself"]),
			(0, True))
		self.assertEqual(
			self.transm.proceed(["set", self.jailName, "ignoreself", False]),
			(0, False))
		self.assertEqual(
			self.transm.proceed(["get", self.jailName, "ignoreself"]),
			(0, False))

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
				"user john at %s" % (Regex._resolveHostTag('<HOST>')),
				"Admin user login from %s" % (Regex._resolveHostTag('<HOST>')),
				"failed attempt from %s again" % (Regex._resolveHostTag('<HOST>')),
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
				"Admin user login from %s" % (Regex._resolveHostTag('<HOST>')),
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
		self.server.addJail("TestJail2", FAST_BACKEND)
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
		unittest.F2B.SkipIfNoNetwork()
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
			(0, "10"))
		self.assertEqual(
			self.transm.proceed(
				["get", self.jailName, "action", action, "timeout"]),
			(0, "10"))
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
			raise unittest.SkipTest("systemd python interface not available")
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
		super(TransmitterLogging, self).setUp()
		self.server.setLogTarget("/dev/null")
		self.server.setLogLevel("CRITICAL")
		self.server.setSyslogSocket("auto")

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
		if not os.path.exists("/dev/log"):
			raise unittest.SkipTest("'/dev/log' not present")
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
		self.setGetTest("loglevel", "TRACEDEBUG")
		self.setGetTest("loglevel", "9")
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
		self.assertRaises(RegexException, FailRegex, '^test no group$')
		self.assertTrue(FailRegex('^test <HOST> group$'))
		self.assertTrue(FailRegex('^test <IP4> group$'))
		self.assertTrue(FailRegex('^test <IP6> group$'))
		self.assertTrue(FailRegex('^test <DNS> group$'))
		self.assertTrue(FailRegex('^test id group: ip:port = <F-ID><IP4>(?::<F-PORT/>)?</F-ID>$'))
		self.assertTrue(FailRegex('^test id group: user:\(<F-ID>[^\)]+</F-ID>\)$'))
		self.assertTrue(FailRegex('^test id group: anything = <F-ID/>$'))
		# Testing obscure case when host group might be missing in the matched pattern,
		# e.g. if we made it optional.
		fr = FailRegex('%%<HOST>?')
		self.assertFalse(fr.hasMatched())
		fr.search([('%%',"","")])
		self.assertTrue(fr.hasMatched())
		self.assertRaises(RegexException, fr.getHost)
		# The same as above but using separated IPv4/IPv6 expressions
		fr = FailRegex('%%inet(?:=<F-IP4/>|inet6=<F-IP6/>)?')
		self.assertFalse(fr.hasMatched())
		fr.search([('%%inet=test',"","")])
		self.assertTrue(fr.hasMatched())
		self.assertRaises(RegexException, fr.getHost)
		# Success case: using separated IPv4/IPv6 expressions (no HOST)
		fr = FailRegex('%%(?:inet(?:=<IP4>|6=<IP6>)?|dns=<DNS>?)')
		self.assertFalse(fr.hasMatched())
		fr.search([('%%inet=192.0.2.1',"","")])
		self.assertTrue(fr.hasMatched())
		self.assertEqual(fr.getHost(), '192.0.2.1')
		fr.search([('%%inet6=2001:DB8::',"","")])
		self.assertTrue(fr.hasMatched())
		self.assertEqual(fr.getHost(), '2001:DB8::')
		fr.search([('%%dns=example.com',"","")])
		self.assertTrue(fr.hasMatched())
		self.assertEqual(fr.getHost(), 'example.com')
		# Success case: using user as failure-id
		fr = FailRegex('^test id group: user:\(<F-ID>[^\)]+</F-ID>\)$')
		self.assertFalse(fr.hasMatched())
		fr.search([('test id group: user:(test login name)',"","")])
		self.assertTrue(fr.hasMatched())
		self.assertEqual(fr.getFailID(), 'test login name')


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
			self.assertTrue( Utils.wait_for( lambda: len(x) and self._is_logged("Unhandled exception"), 3) )
		finally:
			sys.__excepthook__ = prev_exchook
		self.assertLogged("Unhandled exception")
		self.assertEqual(len(x), 1)
		self.assertEqual(x[0][0], RuntimeError)

	def testStartFailedSockExists(self):
		tmp_files = []
		sock_fd, sock_name = tempfile.mkstemp('fail2ban.sock', 'f2b-test')
		os.close(sock_fd)
		tmp_files.append(sock_name)
		pidfile_fd, pidfile_name = tempfile.mkstemp('fail2ban.pid', 'f2b-test')
		os.close(pidfile_fd)
		tmp_files.append(pidfile_name)
		server = TestServer()
		try:
			server.start(sock_name, pidfile_name, force=False)
			self.assertFalse(server.isStarted())
			self.assertLogged("Server already running")
		finally:
			server.quit()
			for f in tmp_files:
				if os.path.exists(f):
					os.remove(f)


from clientreadertestcase import ActionReader, JailReader, JailsReader, CONFIG_DIR, STOCK

class ServerConfigReaderTests(LogCaptureTestCase):

	def __init__(self, *args, **kwargs):
		super(ServerConfigReaderTests, self).__init__(*args, **kwargs)
		self.__share_cfg = {}

	def setUp(self):
		"""Call before every test case."""
		super(ServerConfigReaderTests, self).setUp()
		self._execCmdLst = []
	
	def tearDown(self):
		"""Call after every test case."""
		super(ServerConfigReaderTests, self).tearDown()

	def _executeCmd(self, realCmd, timeout=60):
		for l in realCmd.split('\n'):
			if not l.startswith('#'):
				logSys.debug('exec-cmd: `%s`', l)
			else:
				logSys.debug(l)
		return True

	def _testExecActions(self, server):
		jails = server._Server__jails
		for jail in jails:
			# print(jail, jails[jail])
			for a in jails[jail].actions:
				action = jails[jail].actions[a]
				logSys.debug('# ' + ('=' * 50))
				logSys.debug('# == %-44s ==', jail + ' - ' + action._name)
				logSys.debug('# ' + ('=' * 50))
				# we can currently test only command actions:
				if not isinstance(action, _actions.CommandAction): continue
				# wrap default command processor, just log if (heavy)debug:
				action.executeCmd = self._executeCmd
				# test start :
				logSys.debug('# === start ==='); self.pruneLog()
				action.start()
				# test ban ip4 :
				logSys.debug('# === ban-ipv4 ==='); self.pruneLog()
				action.ban({'ip': IPAddr('192.0.2.1'), 'family': 'inet4'})
				# test unban ip4 :
				logSys.debug('# === unban ipv4 ==='); self.pruneLog()
				action.unban({'ip': IPAddr('192.0.2.1'), 'family': 'inet4'})
				# test ban ip6 :
				logSys.debug('# === ban ipv6 ==='); self.pruneLog()
				action.ban({'ip': IPAddr('2001:DB8::'), 'family': 'inet6'})
				# test unban ip6 :
				logSys.debug('# === unban ipv6 ==='); self.pruneLog()
				action.unban({'ip': IPAddr('2001:DB8::'), 'family': 'inet6'})
				# test stop :
				logSys.debug('# === stop ==='); self.pruneLog()
				action.stop()

	if STOCK:

		def testCheckStockJailActions(self):
			# we are running tests from root project dir atm
			jails = JailsReader(basedir=CONFIG_DIR, force_enable=True, share_config=self.__share_cfg)
			self.assertTrue(jails.read())		  # opens fine
			self.assertTrue(jails.getOptions())	  # reads fine
			stream = jails.convert(allow_no_files=True)

			server = TestServer()
			transm = server._Server__transm
			cmdHandler = transm._Transmitter__commandHandler

			# for cmd in stream:
			# 	print(cmd)

			# filter all start commands (we want not start all jails):
			for cmd in stream:
				if cmd[0] != 'start':
					# change to the fast init backend:
					if cmd[0] == 'add':
						cmd[2] = 'polling'
					# change log path to test log of the jail
					# (to prevent "Permission denied" on /var/logs/ for test-user):
					elif len(cmd) > 3 and cmd[0] == 'set' and cmd[2] == 'addlogpath':
						fn = os.path.join(TEST_FILES_DIR, 'logs', cmd[1])
						# fallback to testcase01 if jail has no its own test log-file
						# (should not matter really):
						if not os.path.exists(fn):  # pragma: no cover
							fn = os.path.join(TEST_FILES_DIR, 'testcase01.log')
						cmd[3] = fn
					# if fast add dummy regex to prevent too long compile of all regexp
					# (we don't use it in this test at all):
					elif unittest.F2B.fast and (
						len(cmd) > 3 and cmd[0] in ('set', 'multi-set') and cmd[2] == 'addfailregex'
					): # pragma: no cover
						cmd[0] = "set"
						cmd[3] = "DUMMY-REGEX <HOST>"
					# command to server, use cmdHandler direct instead of `transm.proceed(cmd)`:
					try:
						cmdHandler(cmd)
					except Exception as e:  # pragma: no cover
						self.fail("Command %r has failed. Received %r" % (cmd, e))

			# jails = server._Server__jails
			# for j in jails:
			# 	print(j, jails[j])

			# test default stock actions sepecified in all stock jails:
			if not unittest.F2B.fast:
				self._testExecActions(server)

		def getDefaultJailStream(self, jail, act):
			act = act.replace('%(__name__)s', jail)
			actName, actOpt = JailReader.extractOptions(act)
			stream = [
				['add', jail, 'polling'],
				# ['set', jail, 'addfailregex', 'DUMMY-REGEX <HOST>'],
			]
			action = ActionReader(
				actName, jail, actOpt,
				share_config=self.__share_cfg, basedir=CONFIG_DIR)
			self.assertTrue(action.read())
			action.getOptions({})
			stream.extend(action.convert())
			return stream

		def testCheckStockAllActions(self):
			unittest.F2B.SkipIfFast()
			import glob

			server = TestServer()
			transm = server._Server__transm

			for actCfg in glob.glob(os.path.join(CONFIG_DIR, 'action.d', '*.conf')):
				act = os.path.basename(actCfg).replace('.conf', '')
				# transmit artifical jail with each action to the server:
				stream = self.getDefaultJailStream('j-'+act, act)
				for cmd in stream:
					# command to server:
					ret, res = transm.proceed(cmd)
					self.assertEqual(ret, 0)
				# test executing action commands:
				self._testExecActions(server)


		def testCheckStockCommandActions(self):
			# test cases to check valid ipv4/ipv6 action definition, tuple with (('jail', 'action[params]', 'tests', ...)
			# where tests is a dictionary contains:
			#   'ip4' - should not be found (logged) on ban/unban of IPv6 (negative test),
			#   'ip6' - should not be found (logged) on ban/unban of IPv4 (negative test),
			#   'start', 'stop' - should be found (logged) on action start/stop,
			#   etc.
			testJailsActions = (
				# dummy --
				('j-dummy', 'dummy[name=%(__name__)s, init="==", target="/tmp/fail2ban.dummy"]', {
					'ip4': ('family: inet4',), 'ip6': ('family: inet6',),
					'start': (
						'`echo "[j-dummy] dummy /tmp/fail2ban.dummy -- started"`',
					), 
					'flush': (
						'`echo "[j-dummy] dummy /tmp/fail2ban.dummy -- clear all"`',
					),
					'stop': (
						'`echo "[j-dummy] dummy /tmp/fail2ban.dummy -- stopped"`',
					),
					'ip4-check': (),
					'ip6-check': (),
					'ip4-ban': (
						'`echo "[j-dummy] dummy /tmp/fail2ban.dummy -- banned 192.0.2.1 (family: inet4)"`',
					),
					'ip4-unban': (
						'`echo "[j-dummy] dummy /tmp/fail2ban.dummy -- unbanned 192.0.2.1 (family: inet4)"`',
					),
					'ip6-ban': (
						'`echo "[j-dummy] dummy /tmp/fail2ban.dummy -- banned 2001:db8:: (family: inet6)"`',
					),
					'ip6-unban': (
						'`echo "[j-dummy] dummy /tmp/fail2ban.dummy -- unbanned 2001:db8:: (family: inet6)"`',
					),					
				}),
				# iptables-multiport --
				('j-w-iptables-mp', 'iptables-multiport[name=%(__name__)s, bantime="10m", port="http,https", protocol="tcp", chain="INPUT"]', {
					'ip4': ('`iptables ', 'icmp-port-unreachable'), 'ip6': ('`ip6tables ', 'icmp6-port-unreachable'),
					'ip4-start': (
						"`iptables -w -N f2b-j-w-iptables-mp`",
						"`iptables -w -A f2b-j-w-iptables-mp -j RETURN`",
						"`iptables -w -I INPUT -p tcp -m multiport --dports http,https -j f2b-j-w-iptables-mp`",
					), 
					'ip6-start': (
						"`ip6tables -w -N f2b-j-w-iptables-mp`",
						"`ip6tables -w -A f2b-j-w-iptables-mp -j RETURN`",
						"`ip6tables -w -I INPUT -p tcp -m multiport --dports http,https -j f2b-j-w-iptables-mp`",
					),
					'flush': (
						"`iptables -w -F f2b-j-w-iptables-mp`",
						"`ip6tables -w -F f2b-j-w-iptables-mp`",
					),
					'stop': (
						"`iptables -w -D INPUT -p tcp -m multiport --dports http,https -j f2b-j-w-iptables-mp`",
						"`iptables -w -F f2b-j-w-iptables-mp`",
						"`iptables -w -X f2b-j-w-iptables-mp`",
						"`ip6tables -w -D INPUT -p tcp -m multiport --dports http,https -j f2b-j-w-iptables-mp`",
						"`ip6tables -w -F f2b-j-w-iptables-mp`",
						"`ip6tables -w -X f2b-j-w-iptables-mp`",
					),
					'ip4-check': (
						r"""`iptables -w -n -L INPUT | grep -q 'f2b-j-w-iptables-mp[ \t]'`""",
					),
					'ip6-check': (
						r"""`ip6tables -w -n -L INPUT | grep -q 'f2b-j-w-iptables-mp[ \t]'`""",
					),
					'ip4-ban': (
						r"`iptables -w -I f2b-j-w-iptables-mp 1 -s 192.0.2.1 -j REJECT --reject-with icmp-port-unreachable`",
					),
					'ip4-unban': (
						r"`iptables -w -D f2b-j-w-iptables-mp -s 192.0.2.1 -j REJECT --reject-with icmp-port-unreachable`",
					),
					'ip6-ban': (
						r"`ip6tables -w -I f2b-j-w-iptables-mp 1 -s 2001:db8:: -j REJECT --reject-with icmp6-port-unreachable`",
					),
					'ip6-unban': (
						r"`ip6tables -w -D f2b-j-w-iptables-mp -s 2001:db8:: -j REJECT --reject-with icmp6-port-unreachable`",
					),					
				}),
				# iptables-allports --
				('j-w-iptables-ap', 'iptables-allports[name=%(__name__)s, bantime="10m", protocol="tcp", chain="INPUT"]', {
					'ip4': ('`iptables ', 'icmp-port-unreachable'), 'ip6': ('`ip6tables ', 'icmp6-port-unreachable'),
					'ip4-start': (
						"`iptables -w -N f2b-j-w-iptables-ap`",
						"`iptables -w -A f2b-j-w-iptables-ap -j RETURN`",
						"`iptables -w -I INPUT -p tcp -j f2b-j-w-iptables-ap`",
					), 
					'ip6-start': (
						"`ip6tables -w -N f2b-j-w-iptables-ap`",
						"`ip6tables -w -A f2b-j-w-iptables-ap -j RETURN`",
						"`ip6tables -w -I INPUT -p tcp -j f2b-j-w-iptables-ap`",
					),
					'flush': (
						"`iptables -w -F f2b-j-w-iptables-ap`",
						"`ip6tables -w -F f2b-j-w-iptables-ap`",
					),
					'stop': (
						"`iptables -w -D INPUT -p tcp -j f2b-j-w-iptables-ap`",
						"`iptables -w -F f2b-j-w-iptables-ap`",
						"`iptables -w -X f2b-j-w-iptables-ap`",
						"`ip6tables -w -D INPUT -p tcp -j f2b-j-w-iptables-ap`",
						"`ip6tables -w -F f2b-j-w-iptables-ap`",
						"`ip6tables -w -X f2b-j-w-iptables-ap`",
					),
					'ip4-check': (
						r"""`iptables -w -n -L INPUT | grep -q 'f2b-j-w-iptables-ap[ \t]'`""",
					),
					'ip6-check': (
						r"""`ip6tables -w -n -L INPUT | grep -q 'f2b-j-w-iptables-ap[ \t]'`""",
					),
					'ip4-ban': (
						r"`iptables -w -I f2b-j-w-iptables-ap 1 -s 192.0.2.1 -j REJECT --reject-with icmp-port-unreachable`",
					),
					'ip4-unban': (
						r"`iptables -w -D f2b-j-w-iptables-ap -s 192.0.2.1 -j REJECT --reject-with icmp-port-unreachable`",
					),
					'ip6-ban': (
						r"`ip6tables -w -I f2b-j-w-iptables-ap 1 -s 2001:db8:: -j REJECT --reject-with icmp6-port-unreachable`",
					),
					'ip6-unban': (
						r"`ip6tables -w -D f2b-j-w-iptables-ap -s 2001:db8:: -j REJECT --reject-with icmp6-port-unreachable`",
					),					
				}),
				# iptables-ipset-proto6 --
				('j-w-iptables-ipset', 'iptables-ipset-proto6[name=%(__name__)s, bantime="10m", port="http", protocol="tcp", chain="INPUT"]', {
					'ip4': (' f2b-j-w-iptables-ipset ',), 'ip6': (' f2b-j-w-iptables-ipset6 ',),
					'ip4-start': (
						"`ipset create f2b-j-w-iptables-ipset hash:ip timeout 600`",
						"`iptables -w -I INPUT -p tcp -m multiport --dports http -m set --match-set f2b-j-w-iptables-ipset src -j REJECT --reject-with icmp-port-unreachable`",
					), 
					'ip6-start': (
						"`ipset create f2b-j-w-iptables-ipset6 hash:ip timeout 600 family inet6`",
						"`ip6tables -w -I INPUT -p tcp -m multiport --dports http -m set --match-set f2b-j-w-iptables-ipset6 src -j REJECT --reject-with icmp6-port-unreachable`",
					),
					'flush': (
						"`ipset flush f2b-j-w-iptables-ipset`",
						"`ipset flush f2b-j-w-iptables-ipset6`",
					),
					'stop': (
						"`iptables -w -D INPUT -p tcp -m multiport --dports http -m set --match-set f2b-j-w-iptables-ipset src -j REJECT --reject-with icmp-port-unreachable`",
						"`ipset flush f2b-j-w-iptables-ipset`",
						"`ipset destroy f2b-j-w-iptables-ipset`",
						"`ip6tables -w -D INPUT -p tcp -m multiport --dports http -m set --match-set f2b-j-w-iptables-ipset6 src -j REJECT --reject-with icmp6-port-unreachable`",
						"`ipset flush f2b-j-w-iptables-ipset6`",
						"`ipset destroy f2b-j-w-iptables-ipset6`",
					),
					'ip4-check': (),
					'ip6-check': (),
					'ip4-ban': (
						r"`ipset add f2b-j-w-iptables-ipset 192.0.2.1 timeout 600 -exist`",
					),
					'ip4-unban': (
						r"`ipset del f2b-j-w-iptables-ipset 192.0.2.1 -exist`",
					),
					'ip6-ban': (
						r"`ipset add f2b-j-w-iptables-ipset6 2001:db8:: timeout 600 -exist`",
					),
					'ip6-unban': (
						r"`ipset del f2b-j-w-iptables-ipset6 2001:db8:: -exist`",
					),					
				}),
				# iptables-ipset-proto6-allports --
				('j-w-iptables-ipset-ap', 'iptables-ipset-proto6-allports[name=%(__name__)s, bantime="10m", chain="INPUT"]', {
					'ip4': (' f2b-j-w-iptables-ipset-ap ',), 'ip6': (' f2b-j-w-iptables-ipset-ap6 ',),
					'ip4-start': (
						"`ipset create f2b-j-w-iptables-ipset-ap hash:ip timeout 600`",
						"`iptables -w -I INPUT -m set --match-set f2b-j-w-iptables-ipset-ap src -j REJECT --reject-with icmp-port-unreachable`",
					), 
					'ip6-start': (
						"`ipset create f2b-j-w-iptables-ipset-ap6 hash:ip timeout 600 family inet6`",
						"`ip6tables -w -I INPUT -m set --match-set f2b-j-w-iptables-ipset-ap6 src -j REJECT --reject-with icmp6-port-unreachable`",
					),
					'flush': (
						"`ipset flush f2b-j-w-iptables-ipset-ap`",
						"`ipset flush f2b-j-w-iptables-ipset-ap6`",
					),
					'stop': (
						"`iptables -w -D INPUT -m set --match-set f2b-j-w-iptables-ipset-ap src -j REJECT --reject-with icmp-port-unreachable`",
						"`ipset flush f2b-j-w-iptables-ipset-ap`",
						"`ipset destroy f2b-j-w-iptables-ipset-ap`",
						"`ip6tables -w -D INPUT -m set --match-set f2b-j-w-iptables-ipset-ap6 src -j REJECT --reject-with icmp6-port-unreachable`",
						"`ipset flush f2b-j-w-iptables-ipset-ap6`",
						"`ipset destroy f2b-j-w-iptables-ipset-ap6`",
					),
					'ip4-check': (),
					'ip6-check': (),
					'ip4-ban': (
						r"`ipset add f2b-j-w-iptables-ipset-ap 192.0.2.1 timeout 600 -exist`",
					),
					'ip4-unban': (
						r"`ipset del f2b-j-w-iptables-ipset-ap 192.0.2.1 -exist`",
					),
					'ip6-ban': (
						r"`ipset add f2b-j-w-iptables-ipset-ap6 2001:db8:: timeout 600 -exist`",
					),
					'ip6-unban': (
						r"`ipset del f2b-j-w-iptables-ipset-ap6 2001:db8:: -exist`",
					),					
				}),
				# iptables --
				('j-w-iptables', 'iptables[name=%(__name__)s, bantime="10m", port="http", protocol="tcp", chain="INPUT"]', {
					'ip4': ('`iptables ', 'icmp-port-unreachable'), 'ip6': ('`ip6tables ', 'icmp6-port-unreachable'),
					'ip4-start': (
						"`iptables -w -N f2b-j-w-iptables`",
						"`iptables -w -A f2b-j-w-iptables -j RETURN`",
						"`iptables -w -I INPUT -p tcp --dport http -j f2b-j-w-iptables`",
					), 
					'ip6-start': (
						"`ip6tables -w -N f2b-j-w-iptables`",
						"`ip6tables -w -A f2b-j-w-iptables -j RETURN`",
						"`ip6tables -w -I INPUT -p tcp --dport http -j f2b-j-w-iptables`",
					),
					'flush': (
						"`iptables -w -F f2b-j-w-iptables`",
						"`ip6tables -w -F f2b-j-w-iptables`",
					),
					'stop': (
						"`iptables -w -D INPUT -p tcp --dport http -j f2b-j-w-iptables`",
						"`iptables -w -F f2b-j-w-iptables`",
						"`iptables -w -X f2b-j-w-iptables`",
						"`ip6tables -w -D INPUT -p tcp --dport http -j f2b-j-w-iptables`",
						"`ip6tables -w -F f2b-j-w-iptables`",
						"`ip6tables -w -X f2b-j-w-iptables`",
					),
					'ip4-check': (
						r"""`iptables -w -n -L INPUT | grep -q 'f2b-j-w-iptables[ \t]'`""",
					),
					'ip6-check': (
						r"""`ip6tables -w -n -L INPUT | grep -q 'f2b-j-w-iptables[ \t]'`""",
					),
					'ip4-ban': (
						r"`iptables -w -I f2b-j-w-iptables 1 -s 192.0.2.1 -j REJECT --reject-with icmp-port-unreachable`",
					),
					'ip4-unban': (
						r"`iptables -w -D f2b-j-w-iptables -s 192.0.2.1 -j REJECT --reject-with icmp-port-unreachable`",
					),
					'ip6-ban': (
						r"`ip6tables -w -I f2b-j-w-iptables 1 -s 2001:db8:: -j REJECT --reject-with icmp6-port-unreachable`",
					),
					'ip6-unban': (
						r"`ip6tables -w -D f2b-j-w-iptables -s 2001:db8:: -j REJECT --reject-with icmp6-port-unreachable`",
					),					
				}),
				# iptables-new --
				('j-w-iptables-new', 'iptables-new[name=%(__name__)s, bantime="10m", port="http", protocol="tcp", chain="INPUT"]', {
					'ip4': ('`iptables ', 'icmp-port-unreachable'), 'ip6': ('`ip6tables ', 'icmp6-port-unreachable'),
					'ip4-start': (
						"`iptables -w -N f2b-j-w-iptables-new`",
						"`iptables -w -A f2b-j-w-iptables-new -j RETURN`",
						"`iptables -w -I INPUT -m state --state NEW -p tcp --dport http -j f2b-j-w-iptables-new`",
					), 
					'ip6-start': (
						"`ip6tables -w -N f2b-j-w-iptables-new`",
						"`ip6tables -w -A f2b-j-w-iptables-new -j RETURN`",
						"`ip6tables -w -I INPUT -m state --state NEW -p tcp --dport http -j f2b-j-w-iptables-new`",
					),
					'flush': (
						"`iptables -w -F f2b-j-w-iptables-new`",
						"`ip6tables -w -F f2b-j-w-iptables-new`",
					),
					'stop': (
						"`iptables -w -D INPUT -m state --state NEW -p tcp --dport http -j f2b-j-w-iptables-new`",
						"`iptables -w -F f2b-j-w-iptables-new`",
						"`iptables -w -X f2b-j-w-iptables-new`",
						"`ip6tables -w -D INPUT -m state --state NEW -p tcp --dport http -j f2b-j-w-iptables-new`",
						"`ip6tables -w -F f2b-j-w-iptables-new`",
						"`ip6tables -w -X f2b-j-w-iptables-new`",
					),
					'ip4-check': (
						r"""`iptables -w -n -L INPUT | grep -q 'f2b-j-w-iptables-new[ \t]'`""",
					),
					'ip6-check': (
						r"""`ip6tables -w -n -L INPUT | grep -q 'f2b-j-w-iptables-new[ \t]'`""",
					),
					'ip4-ban': (
						r"`iptables -w -I f2b-j-w-iptables-new 1 -s 192.0.2.1 -j REJECT --reject-with icmp-port-unreachable`",
					),
					'ip4-unban': (
						r"`iptables -w -D f2b-j-w-iptables-new -s 192.0.2.1 -j REJECT --reject-with icmp-port-unreachable`",
					),
					'ip6-ban': (
						r"`ip6tables -w -I f2b-j-w-iptables-new 1 -s 2001:db8:: -j REJECT --reject-with icmp6-port-unreachable`",
					),
					'ip6-unban': (
						r"`ip6tables -w -D f2b-j-w-iptables-new -s 2001:db8:: -j REJECT --reject-with icmp6-port-unreachable`",
					),					
				}),
				# iptables-xt_recent-echo --
				('j-w-iptables-xtre', 'iptables-xt_recent-echo[name=%(__name__)s, bantime="10m", chain="INPUT"]', {
					'ip4': ('`iptables ', '/f2b-j-w-iptables-xtre`'), 'ip6': ('`ip6tables ', '/f2b-j-w-iptables-xtre6`'),
					'ip4-start': (
						"`if [ `id -u` -eq 0 ];then iptables -w -I INPUT -m recent --update --seconds 3600 --name f2b-j-w-iptables-xtre -j REJECT --reject-with icmp-port-unreachable;fi`",
					), 
					'ip6-start': (
						"`if [ `id -u` -eq 0 ];then ip6tables -w -I INPUT -m recent --update --seconds 3600 --name f2b-j-w-iptables-xtre6 -j REJECT --reject-with icmp6-port-unreachable;fi`",
					),
					'stop': (
						"`echo / > /proc/net/xt_recent/f2b-j-w-iptables-xtre`",
						"`if [ `id -u` -eq 0 ];then iptables -w -D INPUT -m recent --update --seconds 3600 --name f2b-j-w-iptables-xtre -j REJECT --reject-with icmp-port-unreachable;fi`",
						"`echo / > /proc/net/xt_recent/f2b-j-w-iptables-xtre6`",
						"`if [ `id -u` -eq 0 ];then ip6tables -w -D INPUT -m recent --update --seconds 3600 --name f2b-j-w-iptables-xtre6 -j REJECT --reject-with icmp6-port-unreachable;fi`",
					),
					'ip4-check': (
						r"`test -e /proc/net/xt_recent/f2b-j-w-iptables-xtre`",
					),
					'ip6-check': (
						r"`test -e /proc/net/xt_recent/f2b-j-w-iptables-xtre6`",
					),
					'ip4-ban': (
						r"`echo +192.0.2.1 > /proc/net/xt_recent/f2b-j-w-iptables-xtre`",
					),
					'ip4-unban': (
						r"`echo -192.0.2.1 > /proc/net/xt_recent/f2b-j-w-iptables-xtre`",
					),
					'ip6-ban': (
						r"`echo +2001:db8:: > /proc/net/xt_recent/f2b-j-w-iptables-xtre6`",
					),
					'ip6-unban': (
						r"`echo -2001:db8:: > /proc/net/xt_recent/f2b-j-w-iptables-xtre6`",
					),
				}),
				# pf default -- multiport on default port (tag <port> set in jail.conf, but not in this test case)
				('j-w-pf', 'pf[name=%(__name__)s, actionstart_on_demand=false]', {
					'ip4': (), 'ip6': (),
					'start': (
						'`echo "table <f2b-j-w-pf> persist counters" | pfctl -f-`',
						'`echo "block proto tcp from <f2b-j-w-pf> to any port <port>" | pfctl -f-`',
					),
					'stop': (
						'`pfctl -sr 2>/dev/null | grep -v f2b-j-w-pf | pfctl -f-`',
						'`pfctl -t f2b-j-w-pf -T flush`',
						'`pfctl -t f2b-j-w-pf -T kill`',
					),
					'ip4-check': ("`pfctl -sr | grep -q f2b-j-w-pf`",),
					'ip6-check': ("`pfctl -sr | grep -q f2b-j-w-pf`",),
					'ip4-ban':   ("`pfctl -t f2b-j-w-pf -T add 192.0.2.1`",),
					'ip4-unban': ("`pfctl -t f2b-j-w-pf -T delete 192.0.2.1`",),
					'ip6-ban':   ("`pfctl -t f2b-j-w-pf -T add 2001:db8::`",),
					'ip6-unban': ("`pfctl -t f2b-j-w-pf -T delete 2001:db8::`",),
				}),
				# pf multiport with custom port --
				('j-w-pf-mp', 'pf[actiontype=<multiport>][name=%(__name__)s, port=http]', {
					'ip4': (), 'ip6': (),
					'start': (
						'`echo "table <f2b-j-w-pf-mp> persist counters" | pfctl -f-`',
						'`echo "block proto tcp from <f2b-j-w-pf-mp> to any port http" | pfctl -f-`',
					),
					'stop': (
						'`pfctl -sr 2>/dev/null | grep -v f2b-j-w-pf-mp | pfctl -f-`',
						'`pfctl -t f2b-j-w-pf-mp -T flush`',
						'`pfctl -t f2b-j-w-pf-mp -T kill`',
					),
					'ip4-check': ("`pfctl -sr | grep -q f2b-j-w-pf-mp`",),
					'ip6-check': ("`pfctl -sr | grep -q f2b-j-w-pf-mp`",),
					'ip4-ban':   ("`pfctl -t f2b-j-w-pf-mp -T add 192.0.2.1`",),
					'ip4-unban': ("`pfctl -t f2b-j-w-pf-mp -T delete 192.0.2.1`",),
					'ip6-ban':   ("`pfctl -t f2b-j-w-pf-mp -T add 2001:db8::`",),
					'ip6-unban': ("`pfctl -t f2b-j-w-pf-mp -T delete 2001:db8::`",),
				}),
				# pf allports -- test additionally "actionstart_on_demand" was set to true
				('j-w-pf-ap', 'pf[actiontype=<allports>, actionstart_on_demand=true][name=%(__name__)s]', {
					'ip4': (), 'ip6': (),
					'ip4-start': (
						'`echo "table <f2b-j-w-pf-ap> persist counters" | pfctl -f-`',
						'`echo "block proto tcp from <f2b-j-w-pf-ap> to any" | pfctl -f-`',
					),
					'ip6-start': (), # the same as ipv4
					'stop': (
						'`pfctl -sr 2>/dev/null | grep -v f2b-j-w-pf-ap | pfctl -f-`',
						'`pfctl -t f2b-j-w-pf-ap -T flush`',
						'`pfctl -t f2b-j-w-pf-ap -T kill`',
					),
					'ip4-check': ("`pfctl -sr | grep -q f2b-j-w-pf-ap`",),
					'ip6-check': ("`pfctl -sr | grep -q f2b-j-w-pf-ap`",),
					'ip4-ban':   ("`pfctl -t f2b-j-w-pf-ap -T add 192.0.2.1`",),
					'ip4-unban': ("`pfctl -t f2b-j-w-pf-ap -T delete 192.0.2.1`",),
					'ip6-ban':   ("`pfctl -t f2b-j-w-pf-ap -T add 2001:db8::`",),
					'ip6-unban': ("`pfctl -t f2b-j-w-pf-ap -T delete 2001:db8::`",),
				}),
				# firewallcmd-multiport --
				('j-w-fwcmd-mp', 'firewallcmd-multiport[name=%(__name__)s, bantime="10m", port="http,https", protocol="tcp", chain="INPUT"]', {
					'ip4': (' ipv4 ', 'icmp-port-unreachable'), 'ip6': (' ipv6 ', 'icmp6-port-unreachable'),
					'ip4-start': (
						"`firewall-cmd --direct --add-chain ipv4 filter f2b-j-w-fwcmd-mp`",
						"`firewall-cmd --direct --add-rule ipv4 filter f2b-j-w-fwcmd-mp 1000 -j RETURN`",
						"`firewall-cmd --direct --add-rule ipv4 filter INPUT 0 -m conntrack --ctstate NEW -p tcp -m multiport --dports http,https -j f2b-j-w-fwcmd-mp`",
					), 
					'ip6-start': (
						"`firewall-cmd --direct --add-chain ipv6 filter f2b-j-w-fwcmd-mp`",
						"`firewall-cmd --direct --add-rule ipv6 filter f2b-j-w-fwcmd-mp 1000 -j RETURN`",
						"`firewall-cmd --direct --add-rule ipv6 filter INPUT 0 -m conntrack --ctstate NEW -p tcp -m multiport --dports http,https -j f2b-j-w-fwcmd-mp`",
					),
					'stop': (
						"`firewall-cmd --direct --remove-rule ipv4 filter INPUT 0 -m conntrack --ctstate NEW -p tcp -m multiport --dports http,https -j f2b-j-w-fwcmd-mp`",
						"`firewall-cmd --direct --remove-rules ipv4 filter f2b-j-w-fwcmd-mp`",
						"`firewall-cmd --direct --remove-chain ipv4 filter f2b-j-w-fwcmd-mp`",
						"`firewall-cmd --direct --remove-rule ipv6 filter INPUT 0 -m conntrack --ctstate NEW -p tcp -m multiport --dports http,https -j f2b-j-w-fwcmd-mp`",
						"`firewall-cmd --direct --remove-rules ipv6 filter f2b-j-w-fwcmd-mp`",
						"`firewall-cmd --direct --remove-chain ipv6 filter f2b-j-w-fwcmd-mp`",
					),
					'ip4-check': (
						r"`firewall-cmd --direct --get-chains ipv4 filter | sed -e 's, ,\n,g' | grep -q '^f2b-j-w-fwcmd-mp$'`",
					),
					'ip6-check': (
						r"`firewall-cmd --direct --get-chains ipv6 filter | sed -e 's, ,\n,g' | grep -q '^f2b-j-w-fwcmd-mp$'`",
					),
					'ip4-ban': (
						r"`firewall-cmd --direct --add-rule ipv4 filter f2b-j-w-fwcmd-mp 0 -s 192.0.2.1 -j REJECT --reject-with icmp-port-unreachable`",
					),
					'ip4-unban': (
						r"`firewall-cmd --direct --remove-rule ipv4 filter f2b-j-w-fwcmd-mp 0 -s 192.0.2.1 -j REJECT --reject-with icmp-port-unreachable`",
					),
					'ip6-ban': (
						r"`firewall-cmd --direct --add-rule ipv6 filter f2b-j-w-fwcmd-mp 0 -s 2001:db8:: -j REJECT --reject-with icmp6-port-unreachable`",
					),
					'ip6-unban': (
						r"`firewall-cmd --direct --remove-rule ipv6 filter f2b-j-w-fwcmd-mp 0 -s 2001:db8:: -j REJECT --reject-with icmp6-port-unreachable`",
					),					
				}),
				# firewallcmd-allports --
				('j-w-fwcmd-ap', 'firewallcmd-allports[name=%(__name__)s, bantime="10m", protocol="tcp", chain="INPUT"]', {
					'ip4': (' ipv4 ', 'icmp-port-unreachable'), 'ip6': (' ipv6 ', 'icmp6-port-unreachable'),
					'ip4-start': (
						"`firewall-cmd --direct --add-chain ipv4 filter f2b-j-w-fwcmd-ap`",
						"`firewall-cmd --direct --add-rule ipv4 filter f2b-j-w-fwcmd-ap 1000 -j RETURN`",
						"`firewall-cmd --direct --add-rule ipv4 filter INPUT 0 -j f2b-j-w-fwcmd-ap`",
					), 
					'ip6-start': (
						"`firewall-cmd --direct --add-chain ipv6 filter f2b-j-w-fwcmd-ap`",
						"`firewall-cmd --direct --add-rule ipv6 filter f2b-j-w-fwcmd-ap 1000 -j RETURN`",
						"`firewall-cmd --direct --add-rule ipv6 filter INPUT 0 -j f2b-j-w-fwcmd-ap`",
					),
					'stop': (
						"`firewall-cmd --direct --remove-rule ipv4 filter INPUT 0 -j f2b-j-w-fwcmd-ap`",
						"`firewall-cmd --direct --remove-rules ipv4 filter f2b-j-w-fwcmd-ap`",
						"`firewall-cmd --direct --remove-chain ipv4 filter f2b-j-w-fwcmd-ap`",
						"`firewall-cmd --direct --remove-rule ipv6 filter INPUT 0 -j f2b-j-w-fwcmd-ap`",
						"`firewall-cmd --direct --remove-rules ipv6 filter f2b-j-w-fwcmd-ap`",
						"`firewall-cmd --direct --remove-chain ipv6 filter f2b-j-w-fwcmd-ap`",
					),
					'ip4-check': (
						r"`firewall-cmd --direct --get-chains ipv4 filter | sed -e 's, ,\n,g' | grep -q '^f2b-j-w-fwcmd-ap$'`",
					),
					'ip6-check': (
						r"`firewall-cmd --direct --get-chains ipv6 filter | sed -e 's, ,\n,g' | grep -q '^f2b-j-w-fwcmd-ap$'`",
					),
					'ip4-ban': (
						r"`firewall-cmd --direct --add-rule ipv4 filter f2b-j-w-fwcmd-ap 0 -s 192.0.2.1 -j REJECT --reject-with icmp-port-unreachable`",
					),
					'ip4-unban': (
						r"`firewall-cmd --direct --remove-rule ipv4 filter f2b-j-w-fwcmd-ap 0 -s 192.0.2.1 -j REJECT --reject-with icmp-port-unreachable`",
					),
					'ip6-ban': (
						r"`firewall-cmd --direct --add-rule ipv6 filter f2b-j-w-fwcmd-ap 0 -s 2001:db8:: -j REJECT --reject-with icmp6-port-unreachable`",
					),
					'ip6-unban': (
						r"`firewall-cmd --direct --remove-rule ipv6 filter f2b-j-w-fwcmd-ap 0 -s 2001:db8:: -j REJECT --reject-with icmp6-port-unreachable`",
					),					
				}),
				# firewallcmd-ipset --
				('j-w-fwcmd-ipset', 'firewallcmd-ipset[name=%(__name__)s, bantime="10m", port="http", protocol="tcp", chain="INPUT"]', {
					'ip4': (' f2b-j-w-fwcmd-ipset ',), 'ip6': (' f2b-j-w-fwcmd-ipset6 ',),
					'ip4-start': (
						"`ipset create f2b-j-w-fwcmd-ipset hash:ip timeout 600`",
						"`firewall-cmd --direct --add-rule ipv4 filter INPUT 0 -p tcp -m multiport --dports http -m set --match-set f2b-j-w-fwcmd-ipset src -j REJECT --reject-with icmp-port-unreachable`",
					), 
					'ip6-start': (
						"`ipset create f2b-j-w-fwcmd-ipset6 hash:ip timeout 600`",
						"`firewall-cmd --direct --add-rule ipv6 filter INPUT 0 -p tcp -m multiport --dports http -m set --match-set f2b-j-w-fwcmd-ipset6 src -j REJECT --reject-with icmp6-port-unreachable`",
					),
					'stop': (
						"`firewall-cmd --direct --remove-rule ipv4 filter INPUT 0 -p tcp -m multiport --dports http -m set --match-set f2b-j-w-fwcmd-ipset src -j REJECT --reject-with icmp-port-unreachable`",
						"`ipset flush f2b-j-w-fwcmd-ipset`",
						"`ipset destroy f2b-j-w-fwcmd-ipset`",
						"`firewall-cmd --direct --remove-rule ipv6 filter INPUT 0 -p tcp -m multiport --dports http -m set --match-set f2b-j-w-fwcmd-ipset6 src -j REJECT --reject-with icmp6-port-unreachable`",
						"`ipset flush f2b-j-w-fwcmd-ipset6`",
						"`ipset destroy f2b-j-w-fwcmd-ipset6`",
					),
					'ip4-check': (),
					'ip6-check': (),
					'ip4-ban': (
						r"`ipset add f2b-j-w-fwcmd-ipset 192.0.2.1 timeout 600 -exist`",
					),
					'ip4-unban': (
						r"`ipset del f2b-j-w-fwcmd-ipset 192.0.2.1 -exist`",
					),
					'ip6-ban': (
						r"`ipset add f2b-j-w-fwcmd-ipset6 2001:db8:: timeout 600 -exist`",
					),
					'ip6-unban': (
						r"`ipset del f2b-j-w-fwcmd-ipset6 2001:db8:: -exist`",
					),					
				}),
			)
			server = TestServer()
			transm = server._Server__transm
			cmdHandler = transm._Transmitter__commandHandler

			for jail, act, tests in testJailsActions:
				stream = self.getDefaultJailStream(jail, act)

				# for cmd in stream:
				# 	print(cmd)

				# transmit jail to the server:
				for cmd in stream:
					# command to server:
					ret, res = transm.proceed(cmd)
					self.assertEqual(ret, 0)

			jails = server._Server__jails

			tickets = {
				'ip4': BanTicket('192.0.2.1'),
				'ip6': BanTicket('2001:DB8::'),
			}
			for jail, act, tests in testJailsActions:
				# print(jail, jails[jail])
				for a in jails[jail].actions:
					action = jails[jail].actions[a]
					logSys.debug('# ' + ('=' * 50))
					logSys.debug('# == %-44s ==', jail + ' - ' + action._name)
					logSys.debug('# ' + ('=' * 50))
					self.assertTrue(isinstance(action, _actions.CommandAction))
					# wrap default command processor:
					action.executeCmd = self._executeCmd
					# test start :
					self.pruneLog('# === start ===')
					action.start()
					if tests.get('start'):
						self.assertLogged(*tests['start'], all=True)
					else:
						self.assertNotLogged(*tests['ip4-start']+tests['ip6-start'], all=True)
					ainfo = {
						'ip4': _actions.Actions.ActionInfo(tickets['ip4'], jails[jail]),
						'ip6': _actions.Actions.ActionInfo(tickets['ip6'], jails[jail]),
					}
					# test ban ip4 :
					self.pruneLog('# === ban-ipv4 ===')
					action.ban(ainfo['ip4'])
					if tests.get('ip4-start'): self.assertLogged(*tests['ip4-start'], all=True)
					if tests.get('ip6-start'): self.assertNotLogged(*tests['ip6-start'], all=True)
					self.assertLogged(*tests['ip4-check']+tests['ip4-ban'], all=True)
					self.assertNotLogged(*tests['ip6'], all=True)
					# test unban ip4 :
					self.pruneLog('# === unban ipv4 ===')
					action.unban(ainfo['ip4'])
					self.assertLogged(*tests['ip4-check']+tests['ip4-unban'], all=True)
					self.assertNotLogged(*tests['ip6'], all=True)
					# test ban ip6 :
					self.pruneLog('# === ban ipv6 ===')
					action.ban(ainfo['ip6'])
					if tests.get('ip6-start'): self.assertLogged(*tests['ip6-start'], all=True)
					if tests.get('ip4-start'): self.assertNotLogged(*tests['ip4-start'], all=True)
					self.assertLogged(*tests['ip6-check']+tests['ip6-ban'], all=True)
					self.assertNotLogged(*tests['ip4'], all=True)
					# test unban ip6 :
					self.pruneLog('# === unban ipv6 ===')
					action.unban(ainfo['ip6'])
					self.assertLogged(*tests['ip6-check']+tests['ip6-unban'], all=True)
					self.assertNotLogged(*tests['ip4'], all=True)
					# test flush for actions should supported this:
					if tests.get('flush'):
						self.pruneLog('# === flush ===')
						action.flush()
						self.assertLogged(*tests['flush'], all=True)
					# test stop :
					self.pruneLog('# === stop ===')
					action.stop()
					self.assertLogged(*tests['stop'], all=True)

		def _executeMailCmd(self, realCmd, timeout=60):
			# replace pipe to mail with pipe to cat:
			realCmd = re.sub(r'\)\s*\|\s*mail\b([^\n]*)',
				r') | cat; printf "\\n... | "; echo mail \1', realCmd)
			# replace abuse retrieving (possible no-network), just replace first occurrence of 'dig...':
			realCmd = re.sub(r'\bADDRESSES=\$\(dig\s[^\n]+',
				lambda m: 'ADDRESSES="abuse-1@abuse-test-server, abuse-2@abuse-test-server"',
					realCmd, 1)
			# execute action:
			return _actions.CommandAction.executeCmd(realCmd, timeout=timeout)

		def testComplexMailActionMultiLog(self):
			testJailsActions = (
				# mail-whois-lines --
				('j-mail-whois-lines', 
					'mail-whois-lines['
					  'name=%(__name__)s, grepopts="-m 1", grepmax=2, mailcmd="mail -s", ' +
						# 2 logs to test grep from multiple logs:
					  'logpath="' + os.path.join(TEST_FILES_DIR, "testcase01.log") + '\n' +
				    '         ' + os.path.join(TEST_FILES_DIR, "testcase01a.log") + '", '
					  '_whois_command="echo \'-- information about <ip> --\'"'
					  ']',
				{
					'ip4-ban': (
						'The IP 87.142.124.10 has just been banned by Fail2Ban after',
						'100 attempts against j-mail-whois-lines.',
						'Here is more information about 87.142.124.10 :',
						'-- information about 87.142.124.10 --',
						'Lines containing failures of 87.142.124.10 (max 2)',
						'testcase01.log:Dec 31 11:59:59 [sshd] error: PAM: Authentication failure for kevin from 87.142.124.10',
						'testcase01a.log:Dec 31 11:55:01 [sshd] error: PAM: Authentication failure for test from 87.142.124.10',
					),
				}),
				# complain --
				('j-complain-abuse', 
					'complain['
					  'name=%(__name__)s, grepopts="-m 1", grepmax=2, mailcmd="mail -s \'Hostname: <ip-host>, family: <family>\' - ",' +
					  # test reverse ip:
					  'debug=1,' +
						# 2 logs to test grep from multiple logs:
					  'logpath="' + os.path.join(TEST_FILES_DIR, "testcase01.log") + '\n' +
				    '         ' + os.path.join(TEST_FILES_DIR, "testcase01a.log") + '", '
					  ']',
				{
					'ip4-ban': (
						# test reverse ip:
						'try to resolve 10.124.142.87.abuse-contacts.abusix.org',
						'Lines containing failures of 87.142.124.10 (max 2)',
						'testcase01.log:Dec 31 11:59:59 [sshd] error: PAM: Authentication failure for kevin from 87.142.124.10',
						'testcase01a.log:Dec 31 11:55:01 [sshd] error: PAM: Authentication failure for test from 87.142.124.10',
						# both abuse mails should be separated with space:
						'mail -s Hostname: test-host, family: inet4 - Abuse from 87.142.124.10 abuse-1@abuse-test-server abuse-2@abuse-test-server',
					),
					'ip6-ban': (
						# test reverse ip:
						'try to resolve 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.abuse-contacts.abusix.org',
						'Lines containing failures of 2001:db8::1 (max 2)',
						# both abuse mails should be separated with space:
						'mail -s Hostname: test-host, family: inet6 - Abuse from 2001:db8::1 abuse-1@abuse-test-server abuse-2@abuse-test-server',
					),
				}),
			)
			server = TestServer()
			transm = server._Server__transm
			cmdHandler = transm._Transmitter__commandHandler

			for jail, act, tests in testJailsActions:
				stream = self.getDefaultJailStream(jail, act)

				# for cmd in stream:
				# 	print(cmd)

				# transmit jail to the server:
				for cmd in stream:
					# command to server:
					ret, res = transm.proceed(cmd)
					self.assertEqual(ret, 0)

			jails = server._Server__jails

			ipv4 = IPAddr('87.142.124.10')
			ipv6 = IPAddr('2001:db8::1');
			dmyjail = DummyJail()
			for jail, act, tests in testJailsActions:
				# print(jail, jails[jail])
				for a in jails[jail].actions:
					action = jails[jail].actions[a]
					logSys.debug('# ' + ('=' * 50))
					logSys.debug('# == %-44s ==', jail + ' - ' + action._name)
					logSys.debug('# ' + ('=' * 50))
					# wrap default command processor:
					action.executeCmd = self._executeMailCmd
					# test ban :
					for (test, ip) in (('ip4-ban', ipv4), ('ip6-ban', ipv6)):
						if not tests.get(test): continue
						self.pruneLog('# === %s ===' % test)
						ticket = BanTicket(ip)
						ticket.setAttempt(100)
						ticket = _actions.Actions.ActionInfo(ticket, dmyjail)
						action.ban(ticket)
						self.assertLogged(*tests[test], all=True)
