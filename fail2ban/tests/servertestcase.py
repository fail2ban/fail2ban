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
# $Revision$

__author__ = "Cyril Jaquier"
__version__ = "$Revision$"
__date__ = "$Date$"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import unittest, socket, time, tempfile, os, locale

from fail2ban.server.server import Server
from fail2ban.exceptions import UnknownJailException

TEST_FILES_DIR = os.path.join(os.path.dirname(__file__), "files")

class StartStop(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""
		self.__server = Server()
		self.__server.setLogLevel(0)
		self.__server.start(False)

	def tearDown(self):
		"""Call after every test case."""
		self.__server.quit()
	
	def testStartStopJail(self):
		name = "TestCase"
		self.__server.addJail(name)
		self.__server.startJail(name)
		time.sleep(1)
		self.__server.stopJail(name)

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

	def setGetTest(self, cmd, inValue, outValue=None, jail=None):
		setCmd = ["set", cmd, inValue]
		getCmd = ["get", cmd]
		if jail is not None:
			setCmd.insert(1, jail)
			getCmd.insert(1, jail)
		if outValue is None:
			outValue = inValue

		self.assertEqual(self.transm.proceed(setCmd), (0, outValue))
		self.assertEqual(self.transm.proceed(getCmd), (0, outValue))

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
			self.assertEqual(
				self.transm.proceed(["set", jail, cmdAdd, value]),
				(0, values[:n+1]))
			self.assertEqual(
				self.transm.proceed(["get", jail, cmd]),
				(0, values[:n+1]))
		for n, value in enumerate(values):
			self.assertEqual(
				self.transm.proceed(["set", jail, cmdDel, value]),
				(0, values[n+1:]))
			self.assertEqual(
				self.transm.proceed(["get", jail, cmd]),
				(0, values[n+1:]))

	def jailAddDelRegexTest(self, cmd, inValues, outValues, jail):
		cmdAdd = "add" + cmd
		cmdDel = "del" + cmd

		if outValues is None:
			outValues = inValues

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

	def testSleep(self):
		t0 = time.time()
		self.assertEqual(self.transm.proceed(["sleep", "1"]), (0, None))
		t1 = time.time()
		# Approx 1 second delay
		self.assertAlmostEqual(t1 - t0, 1, places=2)

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
		self.assertRaises(
			UnknownJailException, self.server.isAlive, self.jailName)

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
		self.assertRaises(
			UnknownJailException, self.server.isAlive, self.jailName)
		self.assertRaises(
			UnknownJailException, self.server.isAlive, "TestJail2")

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

		# Invalid file
		value = "this_file_shouldn't_exist"
		result = self.transm.proceed(
			["set", self.jailName, "addlogpath", value])
		self.assertTrue(isinstance(result[1], IOError))

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

	def testJailRegex(self):
		self.jailAddDelRegexTest("failregex",
			[
				"user john at <HOST>",
				"Admin user login from <HOST>",
				"failed attempt from <HOST> again",
			],
			[
				"user john at (?:::f{4,6}:)?(?P<host>[\w\-.^_]+)",
				"Admin user login from (?:::f{4,6}:)?(?P<host>[\w\-.^_]+)",
				"failed attempt from (?:::f{4,6}:)?(?P<host>[\w\-.^_]+) again",
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
				"Admin user login from (?:::f{4,6}:)?(?P<host>[\w\-.^_]+)",
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
					('filter', [
						('Currently failed', 0),
						('Total failed', 0),
						('File list', [])]
					),
					('action', [
						('Currently banned', 0),
						('Total banned', 0),
						('IP list', [])]
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
			self.transm.proceed(["get", self.jailName, "addaction", action]),
			(0, action))
		for cmd, value in zip(cmdList, cmdValueList):
			self.assertEqual(
				self.transm.proceed(
					["set", self.jailName, cmd, action, value]),
				(0, value))
		for cmd, value in zip(cmdList, cmdValueList):
			self.assertEqual(
				self.transm.proceed(["get", self.jailName, cmd, action]),
				(0, value))
		self.assertEqual(
			self.transm.proceed(
				["set", self.jailName, "setcinfo", action, "KEY", "VALUE"]),
			(0, "VALUE"))
		self.assertEqual(
			self.transm.proceed(
				["get", self.jailName, "cinfo", action, "KEY"]),
			(0, "VALUE"))
		self.assertEqual(
			self.transm.proceed(
				["get", self.jailName, "cinfo", action, "InvalidKey"])[0],
			1)
		self.assertEqual(
			self.transm.proceed(
				["set", self.jailName, "delcinfo", action, "KEY"]),
			(0, None))
		self.assertEqual(
			self.transm.proceed(["set", self.jailName, "delaction", action]),
			(0, None))
		self.assertEqual(
			self.transm.proceed(
				["set", self.jailName, "delaction", "Doesn't exist"])[0],1)

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

class TransmitterLogging(TransmitterBase):

	def setUp(self):
		self.server = Server()
		self.server.setLogTarget("/dev/null")
		self.server.setLogLevel(0)
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

		self.transm.proceed(["set", "/dev/null"])
		for logTarget in logTargets:
			os.remove(logTarget)

		self.setGetTest("logtarget", "STDOUT")
		self.setGetTest("logtarget", "STDERR")
		self.setGetTest("logtarget", "SYSLOG")

	def testLogLevel(self):
		self.setGetTest("loglevel", "4", 4)
		self.setGetTest("loglevel", "2", 2)
		self.setGetTest("loglevel", "-1", -1)
		self.setGetTest("loglevel", "0", 0)
		self.setGetTestNOK("loglevel", "Bird")
