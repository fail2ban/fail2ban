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

import os
import smtpd
import asyncore
import threading
import unittest
import sys
if sys.version_info >= (3, 3):
	import importlib
else:
	import imp

from ..dummyjail import DummyJail

from ..utils import CONFIG_DIR


class TestSMTPServer(smtpd.SMTPServer):

	def process_message(self, peer, mailfrom, rcpttos, data):
		self.peer = peer
		self.mailfrom = mailfrom
		self.rcpttos = rcpttos
		self.data = data


class SMTPActionTest(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""
		self.jail = DummyJail()
		pythonModule = os.path.join(CONFIG_DIR, "action.d", "smtp.py")
		pythonModuleName = os.path.basename(pythonModule.rstrip(".py"))
		if sys.version_info >= (3, 3):
			customActionModule = importlib.machinery.SourceFileLoader(
				pythonModuleName, pythonModule).load_module()
		else:
			customActionModule = imp.load_source(
				pythonModuleName, pythonModule)

		self.smtpd = TestSMTPServer(("localhost", 0), None)
		port = self.smtpd.socket.getsockname()[1]

		self.action = customActionModule.Action(
			self.jail, "test", host="127.0.0.1:%i" % port)

		self._loop_thread = threading.Thread(
			target=asyncore.loop, kwargs={'timeout': 1})
		self._loop_thread.start()

	def tearDown(self):
		"""Call after every test case."""
		self.smtpd.close()
		self._loop_thread.join()

	def testStart(self):
		self.action.start()
		self.assertEqual(self.smtpd.mailfrom, "fail2ban")
		self.assertEqual(self.smtpd.rcpttos, ["root"])
		self.assertTrue(
			"Subject: [Fail2Ban] %s: started" % self.jail.name
			in self.smtpd.data)

	def testStop(self):
		self.action.stop()
		self.assertEqual(self.smtpd.mailfrom, "fail2ban")
		self.assertEqual(self.smtpd.rcpttos, ["root"])
		self.assertTrue(
			"Subject: [Fail2Ban] %s: stopped" %
				self.jail.name in self.smtpd.data)

	def testBan(self):
		aInfo = {
			'ip': "127.0.0.2",
			'failures': 3,
			'matches': "Test fail 1\n",
			'ipjailmatches': "Test fail 1\nTest Fail2\n",
			'ipmatches': "Test fail 1\nTest Fail2\nTest Fail3\n",
			}

		self.action.ban(aInfo)
		self.assertEqual(self.smtpd.mailfrom, "fail2ban")
		self.assertEqual(self.smtpd.rcpttos, ["root"])
		subject = "Subject: [Fail2Ban] %s: banned %s" % (
			self.jail.name, aInfo['ip'])
		self.assertTrue(subject in self.smtpd.data.replace("\n", ""))
		self.assertTrue(
			"%i attempts" % aInfo['failures'] in self.smtpd.data)

		self.action.matches = "matches"
		self.action.ban(aInfo)
		self.assertTrue(aInfo['matches'] in self.smtpd.data)

		self.action.matches = "ipjailmatches"
		self.action.ban(aInfo)
		self.assertTrue(aInfo['ipjailmatches'] in self.smtpd.data)

		self.action.matches = "ipmatches"
		self.action.ban(aInfo)
		self.assertTrue(aInfo['ipmatches'] in self.smtpd.data)

	def testOptions(self):
		self.action.start()
		self.assertEqual(self.smtpd.mailfrom, "fail2ban")
		self.assertEqual(self.smtpd.rcpttos, ["root"])

		self.action.fromname = "Test"
		self.action.fromaddr = "test@example.com"
		self.action.toaddr = "test@example.com, test2@example.com"
		self.action.start()
		self.assertEqual(self.smtpd.mailfrom, "test@example.com")
		self.assertTrue("From: %s <%s>" %
			(self.action.fromname, self.action.fromaddr) in self.smtpd.data)
		self.assertEqual(set(self.smtpd.rcpttos), set(["test@example.com", "test2@example.com"]))
