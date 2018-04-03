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
import unittest
import sys

from ..actiontestcase import CallingMap
from ..dummyjail import DummyJail
from ..servertestcase import IPAddr
from ..utils import LogCaptureTestCase, CONFIG_DIR

if sys.version_info >= (2,7): # pragma: no cover - may be unavailable
	class BadIPsActionTest(LogCaptureTestCase):

		available = True, None
		pythonModule = None
		modAction = None

		def setUp(self):
			"""Call before every test case."""
			super(BadIPsActionTest, self).setUp()
			unittest.F2B.SkipIfNoNetwork()

			self.jail = DummyJail()

			self.jail.actions.add("test")

			pythonModuleName = os.path.join(CONFIG_DIR, "action.d", "badips.py")

			# check availability (once if not alive, used shorter timeout as in test cases):
			if BadIPsActionTest.available[0]:
				if not BadIPsActionTest.modAction:
					if not BadIPsActionTest.pythonModule:
						BadIPsActionTest.pythonModule = self.jail.actions._load_python_module(pythonModuleName)
					BadIPsActionTest.modAction = BadIPsActionTest.pythonModule.Action
					self.jail.actions._load_python_module(pythonModuleName)
				BadIPsActionTest.available = BadIPsActionTest.modAction.isAvailable(timeout=2 if unittest.F2B.fast else 10)
			if not BadIPsActionTest.available[0]:
				raise unittest.SkipTest('Skip test because service is not available: %s' % BadIPsActionTest.available[1])

			self.jail.actions.add("badips", pythonModuleName, initOpts={
				'category': "ssh",
				'banaction': "test",
				'age': "2w",
				'score': 5,
				'key': "fail2ban-test-suite",
				#'bankey': "fail2ban-test-suite",
				'timeout': (3 if unittest.F2B.fast else 30),
				})
			self.action = self.jail.actions["badips"]

		def tearDown(self):
			"""Call after every test case."""
			# Must cancel timer!
			if self.action._timer:
				self.action._timer.cancel()
			super(BadIPsActionTest, self).tearDown()

		def testCategory(self):
			categories = self.action.getCategories()
			self.assertIn("ssh", categories)
			self.assertTrue(len(categories) >= 10)

			self.assertRaises(
				ValueError, setattr, self.action, "category",
				"invalid-category")

			# Not valid for reporting category...
			self.assertRaises(
				ValueError, setattr, self.action, "category", "mail")
			# but valid for blacklisting.
			self.action.bancategory = "mail"

		def testScore(self):
			self.assertRaises(ValueError, setattr, self.action, "score", -5)
			self.action.score = 3
			self.action.score = "3"

		def testBanaction(self):
			self.assertRaises(
				ValueError, setattr, self.action, "banaction",
				"invalid-action")
			self.action.banaction = "test"

		def testUpdateperiod(self):
			self.assertRaises(
				ValueError, setattr, self.action, "updateperiod", -50)
			self.assertRaises(
				ValueError, setattr, self.action, "updateperiod", 0)
			self.action.updateperiod = 900
			self.action.updateperiod = "900"

		def testStartStop(self):
			self.action.start()
			self.assertTrue(len(self.action._bannedips) > 10,
				"%s is fewer as 10: %r" % (len(self.action._bannedips), self.action._bannedips))
			self.action.stop()
			self.assertTrue(len(self.action._bannedips) == 0)

		def testBanIP(self):
			aInfo = CallingMap({
				'ip': IPAddr('192.0.2.1')
			})
			self.action.ban(aInfo)
			self.assertLogged('badips.com: ban', wait=True)
			self.pruneLog()
			# produce an error using wrong category/IP:
			self.action._category = 'f2b-this-category-dont-available-test-suite-only'
			aInfo['ip'] = ''
			self.assertRaises(BadIPsActionTest.pythonModule.HTTPError, self.action.ban, aInfo)
			self.assertLogged('IP is invalid', 'invalid category', wait=True, all=False)
