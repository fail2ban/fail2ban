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
from functools import wraps
from socket import timeout
from ssl import SSLError

from ..actiontestcase import CallingMap
from ..dummyjail import DummyJail
from ..servertestcase import IPAddr
from ..utils import LogCaptureTestCase, CONFIG_DIR

if sys.version_info >= (3, ): # pragma: 2.x no cover
	from urllib.error import HTTPError, URLError
else: # pragma: 3.x no cover
	from urllib2 import HTTPError, URLError

def skip_if_not_available(f):
	"""Helper to decorate tests to skip in case of timeout/http-errors like "502 bad gateway".
	"""
	@wraps(f)
	def wrapper(self, *args):
		try:
			return f(self, *args)
		except (SSLError, HTTPError, URLError, timeout) as e: # pragma: no cover - timeout/availability issues
			if not isinstance(e, timeout) and 'timed out' not in str(e):
				if not hasattr(e, 'code') or e.code > 200 and e.code <= 404:
					raise
			raise unittest.SkipTest('Skip test because of %s' % e)
	return wrapper

if sys.version_info >= (2,7): # pragma: no cover - may be unavailable
	class BadIPsActionTest(LogCaptureTestCase):

		available = True, None
		pythonModule = None
		modAction = None

		@skip_if_not_available
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
				BadIPsActionTest.available = BadIPsActionTest.modAction.isAvailable(timeout=2 if unittest.F2B.fast else 30)
			if not BadIPsActionTest.available[0]:
				raise unittest.SkipTest('Skip test because service is not available: %s' % BadIPsActionTest.available[1])

			self.jail.actions.add("badips", pythonModuleName, initOpts={
				'category': "ssh",
				'banaction': "test",
				'age': "2w",
				'score': 5,
				#'key': "fail2ban-test-suite",
				#'bankey': "fail2ban-test-suite",
				'timeout': (3 if unittest.F2B.fast else 60),
				})
			self.action = self.jail.actions["badips"]

		def tearDown(self):
			"""Call after every test case."""
			# Must cancel timer!
			if self.action._timer:
				self.action._timer.cancel()
			super(BadIPsActionTest, self).tearDown()

		@skip_if_not_available
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

		@skip_if_not_available
		def testScore(self):
			self.assertRaises(ValueError, setattr, self.action, "score", -5)
			self.action.score = 3
			self.action.score = "3"

		@skip_if_not_available
		def testBanaction(self):
			self.assertRaises(
				ValueError, setattr, self.action, "banaction",
				"invalid-action")
			self.action.banaction = "test"

		@skip_if_not_available
		def testUpdateperiod(self):
			self.assertRaises(
				ValueError, setattr, self.action, "updateperiod", -50)
			self.assertRaises(
				ValueError, setattr, self.action, "updateperiod", 0)
			self.action.updateperiod = 900
			self.action.updateperiod = "900"

		@skip_if_not_available
		def testStartStop(self):
			self.action.start()
			self.assertTrue(len(self.action._bannedips) > 10,
				"%s is fewer as 10: %r" % (len(self.action._bannedips), self.action._bannedips))
			self.action.stop()
			self.assertTrue(len(self.action._bannedips) == 0)

		@skip_if_not_available
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
