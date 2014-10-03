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

from ..dummyjail import DummyJail
from ..utils import CONFIG_DIR

if sys.version_info >= (2,7):
	class BadIPsActionTest(unittest.TestCase):

		def setUp(self):
			"""Call before every test case."""
			self.jail = DummyJail()

			self.jail.actions.add("test")

			pythonModule = os.path.join(CONFIG_DIR, "action.d", "badips.py")
			self.jail.actions.add("badips", pythonModule, initOpts={
				'category': "ssh",
				'banaction': "test",
				})
			self.action = self.jail.actions["badips"]

		def tearDown(self):
			"""Call after every test case."""
			# Must cancel timer!
			if self.action._timer:
				self.action._timer.cancel()

		def testCategory(self):
			categories = self.action.getCategories()
			self.assertTrue("ssh" in categories)
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
			self.action.score = 5
			self.action.score = "5"

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

		def testStart(self):
			self.action.start()
			self.assertTrue(len(self.action._bannedips) > 10)

		def testStop(self):
			self.testStart()
			self.action.stop()
			self.assertTrue(len(self.action._bannedips) == 0)
