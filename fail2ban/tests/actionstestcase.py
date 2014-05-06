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

# Author: Daniel Black
# 

__author__ = "Daniel Black"
__copyright__ = "Copyright (c) 2013 Daniel Black"
__license__ = "GPL"

import time
import os
import tempfile

from ..server.actions import Actions
from .dummyjail import DummyJail
from .utils import LogCaptureTestCase

TEST_FILES_DIR = os.path.join(os.path.dirname(__file__), "files")

class ExecuteActions(LogCaptureTestCase):

	def setUp(self):
		"""Call before every test case."""
		super(ExecuteActions, self).setUp()
		self.__jail = DummyJail()
		self.__actions = Actions(self.__jail)
		self.__tmpfile, self.__tmpfilename  = tempfile.mkstemp()

	def tearDown(self):
		super(ExecuteActions, self).tearDown()
		os.remove(self.__tmpfilename)

	def defaultActions(self):
		self.__actions.add('ip')
		self.__ip = self.__actions['ip']
		self.__ip.actionstart = 'echo ip start 64 >> "%s"' % self.__tmpfilename
		self.__ip.actionban = 'echo ip ban <ip> >> "%s"' % self.__tmpfilename
		self.__ip.actionunban = 'echo ip unban <ip> >> "%s"' % self.__tmpfilename
		self.__ip.actioncheck = 'echo ip check <ip> >> "%s"' % self.__tmpfilename
		self.__ip.actionstop = 'echo ip stop >> "%s"' % self.__tmpfilename

	def testActionsAddDuplicateName(self):
		self.__actions.add('test')
		self.assertRaises(ValueError, self.__actions.add, 'test')

	def testActionsManipulation(self):
		self.__actions.add('test')
		self.assertTrue(self.__actions['test'])
		self.assertTrue('test' in self.__actions)
		self.assertFalse('nonexistant action' in self.__actions)
		self.__actions.add('test1')
		del self.__actions['test']
		del self.__actions['test1']
		self.assertFalse('test' in self.__actions)
		self.assertEqual(len(self.__actions), 0)

		self.__actions.setBanTime(127)
		self.assertEqual(self.__actions.getBanTime(),127)
		self.assertRaises(ValueError, self.__actions.removeBannedIP, '127.0.0.1')


	def testActionsOutput(self):
		self.defaultActions()
		self.__actions.start()
		with open(self.__tmpfilename) as f:
			time.sleep(3)
			self.assertEqual(f.read(),"ip start 64\n")

		self.__actions.stop()
		self.__actions.join()
		self.assertEqual(self.__actions.status,[("Currently banned", 0 ),
               ("Total banned", 0 ), ("Banned IP list", [] )])


	def testAddActionPython(self):
		self.__actions.add(
			"Action", os.path.join(TEST_FILES_DIR, "action.d/action.py"),
			{'opt1': 'value'})

		self.assertTrue(self._is_logged("TestAction initialised"))

		self.__actions.start()
		time.sleep(3)
		self.assertTrue(self._is_logged("TestAction action start"))

		self.__actions.stop()
		self.__actions.join()
		self.assertTrue(self._is_logged("TestAction action stop"))

		self.assertRaises(IOError,
			self.__actions.add, "Action3", "/does/not/exist.py", {})

		# With optional argument
		self.__actions.add(
			"Action4", os.path.join(TEST_FILES_DIR, "action.d/action.py"),
			{'opt1': 'value', 'opt2': 'value2'})
		# With too many arguments
		self.assertRaises(
			TypeError, self.__actions.add, "Action5",
			os.path.join(TEST_FILES_DIR, "action.d/action.py"),
			{'opt1': 'value', 'opt2': 'value2', 'opt3': 'value3'})
		# Missing required argument
		self.assertRaises(
			TypeError, self.__actions.add, "Action5",
			os.path.join(TEST_FILES_DIR, "action.d/action.py"), {})

	def testAddPythonActionNOK(self):
		self.assertRaises(RuntimeError, self.__actions.add,
			"Action", os.path.join(TEST_FILES_DIR,
				"action.d/action_noAction.py"),
			{})
		self.assertRaises(RuntimeError, self.__actions.add,
			"Action", os.path.join(TEST_FILES_DIR,
				"action.d/action_nomethod.py"),
			{})
		self.__actions.add(
			"Action", os.path.join(TEST_FILES_DIR,
				"action.d/action_errors.py"),
			{})
		self.__actions.start()
		time.sleep(3)
		self.assertTrue(self._is_logged("Failed to start"))
		self.__actions.stop()
		self.__actions.join()
		self.assertTrue(self._is_logged("Failed to stop"))


# Author: Serg G. Brester (sebres)
# 

__author__ = "Serg Brester"
__copyright__ = "Copyright (c) 2014 Serg G. Brester"

class BanTimeIncr(LogCaptureTestCase):

	def setUp(self):
		"""Call before every test case."""
		super(BanTimeIncr, self).setUp()
		self.__jail = DummyJail()
		self.__actions = Actions(self.__jail)
		self.__tmpfile, self.__tmpfilename  = tempfile.mkstemp()

	def tearDown(self):
		super(BanTimeIncr, self).tearDown()
		os.remove(self.__tmpfilename)

	def testMultipliers(self):
		a = self.__actions;
		a.setBanTimeExtra('maxtime', '24*60*60')
		a.setBanTimeExtra('rndtime', None)
		a.setBanTimeExtra('factor', None)
		a.setBanTimeExtra('multipliers', '1 2 4 8 16 32 64 128 256')
		self.assertEqual(
			[a.calcBanTime(600, i) for i in xrange(1, 11)],
			[1200, 2400, 4800, 9600, 19200, 38400, 76800, 86400, 86400, 86400]
		)
		# with extra large max time (30 days):
		a.setBanTimeExtra('maxtime', '30*24*60*60')
		self.assertEqual(
			[a.calcBanTime(600, i) for i in xrange(1, 11)],
			[1200, 2400, 4800, 9600, 19200, 38400, 76800, 153600, 153600, 153600]
		)
		a.setBanTimeExtra('maxtime', '24*60*60')
		# change factor :
		a.setBanTimeExtra('factor', '2');
		self.assertEqual(
			[a.calcBanTime(600, i) for i in xrange(1, 11)],
			[2400, 4800, 9600, 19200, 38400, 76800, 86400, 86400, 86400, 86400]
		)
		a.setBanTimeExtra('factor', None);
		# change max time :
		a.setBanTimeExtra('maxtime', '12*60*60')
		self.assertEqual(
			[a.calcBanTime(600, i) for i in xrange(1, 11)],
			[1200, 2400, 4800, 9600, 19200, 38400, 43200, 43200, 43200, 43200]
		)
		a.setBanTimeExtra('maxtime', '24*60*60')
		## test randomization - not possibe all 10 times we have random = 0:
		a.setBanTimeExtra('rndtime', '5*60')
		self.assertTrue(
			False in [1200 in [a.calcBanTime(600, 1) for i in xrange(10)] for c in xrange(10)]
		)
		a.setBanTimeExtra('rndtime', None)
		self.assertFalse(
			False in [1200 in [a.calcBanTime(600, 1) for i in xrange(10)] for c in xrange(10)]
		)
		# restore default:
		a.setBanTimeExtra('multipliers', None)
		a.setBanTimeExtra('factor', None);
		a.setBanTimeExtra('maxtime', '24*60*60')
		a.setBanTimeExtra('rndtime', None)

	def testFormula(self):
		a = self.__actions;
		a.setBanTimeExtra('maxtime', '24*60*60')
		a.setBanTimeExtra('rndtime', None)
		a.setBanTimeExtra('factor', None)
		## use default formula:
		a.setBanTimeExtra('multipliers', None)
		self.assertEqual(
			[int(a.calcBanTime(600, i)) for i in xrange(1, 11)],
			[1200, 2400, 4800, 9600, 19200, 38400, 76800, 86400, 86400, 86400]
		)
		# with extra large max time (30 days):
		a.setBanTimeExtra('maxtime', '30*24*60*60')
		self.assertEqual(
			[int(a.calcBanTime(600, i)) for i in xrange(1, 11)],
			[1200, 2400, 4800, 9600, 19200, 38400, 76800, 153601, 307203, 614407]
		)
		a.setBanTimeExtra('maxtime', '24*60*60')
		# change factor :
		a.setBanTimeExtra('factor', '1');
		self.assertEqual(
			[int(a.calcBanTime(600, i)) for i in xrange(1, 11)],
			[1630, 4433, 12051, 32758, 86400, 86400, 86400, 86400, 86400, 86400]
		)
		a.setBanTimeExtra('factor', None);
		# change max time :
		a.setBanTimeExtra('maxtime', '12*60*60')
		self.assertEqual(
			[int(a.calcBanTime(600, i)) for i in xrange(1, 11)],
			[1200, 2400, 4800, 9600, 19200, 38400, 43200, 43200, 43200, 43200]
		)
		a.setBanTimeExtra('maxtime', '24*60*60')
		## test randomization - not possibe all 10 times we have random = 0:
		a.setBanTimeExtra('rndtime', '5*60')
		self.assertTrue(
			False in [1200 in [int(a.calcBanTime(600, 1)) for i in xrange(10)] for c in xrange(10)]
		)
		a.setBanTimeExtra('rndtime', None)
		self.assertFalse(
			False in [1200 in [int(a.calcBanTime(600, 1)) for i in xrange(10)] for c in xrange(10)]
		)
		# restore default:
		a.setBanTimeExtra('multipliers', None)
		a.setBanTimeExtra('factor', None);
		a.setBanTimeExtra('maxtime', '24*60*60')
		a.setBanTimeExtra('rndtime', None)

