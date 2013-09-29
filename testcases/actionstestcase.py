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

import unittest, time
import sys, os, tempfile
from server.actions import Actions
from dummyjail import DummyJail

class ExecuteActions(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""
		self.__jail = DummyJail()
		self.__actions = Actions(self.__jail)
		self.__tmpfile, self.__tmpfilename  = tempfile.mkstemp()

	def tearDown(self):
		os.remove(self.__tmpfilename)

	def defaultActions(self):
		self.__actions.addAction('ip')
		self.__ip = self.__actions.getAction('ip')
		self.__ip.setActionStart('echo ip start 64 >> "%s"' % self.__tmpfilename )
		self.__ip.setActionBan('echo ip ban <ip> >> "%s"' % self.__tmpfilename )
		self.__ip.setActionUnban('echo ip unban <ip> >> "%s"' % self.__tmpfilename )
		self.__ip.setActionCheck('echo ip check <ip> >> "%s"' % self.__tmpfilename )
		self.__ip.setActionStop('echo ip stop >> "%s"' % self.__tmpfilename )

	def testActionsManipulation(self):
		self.__actions.addAction('test')
		self.assertTrue(self.__actions.getAction('test'))
		self.assertTrue(self.__actions.getLastAction())
		self.assertRaises(KeyError,self.__actions.getAction,*['nonexistant action'])
		self.__actions.addAction('test1')
		self.__actions.delAction('test')
		self.__actions.delAction('test1')
		self.assertRaises(KeyError, self.__actions.getAction, *['test'])
		self.assertRaises(IndexError,self.__actions.getLastAction)

		self.__actions.setBanTime(127)
		self.assertEqual(self.__actions.getBanTime(),127)
		self.assertRaises(ValueError, self.__actions.removeBannedIP, '127.0.0.1')


	def testActionsOutput(self):
		self.defaultActions()
		self.__actions.start()
		f = open(self.__tmpfilename)
		time.sleep(3)
		self.assertEqual(f.read(),"ip start 64\n")

		self.__actions.stop()
		self.__actions.join()
		self.assertEqual(self.__actions.status(),[("Currently banned", 0 ),
               ("Total banned", 0 ), ("IP list", [] )])

