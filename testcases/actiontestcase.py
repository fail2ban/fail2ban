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

import unittest, time
import sys
from server.action import Action
import logredirect

class ExecuteAction(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""
		self.__action = Action("Test")

		# For extended testing of what gets output into logging
		# system, we will redirect it to a string
		self.log = logredirect.LogRedirect()

	def tearDown(self):
		"""Call after every test case."""
		self.log.restore()
		self.__action.execActionStop()

	def _is_logged(self, s):
		return self.log.is_logged(s)

	def testAttributes(self):
		self.assertEqual(self.__action.getName(),'Test')
		self.__action.setName('fail2ban super action')
		self.assertEqual(self.__action.getName(),'fail2ban super action')
		self.__action.setCInfo('dog','run')
		self.assertEqual(self.__action.getCInfo('dog'),'run')
		self.__action.delCInfo('dog')
		self.assertRaises(KeyError,self.__action.getCInfo,'dog')

	def testReplaceTag(self):
		aInfo = {
			'HOST': "192.0.2.0",
			'ABC': "123",
			'xyz': "890",
		}
		self.assertEqual(
			self.__action.replaceTag("Text <HOST> text", aInfo),
			"Text 192.0.2.0 text")
		self.assertEqual(
			self.__action.replaceTag("Text <xyz> text <ABC> ABC", aInfo),
			"Text 890 text 123 ABC")
		self.assertEqual(
			self.__action.replaceTag("<matches>",
				{'matches': "some >char< should \< be[ escap}ed&"}),
			r"some \>char\< should \\\< be\[ escap\}ed\&")

	def testExecuteActionBan(self):
		self.__action.setActionStart("touch /tmp/fail2ban.test")
		self.assertEqual(self.__action.getActionStart(),"touch /tmp/fail2ban.test")
		self.__action.setActionStop("rm -f /tmp/fail2ban.test")
		self.assertEqual(self.__action.getActionStop(),"rm -f /tmp/fail2ban.test")
		self.__action.setActionBan("echo -n")
		self.assertEqual(self.__action.getActionBan(),"echo -n")
		self.__action.setActionUnban("echo")
		self.assertEqual(self.__action.getActionUnban(),"echo")
		self.__action.setActionCheck("[ -e /tmp/fail2ban.test ]")
		self.assertEqual(self.__action.getActionCheck(),"[ -e /tmp/fail2ban.test ]")

		self.assertFalse(self._is_logged('returned'))
		# no action was actually executed yet

		self.assertTrue(self.__action.execActionBan(None))
		self.assertTrue(self._is_logged('Invariant check failed'))
		self.assertTrue(self._is_logged('returned successfully'))


	def testExecuteIncorrectCmd(self):
		Action.executeCmd('/bin/ls >/dev/null\nbogusXXX now 2>/dev/null')
		self.assertTrue(self._is_logged('HINT on 7f00: "Command not found"'))
