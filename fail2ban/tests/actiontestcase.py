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

import unittest, time
import logging, sys
from StringIO import StringIO

from fail2ban.server.action import Action

class ExecuteAction(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""
		self.__action = Action("Test")

		# For extended testing of what gets output into logging
		# system, we will redirect it to a string
		logSys = logging.getLogger("fail2ban")

		# Keep old settings
		self._old_level = logSys.level
		self._old_handlers = logSys.handlers
		# Let's log everything into a string
		self._log = StringIO()
		logSys.handlers = [logging.StreamHandler(self._log)]
		logSys.setLevel(getattr(logging, 'DEBUG'))

	def tearDown(self):
		"""Call after every test case."""
		# print "O: >>%s<<" % self._log.getvalue()
		logSys = logging.getLogger("fail2ban")
		logSys.handlers = self._old_handlers
		logSys.level = self._old_level
		self.__action.execActionStop()

	def _is_logged(self, s):
		return s in self._log.getvalue()

	def testNameChange(self):
		self.assertEqual(self.__action.getName(), "Test")
		self.__action.setName("Tricky Test")
		self.assertEqual(self.__action.getName(), "Tricky Test")
		
	def testSubstituteRecursiveTags(self):
		aInfo = {
			'HOST': "192.0.2.0",
			'ABC': "123 <HOST>",
			'xyz': "890 <ABC>",
		}
		# Recursion is bad
		self.assertFalse(Action.substituteRecursiveTags({'A': '<A>'}))
		self.assertFalse(Action.substituteRecursiveTags({'A': '<B>', 'B': '<A>'}))
		self.assertFalse(Action.substituteRecursiveTags({'A': '<B>', 'B': '<C>', 'C': '<A>'}))
		# missing tags are ok
		self.assertEqual(Action.substituteRecursiveTags({'A': '<C>'}), {'A': '<C>'})
		self.assertEqual(Action.substituteRecursiveTags({'A': '<C> <D> <X>','X':'fun'}), {'A': '<C> <D> fun', 'X':'fun'})
		self.assertEqual(Action.substituteRecursiveTags({'A': '<C> <B>', 'B': 'cool'}), {'A': '<C> cool', 'B': 'cool'})
		# rest is just cool
		self.assertEqual(Action.substituteRecursiveTags(aInfo),
								{ 'HOST': "192.0.2.0",
									'ABC': '123 192.0.2.0',
									'xyz': '890 123 192.0.2.0',
								})

	def testReplaceTag(self):
		aInfo = {
			'HOST': "192.0.2.0",
			'ABC': "123",
			'xyz': "890",
		}
		self.assertEqual(
			self.__action.replaceTag("Text<br>text", aInfo),
			"Text\ntext")
		self.assertEqual(
			self.__action.replaceTag("Text <HOST> text", aInfo),
			"Text 192.0.2.0 text")
		self.assertEqual(
			self.__action.replaceTag("Text <xyz> text <ABC> ABC", aInfo),
			"Text 890 text 123 ABC")
		self.assertEqual(
			self.__action.replaceTag("<matches>",
				{'matches': "some >char< should \< be[ escap}ed&\n"}),
			"some \\>char\\< should \\\\\\< be\\[ escap\\}ed\\&\n")
		self.assertEqual(
			self.__action.replaceTag("<ipmatches>",
				{'ipmatches': "some >char< should \< be[ escap}ed&\n"}),
			"some \\>char\\< should \\\\\\< be\\[ escap\\}ed\\&\n")
		self.assertEqual(
			self.__action.replaceTag("<ipjailmatches>",
				{'ipjailmatches': "some >char< should \< be[ escap}ed&\n"}),
			"some \\>char\\< should \\\\\\< be\\[ escap\\}ed\\&\n")

		# Callable
		self.assertEqual(
			self.__action.replaceTag("09 <callable> 11",
				{'callable': lambda: str(10)}),
			"09 10 11")

		# As tag not present, therefore callable should not be called
		# Will raise ValueError if it is
		self.assertEqual(
			self.__action.replaceTag("abc",
				{'callable': lambda: int("a")}), "abc")

	def testExecuteActionBan(self):
		self.__action.setActionStart("touch /tmp/fail2ban.test")
		self.assertEqual(self.__action.getActionStart(), "touch /tmp/fail2ban.test")
		self.__action.setActionStop("rm -f /tmp/fail2ban.test")
		self.assertEqual(self.__action.getActionStop(), 'rm -f /tmp/fail2ban.test')
		self.__action.setActionBan("echo -n")
		self.assertEqual(self.__action.getActionBan(), 'echo -n')
		self.__action.setActionCheck("[ -e /tmp/fail2ban.test ]")
		self.assertEqual(self.__action.getActionCheck(), '[ -e /tmp/fail2ban.test ]')
		self.__action.setActionUnban("true")
		self.assertEqual(self.__action.getActionUnban(), 'true')

		self.assertFalse(self._is_logged('returned'))
		# no action was actually executed yet

		self.assertTrue(self.__action.execActionBan(None))
		self.assertTrue(self._is_logged('Invariant check failed'))
		self.assertTrue(self._is_logged('returned successfully'))

	def testExecuteActionEmptyUnban(self):
		self.__action.setActionUnban("")
		self.assertTrue(self.__action.execActionUnban(None))
		self.assertTrue(self._is_logged('Nothing to do'))

	def testExecuteActionStartCtags(self):
		self.__action.setCInfo("HOST","192.0.2.0")
		self.__action.setActionStart("touch /tmp/fail2ban.test.<HOST>")
		self.__action.setActionStop("rm -f /tmp/fail2ban.test.<HOST>")
		self.__action.setActionCheck("[ -e /tmp/fail2ban.test.192.0.2.0 ]")
		self.assertTrue(self.__action.execActionStart())

	def testExecuteActionCheckRestoreEnvironment(self):
		self.__action.setActionStart("")
		self.__action.setActionStop("rm -f /tmp/fail2ban.test")
		self.__action.setActionBan("rm /tmp/fail2ban.test")
		self.__action.setActionCheck("[ -e /tmp/fail2ban.test ]")
		self.assertFalse(self.__action.execActionBan(None))
		self.assertTrue(self._is_logged('Unable to restore environment'))

	def testExecuteActionChangeCtags(self):
		self.__action.setCInfo("ROST","192.0.2.0")
		self.assertEqual(self.__action.getCInfo("ROST"),"192.0.2.0")
		self.__action.delCInfo("ROST")
		self.assertRaises(KeyError, self.__action.getCInfo, "ROST")

	def testExecuteActionUnbanAinfo(self):
		aInfo = {
			'ABC': "123",
		}
		self.__action.setActionBan("touch /tmp/fail2ban.test.123")
		self.__action.setActionUnban("rm /tmp/fail2ban.test.<ABC>")
		self.assertTrue(self.__action.execActionBan(None))
		self.assertTrue(self.__action.execActionUnban(aInfo))

	def testExecuteActionStartEmpty(self):
		self.__action.setActionStart("")
		self.assertTrue(self.__action.execActionStart())
		self.assertTrue(self._is_logged('Nothing to do'))

	def testExecuteIncorrectCmd(self):
		Action.executeCmd('/bin/ls >/dev/null\nbogusXXX now 2>/dev/null')
		self.assertTrue(self._is_logged('HINT on 127: "Command not found"'))

	def testExecuteTimeout(self):
		stime = time.time()
		Action.executeCmd('sleep 60', timeout=2) # Should take a minute
		self.assertAlmostEqual(time.time() - stime, 2, places=0)
		self.assertTrue(self._is_logged('sleep 60 -- timed out after 2 seconds'))
		self.assertTrue(self._is_logged('sleep 60 -- killed with SIGTERM'))

	def testCaptureStdOutErr(self):
		Action.executeCmd('echo "How now brown cow"')
		self.assertTrue(self._is_logged("'How now brown cow\\n'"))
		Action.executeCmd(
			'echo "The rain in Spain stays mainly in the plain" 1>&2')
		self.assertTrue(self._is_logged(
			"'The rain in Spain stays mainly in the plain\\n'"))
