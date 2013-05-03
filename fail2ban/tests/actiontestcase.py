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
		self.assertEquals(Action.substituteRecursiveTags({'A': '<C>'}), {'A': '<C>'})
		self.assertEquals(Action.substituteRecursiveTags({'A': '<C> <D> <X>','X':'fun'}), {'A': '<C> <D> fun', 'X':'fun'})
		self.assertEquals(Action.substituteRecursiveTags({'A': '<C> <B>', 'B': 'cool'}), {'A': '<C> cool', 'B': 'cool'})
		# rest is just cool
		self.assertEquals(Action.substituteRecursiveTags(aInfo),
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
		self.__action.setActionStop("rm -f /tmp/fail2ban.test")
		self.__action.setActionBan("echo -n")
		self.__action.setActionCheck("[ -e /tmp/fail2ban.test ]")

		self.assertFalse(self._is_logged('returned'))
		# no action was actually executed yet

		self.assertTrue(self.__action.execActionBan(None))
		self.assertTrue(self._is_logged('Invariant check failed'))
		self.assertTrue(self._is_logged('returned successfully'))


	def testExecuteIncorrectCmd(self):
		Action.executeCmd('/bin/ls >/dev/null\nbogusXXX now 2>/dev/null')
		self.assertTrue(self._is_logged('HINT on 127: "Command not found"'))

	def testExecuteTimeout(self):
		stime = time.time()
		Action.executeCmd('sleep 60', timeout=2) # Should take a minute
		self.assertAlmostEqual(time.time() - stime, 2.1, places=1)
		self.assertTrue(self._is_logged('sleep 60 timed out after 2 seconds'))
		self.assertTrue(self._is_logged('sleep 60 killed with SIGTERM'))

	def testCaptureStdOutErr(self):
		Action.executeCmd('echo "How now brown cow"')
		self.assertTrue(self._is_logged("'How now brown cow\\n'"))
		Action.executeCmd(
			'echo "The rain in Spain stays mainly in the plain" 1>&2')
		self.assertTrue(self._is_logged(
			"'The rain in Spain stays mainly in the plain\\n'"))
