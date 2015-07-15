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

import os
import tempfile
import time
import unittest

from ..server.action import CommandAction, CallingMap
from ..server.utils import Utils

from .utils import LogCaptureTestCase
from .utils import pid_exists

class CommandActionTest(LogCaptureTestCase):

	def setUp(self):
		"""Call before every test case."""
		self.__action = CommandAction(None, "Test")
		LogCaptureTestCase.setUp(self)

	def tearDown(self):
		"""Call after every test case."""
		LogCaptureTestCase.tearDown(self)
		self.__action.stop()

	def testSubstituteRecursiveTags(self):
		aInfo = {
			'HOST': "192.0.2.0",
			'ABC': "123 <HOST>",
			'xyz': "890 <ABC>",
		}
		# Recursion is bad
		self.assertFalse(CommandAction.substituteRecursiveTags({'A': '<A>'}))
		self.assertFalse(CommandAction.substituteRecursiveTags({'A': '<B>', 'B': '<A>'}))
		self.assertFalse(CommandAction.substituteRecursiveTags({'A': '<B>', 'B': '<C>', 'C': '<A>'}))
		# Unresolveable substition
		self.assertFalse(CommandAction.substituteRecursiveTags({'A': 'to=<B> fromip=<IP>', 'C': '<B>', 'B': '<C>', 'D': ''}))
		self.assertFalse(CommandAction.substituteRecursiveTags({'failregex': 'to=<honeypot> fromip=<IP>', 'sweet': '<honeypot>', 'honeypot': '<sweet>', 'ignoreregex': ''}))
		# missing tags are ok
		self.assertEqual(CommandAction.substituteRecursiveTags({'A': '<C>'}), {'A': '<C>'})
		self.assertEqual(CommandAction.substituteRecursiveTags({'A': '<C> <D> <X>','X':'fun'}), {'A': '<C> <D> fun', 'X':'fun'})
		self.assertEqual(CommandAction.substituteRecursiveTags({'A': '<C> <B>', 'B': 'cool'}), {'A': '<C> cool', 'B': 'cool'})
		# Escaped tags should be ignored
		self.assertEqual(CommandAction.substituteRecursiveTags({'A': '<matches> <B>', 'B': 'cool'}), {'A': '<matches> cool', 'B': 'cool'})
		# Multiple stuff on same line is ok
		self.assertEqual(CommandAction.substituteRecursiveTags({'failregex': 'to=<honeypot> fromip=<IP> evilperson=<honeypot>', 'honeypot': 'pokie', 'ignoreregex': ''}),
								{ 'failregex': "to=pokie fromip=<IP> evilperson=pokie",
									'honeypot': 'pokie',
									'ignoreregex': '',
								})
		# rest is just cool
		self.assertEqual(CommandAction.substituteRecursiveTags(aInfo),
								{ 'HOST': "192.0.2.0",
									'ABC': '123 192.0.2.0',
									'xyz': '890 123 192.0.2.0',
								})
		# obscure embedded case
		self.assertEqual(CommandAction.substituteRecursiveTags({'A': '<<PREF>HOST>', 'PREF': 'IPV4'}),
						 {'A': '<IPV4HOST>', 'PREF': 'IPV4'})
		self.assertEqual(CommandAction.substituteRecursiveTags({'A': '<<PREF>HOST>', 'PREF': 'IPV4', 'IPV4HOST': '1.2.3.4'}),
						 {'A': '1.2.3.4', 'PREF': 'IPV4', 'IPV4HOST': '1.2.3.4'})
		# more embedded within a string and two interpolations
		self.assertEqual(CommandAction.substituteRecursiveTags({'A': 'A <IP<PREF>HOST> B IP<PREF> C', 'PREF': 'V4', 'IPV4HOST': '1.2.3.4'}),
						 {'A': 'A 1.2.3.4 B IPV4 C', 'PREF': 'V4', 'IPV4HOST': '1.2.3.4'})

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

		# Recursive
		aInfo["ABC"] = "<xyz>"
		self.assertEqual(
			self.__action.replaceTag("Text <xyz> text <ABC> ABC", aInfo),
			"Text 890 text 890 ABC")

		# Callable
		self.assertEqual(
			self.__action.replaceTag("09 <matches> 11",
				CallingMap(matches=lambda: str(10))),
			"09 10 11")

		# As tag not present, therefore callable should not be called
		# Will raise ValueError if it is
		self.assertEqual(
			self.__action.replaceTag("abc",
				CallingMap(matches=lambda: int("a"))), "abc")

	def testExecuteActionBan(self):
		self.__action.actionstart = "touch /tmp/fail2ban.test"
		self.assertEqual(self.__action.actionstart, "touch /tmp/fail2ban.test")
		self.__action.actionstop = "rm -f /tmp/fail2ban.test"
		self.assertEqual(self.__action.actionstop, 'rm -f /tmp/fail2ban.test')
		self.__action.actionban = "echo -n"
		self.assertEqual(self.__action.actionban, 'echo -n')
		self.__action.actioncheck = "[ -e /tmp/fail2ban.test ]"
		self.assertEqual(self.__action.actioncheck, '[ -e /tmp/fail2ban.test ]')
		self.__action.actionunban = "true"
		self.assertEqual(self.__action.actionunban, 'true')

		self.assertNotLogged('returned')
		# no action was actually executed yet

		self.__action.ban({'ip': None})
		self.assertLogged('Invariant check failed')
		self.assertLogged('returned successfully')

	def testExecuteActionEmptyUnban(self):
		self.__action.actionunban = ""
		self.__action.unban({})
		self.assertLogged('Nothing to do')

	def testExecuteActionStartCtags(self):
		self.__action.HOST = "192.0.2.0"
		self.__action.actionstart = "touch /tmp/fail2ban.test.<HOST>"
		self.__action.actionstop = "rm -f /tmp/fail2ban.test.<HOST>"
		self.__action.actioncheck = "[ -e /tmp/fail2ban.test.192.0.2.0 ]"
		self.__action.start()

	def testExecuteActionCheckRestoreEnvironment(self):
		self.__action.actionstart = ""
		self.__action.actionstop = "rm -f /tmp/fail2ban.test"
		self.__action.actionban = "rm /tmp/fail2ban.test"
		self.__action.actioncheck = "[ -e /tmp/fail2ban.test ]"
		self.assertRaises(RuntimeError, self.__action.ban, {'ip': None})
		self.assertLogged('Unable to restore environment')

	def testExecuteActionChangeCtags(self):
		self.assertRaises(AttributeError, getattr, self.__action, "ROST")
		self.__action.ROST = "192.0.2.0"
		self.assertEqual(self.__action.ROST,"192.0.2.0")

	def testExecuteActionUnbanAinfo(self):
		aInfo = {
			'ABC': "123",
		}
		self.__action.actionban = "touch /tmp/fail2ban.test.123"
		self.__action.actionunban = "rm /tmp/fail2ban.test.<ABC>"
		self.__action.ban(aInfo)
		self.__action.unban(aInfo)

	def testExecuteActionStartEmpty(self):
		self.__action.actionstart = ""
		self.__action.start()
		self.assertLogged('Nothing to do')

	def testExecuteIncorrectCmd(self):
		CommandAction.executeCmd('/bin/ls >/dev/null\nbogusXXX now 2>/dev/null')
		self.assertLogged('HINT on 127: "Command not found"')

	def testExecuteTimeout(self):
		unittest.F2B.SkipIfFast()
		stime = time.time()
		# Should take a minute
		self.assertFalse(CommandAction.executeCmd('sleep 30', timeout=1))
		# give a test still 1 second, because system could be too busy
		self.assertTrue(time.time() >= stime + 1 and time.time() <= stime + 2)
		self.assertLogged(
			'sleep 30 -- timed out after 1 seconds',
			'sleep 30 -- timed out after 2 seconds'
		)
		self.assertLogged('sleep 30 -- killed with SIGTERM')

	def testExecuteTimeoutWithNastyChildren(self):
		# temporary file for a nasty kid shell script
		tmpFilename = tempfile.mktemp(".sh", "fail2ban_")
		# Create a nasty script which would hang there for a while
		with open(tmpFilename, 'w') as f:
			f.write("""#!/bin/bash
		trap : HUP EXIT TERM

		echo "$$" > %s.pid
		echo "my pid $$ . sleeping lo-o-o-ong"
		sleep 30
		""" % tmpFilename)
		stime = 0

		# timeout as long as pid-file was not created, but max 5 seconds
		def getnasty_tout():
			return (
				getnastypid() is None
				and time.time() - stime <= 5
			)

		def getnastypid():
			cpid = None
			if os.path.isfile(tmpFilename + '.pid'):
				with open(tmpFilename + '.pid') as f:
					try:
						cpid = int(f.read())
					except ValueError:
						pass
			return cpid

		# First test if can kill the bastard
		stime = time.time()
		self.assertFalse(CommandAction.executeCmd(
			'bash %s' % tmpFilename, timeout=getnasty_tout))
		# Wait up to 3 seconds, the child got killed
		cpid = getnastypid()
		# Verify that the process itself got killed
		self.assertTrue(Utils.wait_for(lambda: not pid_exists(cpid), 3))  # process should have been killed
		self.assertLogged('my pid ')
		self.assertLogged('timed out')
		self.assertLogged('killed with SIGTERM', 
		                  'killed with SIGKILL')
		os.unlink(tmpFilename + '.pid')

		# A bit evolved case even though, previous test already tests killing children processes
		stime = time.time()
		self.assertFalse(CommandAction.executeCmd(
			'out=`bash %s`; echo ALRIGHT' % tmpFilename, timeout=getnasty_tout))
		# Wait up to 3 seconds, the child got killed
		cpid = getnastypid()
		# Verify that the process itself got killed
		self.assertTrue(Utils.wait_for(lambda: not pid_exists(cpid), 3))
		self.assertLogged('my pid ')
		self.assertLogged('timed out')
		self.assertLogged('killed with SIGTERM', 
		                  'killed with SIGKILL')
		os.unlink(tmpFilename)
		os.unlink(tmpFilename + '.pid')


	def testCaptureStdOutErr(self):
		CommandAction.executeCmd('echo "How now brown cow"')
		self.assertLogged("'How now brown cow\\n'")
		CommandAction.executeCmd(
			'echo "The rain in Spain stays mainly in the plain" 1>&2')
		self.assertLogged(
			"'The rain in Spain stays mainly in the plain\\n'")

	def testCallingMap(self):
		mymap = CallingMap(callme=lambda: str(10), error=lambda: int('a'),
			dontcallme= "string", number=17)

		# Should work fine
		self.assertEqual(
			"%(callme)s okay %(dontcallme)s %(number)i" % mymap,
			"10 okay string 17")
		# Error will now trip, demonstrating delayed call
		self.assertRaises(ValueError, lambda x: "%(error)i" % x, mymap)
