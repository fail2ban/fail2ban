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

from ..server.action import CommandAction, CallingMap, substituteRecursiveTags
from ..server.actions import OrderedDict
from ..server.utils import Utils

from .utils import LogCaptureTestCase
from .utils import pid_exists

class CommandActionTest(LogCaptureTestCase):

	def setUp(self):
		"""Call before every test case."""
		LogCaptureTestCase.setUp(self)
		self.__action = CommandAction(None, "Test")
		# prevent execute stop if start fails (or event not started at all):
		self.__action_started = False
		orgstart = self.__action.start
		def _action_start():
			self.__action_started = True
			return orgstart()
		self.__action.start = _action_start

	def tearDown(self):
		"""Call after every test case."""
		if self.__action_started:
			self.__action.stop()
		LogCaptureTestCase.tearDown(self)

	def testSubstituteRecursiveTags(self):
		aInfo = {
			'HOST': "192.0.2.0",
			'ABC': "123 <HOST>",
			'xyz': "890 <ABC>",
		}
		# Recursion is bad
		self.assertRaises(ValueError,
			lambda: substituteRecursiveTags({'A': '<A>'}))
		self.assertRaises(ValueError,
			lambda: substituteRecursiveTags({'A': '<B>', 'B': '<A>'}))
		self.assertRaises(ValueError,
			lambda: substituteRecursiveTags({'A': '<B>', 'B': '<C>', 'C': '<A>'}))
		# Unresolveable substition
		self.assertRaises(ValueError,
			lambda: substituteRecursiveTags({'A': 'to=<B> fromip=<IP>', 'C': '<B>', 'B': '<C>', 'D': ''}))
		self.assertRaises(ValueError,
			lambda: substituteRecursiveTags({'failregex': 'to=<honeypot> fromip=<IP>', 'sweet': '<honeypot>', 'honeypot': '<sweet>', 'ignoreregex': ''}))
		# We need here an ordered, because the sequence of iteration is very important for this test
		if OrderedDict:
			# No cyclic recursion, just multiple replacement of tag <T>, should be successful:
			self.assertEqual(substituteRecursiveTags( OrderedDict(
					(('X', 'x=x<T>'), ('T', '1'), ('Z', '<X> <T> <Y>'), ('Y', 'y=y<T>')))
				), {'X': 'x=x1', 'T': '1', 'Y': 'y=y1', 'Z': 'x=x1 1 y=y1'}
			)
			# No cyclic recursion, just multiple replacement of tag <T> in composite tags, should be successful:
			self.assertEqual(substituteRecursiveTags( OrderedDict(
				  (('X', 'x=x<T> <Z> <<R1>> <<R2>>'), ('R1', 'Z'), ('R2', 'Y'), ('T', '1'), ('Z', '<T> <Y>'), ('Y', 'y=y<T>')))
				), {'X': 'x=x1 1 y=y1 1 y=y1 y=y1', 'R1': 'Z', 'R2': 'Y', 'T': '1', 'Z': '1 y=y1', 'Y': 'y=y1'}
			)
			# No cyclic recursion, just multiple replacement of same tags, should be successful:
			self.assertEqual(substituteRecursiveTags( OrderedDict((
					('actionstart', 'ipset create <ipmset> hash:ip timeout <bantime> family <ipsetfamily>\n<iptables> -I <chain> <actiontype>'),
					('ipmset', 'f2b-<name>'),
					('name', 'any'),
					('bantime', '600'),
					('ipsetfamily', 'inet'),
					('iptables', 'iptables <lockingopt>'),
					('lockingopt', '-w'),
					('chain', 'INPUT'),
					('actiontype', '<multiport>'),
					('multiport', '-p <protocol> -m multiport --dports <port> -m set --match-set <ipmset> src -j <blocktype>'),
					('protocol', 'tcp'),
					('port', 'ssh'),
					('blocktype', 'REJECT',),
				))
				), OrderedDict((
					('actionstart', 'ipset create f2b-any hash:ip timeout 600 family inet\niptables -w -I INPUT -p tcp -m multiport --dports ssh -m set --match-set f2b-any src -j REJECT'),
					('ipmset', 'f2b-any'),
					('name', 'any'),
					('bantime', '600'),
					('ipsetfamily', 'inet'),
					('iptables', 'iptables -w'),
					('lockingopt', '-w'),
					('chain', 'INPUT'),
					('actiontype', '-p tcp -m multiport --dports ssh -m set --match-set f2b-any src -j REJECT'),
					('multiport', '-p tcp -m multiport --dports ssh -m set --match-set f2b-any src -j REJECT'),
					('protocol', 'tcp'),
					('port', 'ssh'),
					('blocktype', 'REJECT')
				))
			)
			# Cyclic recursion by composite tag creation, tags "create" another tag, that closes cycle:
			self.assertRaises(ValueError, lambda: substituteRecursiveTags( OrderedDict((
					('A', '<<B><C>>'),
					('B', 'D'), ('C', 'E'),
					('DE', 'cycle <A>'),
			)) ))
			self.assertRaises(ValueError, lambda: substituteRecursiveTags( OrderedDict((
					('DE', 'cycle <A>'),
					('A', '<<B><C>>'),
					('B', 'D'), ('C', 'E'),
			)) ))
			
		# missing tags are ok
		self.assertEqual(substituteRecursiveTags({'A': '<C>'}), {'A': '<C>'})
		self.assertEqual(substituteRecursiveTags({'A': '<C> <D> <X>','X':'fun'}), {'A': '<C> <D> fun', 'X':'fun'})
		self.assertEqual(substituteRecursiveTags({'A': '<C> <B>', 'B': 'cool'}), {'A': '<C> cool', 'B': 'cool'})
		# Escaped tags should be ignored
		self.assertEqual(substituteRecursiveTags({'A': '<matches> <B>', 'B': 'cool'}), {'A': '<matches> cool', 'B': 'cool'})
		# Multiple stuff on same line is ok
		self.assertEqual(substituteRecursiveTags({'failregex': 'to=<honeypot> fromip=<IP> evilperson=<honeypot>', 'honeypot': 'pokie', 'ignoreregex': ''}),
								{ 'failregex': "to=pokie fromip=<IP> evilperson=pokie",
									'honeypot': 'pokie',
									'ignoreregex': '',
								})
		# rest is just cool
		self.assertEqual(substituteRecursiveTags(aInfo),
								{ 'HOST': "192.0.2.0",
									'ABC': '123 192.0.2.0',
									'xyz': '890 123 192.0.2.0',
								})
		# obscure embedded case
		self.assertEqual(substituteRecursiveTags({'A': '<<PREF>HOST>', 'PREF': 'IPV4'}),
						 {'A': '<IPV4HOST>', 'PREF': 'IPV4'})
		self.assertEqual(substituteRecursiveTags({'A': '<<PREF>HOST>', 'PREF': 'IPV4', 'IPV4HOST': '1.2.3.4'}),
						 {'A': '1.2.3.4', 'PREF': 'IPV4', 'IPV4HOST': '1.2.3.4'})
		# more embedded within a string and two interpolations
		self.assertEqual(substituteRecursiveTags({'A': 'A <IP<PREF>HOST> B IP<PREF> C', 'PREF': 'V4', 'IPV4HOST': '1.2.3.4'}),
						 {'A': 'A 1.2.3.4 B IPV4 C', 'PREF': 'V4', 'IPV4HOST': '1.2.3.4'})

	def testSubstRec_DontTouchUnusedCallable(self):
		cm = CallingMap({
			'A':0,
			'B':lambda self: '<A><A>',
			'C':'',
			'D':''
		})
		#
		# should raise no exceptions:
		substituteRecursiveTags(cm)
		# add exception tag:
		cm['C'] = lambda self,i=0: 5 // int(self['A']) # raise error by access
		# test direct get of callable (should raise an error):
		self.assertRaises(ZeroDivisionError, lambda: cm['C'])
		# should raise no exceptions (tag "C" still unused):
		substituteRecursiveTags(cm)
		# add reference to "broken" tag:
		cm['D'] = 'test=<C>'
		# should raise an exception (BOOM by replacement of tag "D" recursive):
		self.assertRaises(ZeroDivisionError, lambda: substituteRecursiveTags(cm))
		#
		# should raise no exceptions:
		self.assertEqual(self.__action.replaceTag('test=<A>', cm), "test=0")
		# **Important**: recursive replacement of dynamic data from calling map should be prohibited,
		# otherwise may be vulnerable on foreign user-input:
		self.assertEqual(self.__action.replaceTag('test=<A>--<B>--<A>', cm), "test=0--<A><A>--0")
		# should raise an exception (BOOM by replacement of tag "C"):
		self.assertRaises(ZeroDivisionError, lambda: self.__action.replaceTag('test=<C>', cm))
		# should raise no exceptions (replaces tag "D" only):
		self.assertEqual(self.__action.replaceTag('<D>', cm), "test=<C>")

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
				CallingMap(matches=lambda self: str(10))),
			"09 10 11")

	def testReplaceNoTag(self):
		# As tag not present, therefore callable should not be called
		# Will raise ValueError if it is
		self.assertEqual(
			self.__action.replaceTag("abc",
				CallingMap(matches=lambda self: int("a"))), "abc")

	def testReplaceTagSelfRecursion(self):
		setattr(self.__action, 'a', "<a")
		setattr(self.__action, 'b', "c>")
		setattr(self.__action, 'b?family=inet6', "b>")
		setattr(self.__action, 'ac', "<a><b>")
		setattr(self.__action, 'ab', "<ac>")
		setattr(self.__action, 'x?family=inet6', "")
		# produce self-referencing properties except:
		self.assertRaisesRegexp(ValueError, r"properties contain self referencing definitions",
			lambda: self.__action.replaceTag("<a><b>", 
				self.__action._properties, conditional="family=inet4")
		)
		# remore self-referencing in props:
		delattr(self.__action, 'ac')
		# produce self-referencing query except:
		self.assertRaisesRegexp(ValueError, r"possible self referencing definitions in query",
			lambda: self.__action.replaceTag("<x<x<x<x<x<x<x<x<x<x<x<x<x<x<x<x<x<x<x<x<x>>>>>>>>>>>>>>>>>>>>>", 
				self.__action._properties, conditional="family=inet6")
		)

	def testReplaceTagConditionalCached(self):
		setattr(self.__action, 'abc', "123")
		setattr(self.__action, 'abc?family=inet4', "345")
		setattr(self.__action, 'abc?family=inet6', "567")
		setattr(self.__action, 'xyz', "890-<abc>")
		setattr(self.__action, 'banaction', "Text <xyz> text <abc>")
		# test replacement in sub tags and direct, conditional, cached:
		cache = self.__action._substCache
		for i in range(2):
			self.assertEqual(
				self.__action.replaceTag("<banaction> '<abc>'", self.__action._properties, 
					conditional="", cache=cache),
				"Text 890-123 text 123 '123'")
			self.assertEqual(
				self.__action.replaceTag("<banaction> '<abc>'", self.__action._properties, 
					conditional="family=inet4", cache=cache),
				"Text 890-345 text 345 '345'")
			self.assertEqual(
				self.__action.replaceTag("<banaction> '<abc>'", self.__action._properties, 
					conditional="family=inet6", cache=cache),
				"Text 890-567 text 567 '567'")
		self.assertTrue(len(cache) >= 3)
		# set one parameter - internal properties and cache should be reseted:
		setattr(self.__action, 'xyz', "000-<abc>")
		self.assertEqual(len(cache), 0)
		# test againg, should have 000 instead of 890:
		for i in range(2):
			self.assertEqual(
				self.__action.replaceTag("<banaction> '<abc>'", self.__action._properties, 
					conditional="", cache=cache),
				"Text 000-123 text 123 '123'")
			self.assertEqual(
				self.__action.replaceTag("<banaction> '<abc>'", self.__action._properties, 
					conditional="family=inet4", cache=cache),
				"Text 000-345 text 345 '345'")
			self.assertEqual(
				self.__action.replaceTag("<banaction> '<abc>'", self.__action._properties, 
					conditional="family=inet6", cache=cache),
				"Text 000-567 text 567 '567'")
		self.assertTrue(len(cache) >= 3)


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

	def testExecuteActionCheckRepairEnvironment(self):
		self.__action.actionstart = ""
		self.__action.actionstop = ""
		self.__action.actionban = "rm /tmp/fail2ban.test"
		self.__action.actioncheck = "[ -e /tmp/fail2ban.test ]"
		self.__action.actionrepair = "echo 'repair ...'; touch /tmp/fail2ban.test"
		# 1st time with success repair:
		self.__action.ban({'ip': None})
		self.assertLogged("Invariant check failed. Trying", "echo 'repair ...'", all=True)
		self.pruneLog()
		# 2nd time failed (not really repaired):
		self.__action.actionrepair = "echo 'repair ...'"
		self.assertRaises(RuntimeError, self.__action.ban, {'ip': None})
		self.assertLogged(
			"Invariant check failed. Trying", 
			"echo 'repair ...'", 
			"Unable to restore environment", all=True)

	def testExecuteActionChangeCtags(self):
		self.assertRaises(AttributeError, getattr, self.__action, "ROST")
		self.__action.ROST = "192.0.2.0"
		self.assertEqual(self.__action.ROST,"192.0.2.0")

	def testExecuteActionUnbanAinfo(self):
		aInfo = CallingMap({
			'ABC': "123",
			'ip': '192.0.2.1',
			'F-*': lambda self: {
		  	'fid': 111,
		  	'fport': 222,
				'user': "tester"
			}
		})
		self.__action.actionban = "touch /tmp/fail2ban.test.123; echo 'failure <F-ID> of <F-USER> -<F-TEST>- from <ip>:<F-PORT>'"
		self.__action.actionunban = "rm /tmp/fail2ban.test.<ABC>; echo 'user <F-USER> unbanned'"
		self.__action.ban(aInfo)
		self.__action.unban(aInfo)
		self.assertLogged(
			" -- stdout: 'failure 111 of tester -- from 192.0.2.1:222'",
			" -- stdout: 'user tester unbanned'",
			all=True
		)

	def testExecuteActionStartEmpty(self):
		self.__action.actionstart = ""
		self.__action.start()
		self.assertTrue(self.__action.executeCmd(""))
		self.assertLogged('Nothing to do')
		self.pruneLog()
		self.assertTrue(self.__action._processCmd(""))
		self.assertLogged('Nothing to do')
		self.pruneLog()

	def testExecuteWithVars(self):
		self.assertTrue(self.__action.executeCmd(
			r'''printf %b "foreign input:\n'''
			r''' -- $f2bV_A --\n'''
			r''' -- $f2bV_B --\n'''
			r''' -- $(echo -n $f2bV_C) --''' # echo just replaces \n to test it as single line
			r'''"''', 
			varsDict={
			'f2bV_A': 'I\'m a hacker; && $(echo $f2bV_B)', 
			'f2bV_B': 'I"m very bad hacker', 
			'f2bV_C': '`Very | very\n$(bad & worst hacker)`'
		}))
		self.assertLogged(r"""foreign input:""",
			' -- I\'m a hacker; && $(echo $f2bV_B) --',
			' -- I"m very bad hacker --',
			' -- `Very | very $(bad & worst hacker)` --', all=True)

	def testExecuteReplaceEscapeWithVars(self):
		self.__action.actionban = 'echo "** ban <ip>, reason: <reason> ...\\n<matches>"'
		self.__action.actionunban = 'echo "** unban <ip>"'
		self.__action.actionstop = 'echo "** stop monitoring"'
		matches = [
			'<actionunban>',
			'" Hooray! #',
			'`I\'m cool script kiddy',
			'`I`m very cool > /here-is-the-path/to/bin/.x-attempt.sh',
			'<actionstop>',
		]
		aInfo = {
			'ip': '192.0.2.1',
			'reason': 'hacking attempt ( he thought he knows how f2b internally works ;)',
			'matches': '\n'.join(matches)
		}
		self.pruneLog()
		self.__action.ban(aInfo)
		self.assertLogged(
			'** ban %s' % aInfo['ip'], aInfo['reason'], *matches, all=True)
		self.assertNotLogged(
			'** unban %s' % aInfo['ip'], '** stop monitoring', all=True)
		self.pruneLog()
		self.__action.unban(aInfo)
		self.__action.stop()
		self.assertLogged(
			'** unban %s' % aInfo['ip'], '** stop monitoring', all=True)

	def testExecuteIncorrectCmd(self):
		CommandAction.executeCmd('/bin/ls >/dev/null\nbogusXXX now 2>/dev/null')
		self.assertLogged('HINT on 127: "Command not found"')

	def testExecuteTimeout(self):
		stime = time.time()
		timeout = 1 if not unittest.F2B.fast else 0.01
		# Should take a 30 seconds (so timeout will occur)
		self.assertFalse(CommandAction.executeCmd('sleep 30', timeout=timeout))
		# give a test still 1 second, because system could be too busy
		self.assertTrue(time.time() >= stime + timeout and time.time() <= stime + timeout + 1)
		self.assertLogged('sleep 30', ' -- timed out after', all=True)
		self.assertLogged(' -- killed with SIGTERM', 
		                  ' -- killed with SIGKILL')

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
				getnastypid() is not None
				or time.time() - stime > 5
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
		self.assertLogged('my pid ', 'Resource temporarily unavailable')
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
		self.assertLogged('my pid ', 'Resource temporarily unavailable')
		self.assertLogged(' -- timed out')
		self.assertLogged(' -- killed with SIGTERM', 
		                  ' -- killed with SIGKILL')
		os.unlink(tmpFilename)
		os.unlink(tmpFilename + '.pid')


	def testCaptureStdOutErr(self):
		CommandAction.executeCmd('echo "How now brown cow"')
		self.assertLogged("stdout: 'How now brown cow'\n")
		CommandAction.executeCmd(
			'echo "The rain in Spain stays mainly in the plain" 1>&2')
		self.assertLogged(
			"stderr: 'The rain in Spain stays mainly in the plain'\n")

	def testCallingMap(self):
		mymap = CallingMap(callme=lambda self: str(10), error=lambda self: int('a'),
			dontcallme= "string", number=17)

		# Should work fine
		self.assertEqual(
			"%(callme)s okay %(dontcallme)s %(number)i" % mymap,
			"10 okay string 17")
		# Error will now trip, demonstrating delayed call
		self.assertRaises(ValueError, lambda x: "%(error)i" % x, mymap)

	def testCallingMapModify(self):
		m = CallingMap({
			'a': lambda self: 2 + 3,
			'b': lambda self: self['a'] + 6,
			'c': 'test',
		})
		# test reset (without modifications):
		m.reset()
		# do modifications:
		m['a'] = 4
		del m['c']
		# test set and delete:
		self.assertEqual(len(m), 2)
		self.assertNotIn('c', m)
		self.assertEqual((m['a'], m['b']), (4, 10))
		# reset to original and test again:
		m.reset()
		s = repr(m)
		self.assertEqual(len(m), 3)
		self.assertIn('c', m)
		self.assertEqual((m['a'], m['b'], m['c']), (5, 11, 'test'))

	def testCallingMapRep(self):
		m = CallingMap({
			'a': lambda self: 2 + 3,
			'b': lambda self: self['a'] + 6,
			'c': ''
		})
		s = repr(m)
		self.assertIn("'a': 5", s)
		self.assertIn("'b': 11", s)
		self.assertIn("'c': ''", s)
		
		m['c'] = lambda self: self['xxx'] + 7; # unresolvable
		s = repr(m)
		self.assertIn("'a': 5", s)
		self.assertIn("'b': 11", s)
		self.assertIn("'c': ", s) # presents as callable
		self.assertNotIn("'c': ''", s) # but not empty
