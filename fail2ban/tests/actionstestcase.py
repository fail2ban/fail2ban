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

from ..server.ticket import FailTicket
from ..server.utils import Utils
from .dummyjail import DummyJail
from .utils import LogCaptureTestCase, with_alt_time, with_tmpdir, MyTime

TEST_FILES_DIR = os.path.join(os.path.dirname(__file__), "files")


class ExecuteActions(LogCaptureTestCase):

	def setUp(self):
		"""Call before every test case."""
		super(ExecuteActions, self).setUp()
		self.__jail = DummyJail()
		self.__actions = self.__jail.actions

	def tearDown(self):
		super(ExecuteActions, self).tearDown()

	def defaultAction(self, o={}):
		self.__actions.add('ip')
		act = self.__actions['ip']
		act.actionstart = 'echo ip start'+o.get('start', '')
		act.actionban = 'echo ip ban <ip>'+o.get('ban', '')
		act.actionunban = 'echo ip unban <ip>'+o.get('unban', '')
		act.actioncheck = 'echo ip check'+o.get('check', '')
		act.actionflush = 'echo ip flush'+o.get('flush', '')
		act.actionstop = 'echo ip stop'+o.get('stop', '')
		return act

	def testActionsAddDuplicateName(self):
		self.__actions.add('test')
		self.assertRaises(ValueError, self.__actions.add, 'test')

	def testActionsManipulation(self):
		self.__actions.add('test')
		self.assertTrue(self.__actions['test'])
		self.assertIn('test', self.__actions)
		self.assertNotIn('nonexistant action', self.__actions)
		self.__actions.add('test1')
		del self.__actions['test']
		del self.__actions['test1']
		self.assertNotIn('test', self.__actions)
		self.assertEqual(len(self.__actions), 0)

		self.__actions.setBanTime(127)
		self.assertEqual(self.__actions.getBanTime(),127)
		self.assertRaises(ValueError, self.__actions.removeBannedIP, '127.0.0.1')

	def testAddBannedIP(self):
		self.assertEqual(self.__actions.addBannedIP('192.0.2.1'), 1)
		self.assertLogged('Ban 192.0.2.1')
		self.pruneLog()
		self.assertEqual(self.__actions.addBannedIP(['192.0.2.1', '192.0.2.2', '192.0.2.3']), 2)
		self.assertLogged('192.0.2.1 already banned')
		self.assertNotLogged('Ban 192.0.2.1')
		self.assertLogged('Ban 192.0.2.2')
		self.assertLogged('Ban 192.0.2.3')

	def testActionsOutput(self):
		self.defaultAction()
		self.__actions.start()
		self.assertLogged("stdout: %r" % 'ip start', wait=True)
		self.__actions.stop()
		self.__actions.join()
		self.assertLogged("stdout: %r" % 'ip flush', "stdout: %r" % 'ip stop')
		self.assertEqual(self.__actions.status(),[("Currently banned", 0 ),
               ("Total banned", 0 ), ("Banned IP list", [] )])

	def testAddActionPython(self):
		self.__actions.add(
			"Action", os.path.join(TEST_FILES_DIR, "action.d/action.py"),
			{'opt1': 'value'})

		self.assertLogged("TestAction initialised")

		self.__actions.start()
		self.assertTrue( Utils.wait_for(lambda: self._is_logged("TestAction action start"), 3) )

		self.__actions.stop()
		self.__actions.join()
		self.assertLogged("TestAction action stop")

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
		self.assertTrue( Utils.wait_for(lambda: self._is_logged("Failed to start"), 3) )
		self.__actions.stop()
		self.__actions.join()
		self.assertLogged("Failed to stop")

	def testBanActionsAInfo(self):
		# Action which deletes IP address from aInfo
		self.__actions.add(
			"action1",
			os.path.join(TEST_FILES_DIR, "action.d/action_modifyainfo.py"),
			{})
		self.__actions.add(
			"action2",
			os.path.join(TEST_FILES_DIR, "action.d/action_modifyainfo.py"),
			{})
		self.__jail.putFailTicket(FailTicket("1.2.3.4"))
		self.__actions._Actions__checkBan()
		# Will fail if modification of aInfo from first action propagates
		# to second action, as both delete same key
		self.assertNotLogged("Failed to execute ban")
		self.assertLogged("action1 ban deleted aInfo IP")
		self.assertLogged("action2 ban deleted aInfo IP")

		self.__actions._Actions__flushBan()
		# Will fail if modification of aInfo from first action propagates
		# to second action, as both delete same key
		self.assertNotLogged("Failed to execute unban")
		self.assertLogged("action1 unban deleted aInfo IP")
		self.assertLogged("action2 unban deleted aInfo IP")

	@with_alt_time
	def testUnbanOnBusyBanBombing(self):
		# check unban happens in-between of "ban bombing" despite lower precedence,
		# if it is not work, we'll not see "Unbanned 30" (rather "Unbanned 50")
		# because then all the unbans occur earliest at flushing (after stop)

		# each 3rd ban we should see an unban check (and up to 5 tickets gets unbanned):
		self.__actions.banPrecedence = 3
		self.__actions.unbanMaxCount = 5
		self.__actions.setBanTime(100)

		self.__actions.start()

		MyTime.setTime(0); # avoid "expired bantime" (in 0.11)
		i = 0
		while i < 20:
			ip = "192.0.2.%d" % i
			self.__jail.putFailTicket(FailTicket(ip, 0))
			i += 1

		# wait for last ban (all 20 tickets gets banned):
		self.assertLogged(' / 20,', wait=True)

		MyTime.setTime(200); # unban time for 20 tickets reached

		while i < 50:
			ip = "192.0.2.%d" % i
			self.__jail.putFailTicket(FailTicket(ip, 200))
			i += 1

		# wait for last ban (all 50 tickets gets banned):
		self.assertLogged(' / 50,', wait=True)
		self.__actions.stop()
		self.__actions.join()

		self.assertLogged('Unbanned 30, 0 ticket(s)')
		self.assertNotLogged('Unbanned 50, 0 ticket(s)')

	def testActionsConsistencyCheck(self):
		act = self.defaultAction({'check':' <family>', 'flush':' <family>'})
		# flush for inet6 is intentionally "broken" here - test no unhandled except and invariant check:
		act['actionflush?family=inet6'] = act.actionflush + '; exit 1'
		act.actionstart_on_demand = True
		self.__actions.start()
		self.assertNotLogged("stdout: %r" % 'ip start')

		self.assertEqual(self.__actions.addBannedIP('192.0.2.1'), 1)
		self.assertEqual(self.__actions.addBannedIP('2001:db8::1'), 1)
		self.assertLogged('Ban 192.0.2.1', 'Ban 2001:db8::1',
			"stdout: %r" % 'ip start',
			"stdout: %r" % 'ip ban 192.0.2.1',
			"stdout: %r" % 'ip ban 2001:db8::1',
			all=True, wait=True)

		# check should fail (so cause stop/start):
		self.pruneLog('[test-phase 1a] simulate inconsistent irreparable env by unban')
		act['actioncheck?family=inet6'] = act.actioncheck + '; exit 1'
		self.__actions.removeBannedIP('2001:db8::1')
		self.assertLogged('Invariant check failed. Unban is impossible.',
			wait=True)
		self.pruneLog('[test-phase 1b] simulate inconsistent irreparable env by flush')
		self.__actions._Actions__flushBan()
		self.assertLogged(
			"stdout: %r" % 'ip flush inet4',
			"stdout: %r" % 'ip flush inet6',
			'Failed to flush bans',
			'No flush occurred, do consistency check',
			'Invariant check failed. Trying to restore a sane environment',
			"stdout: %r" % 'ip stop',  # same for both families
			'Failed to flush bans',
			all=True, wait=True)

		# check succeeds:
		self.pruneLog('[test-phase 2] consistent env')
		act['actioncheck?family=inet6'] = act.actioncheck
		self.assertEqual(self.__actions.addBannedIP('2001:db8::1'), 1)
		self.assertLogged('Ban 2001:db8::1',
			"stdout: %r" % 'ip start',   # same for both families
			"stdout: %r" % 'ip ban 2001:db8::1',
			all=True, wait=True)
		self.assertNotLogged("stdout: %r" % 'ip check inet4',
			all=True)

		self.pruneLog('[test-phase 3] failed flush in consistent env')
		self.__actions._Actions__flushBan()
		self.assertLogged('Failed to flush bans',
			'No flush occurred, do consistency check',
			"stdout: %r" % 'ip flush inet6',
			"stdout: %r" % 'ip check inet6',
			all=True, wait=True)
		self.assertNotLogged(
			"stdout: %r" % 'ip flush inet4',
			"stdout: %r" % 'ip stop',
			"stdout: %r" % 'ip start',
			'Unable to restore environment',
			all=True)

		# stop, flush succeeds:
		self.pruneLog('[test-phase end] flush successful')
		act['actionflush?family=inet6'] = act.actionflush
		self.__actions.stop()
		self.__actions.join()
		self.assertLogged(
			"stdout: %r" % 'ip flush inet6',
			"stdout: %r" % 'ip stop',    # same for both families
			'action ip terminated',
			all=True, wait=True)
		# no flush for inet4 (already successfully flushed):
		self.assertNotLogged("ERROR",
			"stdout: %r" % 'ip flush inet4',
			'Unban tickets each individualy',
			all=True)

	def testActionsConsistencyCheckDiffFam(self):
		# same as testActionsConsistencyCheck, but different start/stop commands for both families and repair on unban
		act = self.defaultAction({'start':' <family>', 'check':' <family>', 'flush':' <family>', 'stop':' <family>'})
		# flush for inet6 is intentionally "broken" here - test no unhandled except and invariant check:
		act['actionflush?family=inet6'] = act.actionflush + '; exit 1'
		act.actionstart_on_demand = True
		act.actionrepair_on_unban = True
		self.__actions.start()
		self.assertNotLogged("stdout: %r" % 'ip start')

		self.assertEqual(self.__actions.addBannedIP('192.0.2.1'), 1)
		self.assertEqual(self.__actions.addBannedIP('2001:db8::1'), 1)
		self.assertLogged('Ban 192.0.2.1', 'Ban 2001:db8::1',
			"stdout: %r" % 'ip start inet4',
			"stdout: %r" % 'ip ban 192.0.2.1',
			"stdout: %r" % 'ip start inet6',
			"stdout: %r" % 'ip ban 2001:db8::1',
			all=True, wait=True)

		# check should fail (so cause stop/start):
		act['actioncheck?family=inet6'] = act.actioncheck + '; exit 1'
		self.pruneLog('[test-phase 1a] simulate inconsistent irreparable env by unban')
		self.__actions.removeBannedIP('2001:db8::1')
		self.assertLogged('Invariant check failed. Trying to restore a sane environment',
			"stdout: %r" % 'ip stop inet6',
			all=True, wait=True)
		self.assertNotLogged(
			"stdout: %r" % 'ip start inet6', # start on demand (not on repair)
			"stdout: %r" % 'ip stop inet4',  # family inet4 is not affected
			"stdout: %r" % 'ip start inet4',
			all=True)

		self.pruneLog('[test-phase 1b] simulate inconsistent irreparable env by ban')
		self.assertEqual(self.__actions.addBannedIP('2001:db8::1'), 1)
		self.assertLogged('Invariant check failed. Trying to restore a sane environment',
			"stdout: %r" % 'ip stop inet6',
			"stdout: %r" % 'ip start inet6',
			"stdout: %r" % 'ip check inet6',
			'Unable to restore environment',
			'Failed to execute ban',
			all=True, wait=True)
		self.assertNotLogged(
			"stdout: %r" % 'ip stop inet4',  # family inet4 is not affected
			"stdout: %r" % 'ip start inet4',
			all=True)

		act['actioncheck?family=inet6'] = act.actioncheck
		self.assertEqual(self.__actions.addBannedIP('2001:db8::2'), 1)
		act['actioncheck?family=inet6'] = act.actioncheck + '; exit 1'
		self.pruneLog('[test-phase 1c] simulate inconsistent irreparable env by flush')
		self.__actions._Actions__flushBan()
		self.assertLogged(
			"stdout: %r" % 'ip flush inet4',
			"stdout: %r" % 'ip flush inet6',
			'Failed to flush bans',
			'No flush occurred, do consistency check',
			'Invariant check failed. Trying to restore a sane environment',
			"stdout: %r" % 'ip stop inet6',
			'Failed to flush bans in jail',
			all=True, wait=True)
		# start/stop should be called for inet6 only:
		self.assertNotLogged(
			"stdout: %r" % 'ip stop inet4',
			all=True)

		# check succeeds:
		self.pruneLog('[test-phase 2] consistent env')
		act['actioncheck?family=inet6'] = act.actioncheck
		self.assertEqual(self.__actions.addBannedIP('2001:db8::1'), 1)
		self.assertLogged('Ban 2001:db8::1',
			"stdout: %r" % 'ip start inet6',
			"stdout: %r" % 'ip ban 2001:db8::1',
			all=True, wait=True)
		self.assertNotLogged(
			"stdout: %r" % 'ip check inet4',
			"stdout: %r" % 'ip start inet4',
			all=True)

		self.pruneLog('[test-phase 3] failed flush in consistent env')
		act['actioncheck?family=inet6'] = act.actioncheck
		self.__actions._Actions__flushBan()
		self.assertLogged('Failed to flush bans',
			'No flush occurred, do consistency check',
			"stdout: %r" % 'ip flush inet6',
			"stdout: %r" % 'ip check inet6',
			all=True, wait=True)
		self.assertNotLogged(
			"stdout: %r" % 'ip flush inet4',
			"stdout: %r" % 'ip stop inet4',
			"stdout: %r" % 'ip start inet4',
			"stdout: %r" % 'ip stop inet6',
			"stdout: %r" % 'ip start inet6',
			all=True)

		# stop, flush succeeds:
		self.pruneLog('[test-phase end] flush successful')
		act['actionflush?family=inet6'] = act.actionflush
		self.__actions.stop()
		self.__actions.join()
		self.assertLogged(
			"stdout: %r" % 'ip flush inet6',
			"stdout: %r" % 'ip stop inet4',
			"stdout: %r" % 'ip stop inet6',
			'action ip terminated',
			all=True, wait=True)
		# no flush for inet4 (already successfully flushed):
		self.assertNotLogged("ERROR",
			"stdout: %r" % 'ip flush inet4',
			'Unban tickets each individualy',
			all=True)

	@with_alt_time
	@with_tmpdir
	def testActionsRebanBrokenAfterRepair(self, tmp):
		act = self.defaultAction({
			'start':' <family>; touch "<FN>"',
			'check':' <family>; test -f "<FN>"',
			'flush':' <family>; echo -n "" > "<FN>"',
			'stop': ' <family>; rm -f "<FN>"',
			'ban':  ' <family>; echo "<ip> <family>" >> "<FN>"',
		})
		act['FN'] = tmp+'/<family>'
		act.actionstart_on_demand = True
		act.actionrepair = 'echo ip repair <family>; touch "<FN>"'
		act.actionreban = 'echo ip reban <ip> <family>; echo "<ip> <family> -- rebanned" >> "<FN>"'
		self.pruneLog('[test-phase 0] initial ban')
		self.assertEqual(self.__actions.addBannedIP(['192.0.2.1', '2001:db8::1']), 2)
		self.assertLogged('Ban 192.0.2.1', 'Ban 2001:db8::1',
			"stdout: %r" % 'ip start inet4',
			"stdout: %r" % 'ip ban 192.0.2.1 inet4',
			"stdout: %r" % 'ip start inet6',
			"stdout: %r" % 'ip ban 2001:db8::1 inet6',
			all=True)

		self.pruneLog('[test-phase 1] check ban')
		self.dumpFile(tmp+'/inet4')
		self.assertLogged('192.0.2.1 inet4')
		self.assertNotLogged('2001:db8::1 inet6')
		self.pruneLog()
		self.dumpFile(tmp+'/inet6')
		self.assertLogged('2001:db8::1 inet6')
		self.assertNotLogged('192.0.2.1 inet4')

		# simulate 3 seconds past:
		MyTime.setTime(MyTime.time() + 4)
		# already banned produces events:
		self.pruneLog('[test-phase 2] check already banned')
		self.assertEqual(self.__actions.addBannedIP(['192.0.2.1', '2001:db8::1', '2001:db8::2']), 1)
		self.assertLogged(
			'192.0.2.1 already banned', '2001:db8::1 already banned', 'Ban 2001:db8::2',
			"stdout: %r" % 'ip check inet4', # both checks occurred
			"stdout: %r" % 'ip check inet6',
			all=True)
		self.dumpFile(tmp+'/inet4')
		self.dumpFile(tmp+'/inet6')
		# no reban should occur:
		self.assertNotLogged('Reban 192.0.2.1', 'Reban 2001:db8::1',
			"stdout: %r" % 'ip ban 192.0.2.1 inet4',
			"stdout: %r" % 'ip reban 192.0.2.1 inet4',
			"stdout: %r" % 'ip ban 2001:db8::1 inet6',
			"stdout: %r" % 'ip reban 2001:db8::1 inet6',
			'192.0.2.1 inet4 -- repaired',
			'2001:db8::1 inet6 -- repaired',
			all=True)

		# simulate 3 seconds past:
		MyTime.setTime(MyTime.time() + 4)
		# break env (remove both files, so check would fail):
		os.remove(tmp+'/inet4')
		os.remove(tmp+'/inet6')
		# test again already banned (it shall cause reban now):
		self.pruneLog('[test-phase 3a] check reban after sane env repaired')
		self.assertEqual(self.__actions.addBannedIP(['192.0.2.1', '2001:db8::1']), 2)
		self.assertLogged(
			"Invariant check failed. Trying to restore a sane environment",
			"stdout: %r" % 'ip repair inet4', # both repairs occurred
			"stdout: %r" % 'ip repair inet6',
			"Reban 192.0.2.1, action 'ip'", "Reban 2001:db8::1, action 'ip'", # both rebans also
			"stdout: %r" % 'ip reban 192.0.2.1 inet4',
			"stdout: %r" % 'ip reban 2001:db8::1 inet6',
			all=True)

		# now last IP (2001:db8::2) - no repair, but still old epoch of ticket, so it gets rebanned:
		self.pruneLog('[test-phase 3a] check reban by epoch mismatch (without repair)')
		self.assertEqual(self.__actions.addBannedIP('2001:db8::2'), 1)
		self.assertLogged(
			"Reban 2001:db8::2, action 'ip'",
			"stdout: %r" % 'ip reban 2001:db8::2 inet6',
			all=True)
		self.assertNotLogged(
			"Invariant check failed. Trying to restore a sane environment",
			"stdout: %r" % 'ip repair inet4', # both repairs occurred
			"stdout: %r" % 'ip repair inet6',
			"Reban 192.0.2.1, action 'ip'", "Reban 2001:db8::1, action 'ip'", # both rebans also
			"stdout: %r" % 'ip reban 192.0.2.1 inet4',
			"stdout: %r" % 'ip reban 2001:db8::1 inet6',
			all=True)

		# and bans present in files:
		self.pruneLog('[test-phase 4] check reban')
		self.dumpFile(tmp+'/inet4')
		self.assertLogged('192.0.2.1 inet4 -- rebanned')
		self.assertNotLogged('2001:db8::1 inet6 -- rebanned')
		self.pruneLog()
		self.dumpFile(tmp+'/inet6')
		self.assertLogged(
			'2001:db8::1 inet6 -- rebanned', 
			'2001:db8::2 inet6 -- rebanned', all=True)
		self.assertNotLogged('192.0.2.1 inet4 -- rebanned')

		# coverage - intended error in reban (no unhandled exception, message logged):
		act.actionreban = ''
		act.actionban = 'exit 1'
		self.assertEqual(self.__actions._Actions__reBan(FailTicket("192.0.2.1", 0)), 0)
		self.assertLogged(
			'Failed to execute reban',
			'Error banning 192.0.2.1', all=True)
