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

# Fail2Ban developers

__copyright__ = "Copyright (c) 2013 Steven Hiscocks"
__license__ = "GPL"

import os
import sys
import unittest
import tempfile
import sqlite3
import shutil

from ..server.filter import FileContainer
from ..server.mytime import MyTime
from ..server.ticket import FailTicket
from ..server.actions import Actions, Utils
from .dummyjail import DummyJail
try:
	from ..server import database
	Fail2BanDb = database.Fail2BanDb
except ImportError: # pragma: no cover
	Fail2BanDb = None
from .utils import LogCaptureTestCase, logSys as DefLogSys

TEST_FILES_DIR = os.path.join(os.path.dirname(__file__), "files")


# because of tests performance use memory instead of file:
def getFail2BanDb(filename):
	if unittest.F2B.memory_db: # pragma: no cover
		return Fail2BanDb(':memory:')
	return Fail2BanDb(filename)


class DatabaseTest(LogCaptureTestCase):

	def setUp(self):
		"""Call before every test case."""
		super(DatabaseTest, self).setUp()
		if Fail2BanDb is None: # pragma: no cover
			raise unittest.SkipTest(
				"Unable to import fail2ban database module as sqlite is not "
				"available.")
		self.dbFilename = None
		if not unittest.F2B.memory_db:
			_, self.dbFilename = tempfile.mkstemp(".db", "fail2ban_")
		self._db = ':auto-create-in-memory:'

	@property
	def db(self):
		if isinstance(self._db, basestring) and self._db == ':auto-create-in-memory:':
			self._db = getFail2BanDb(self.dbFilename)
		return self._db
	@db.setter
	def db(self, value):
		if isinstance(self._db, Fail2BanDb): # pragma: no cover
			self._db.close()
		self._db = value

	def tearDown(self):
		"""Call after every test case."""
		super(DatabaseTest, self).tearDown()
		if Fail2BanDb is None: # pragma: no cover
			return
		# Cleanup
		if self.dbFilename is not None:
			os.remove(self.dbFilename)

	def testGetFilename(self):
		if self.db.filename == ':memory:': # pragma: no cover
			raise unittest.SkipTest("in :memory: database")
		self.assertEqual(self.dbFilename, self.db.filename)

	def testPurgeAge(self):
		self.assertEqual(self.db.purgeage, 86400)
		self.db.purgeage = '1y6mon15d5h30m'
		self.assertEqual(self.db.purgeage, 48652200)
		self.db.purgeage = '2y 12mon 30d 10h 60m'
		self.assertEqual(self.db.purgeage, 48652200*2)

	def testCreateInvalidPath(self):
		self.assertRaises(
			sqlite3.OperationalError,
			Fail2BanDb,
			"/this/path/should/not/exist")

	def testCreateAndReconnect(self):
		if self.db.filename == ':memory:': # pragma: no cover
			raise unittest.SkipTest("in :memory: database")
		self.testAddJail()
		# Reconnect...
		self.db = Fail2BanDb(self.dbFilename)
		# and check jail of same name still present
		self.assertTrue(
			self.jail.name in self.db.getJailNames(),
			"Jail not retained in Db after disconnect reconnect.")

	def testRepairDb(self):
		if not Utils.executeCmd("sqlite3 --version"): # pragma: no cover
			raise unittest.SkipTest("no sqlite3 command")
		self.db = None
		if self.dbFilename is None: # pragma: no cover
			_, self.dbFilename = tempfile.mkstemp(".db", "fail2ban_")
		# test truncated database with different sizes:
		#   - 14000 bytes - seems to be reparable,
		#   - 4000  bytes - is totally broken.
		for truncSize in (14000, 4000):
			self.pruneLog("[test-repair], next phase - file-size: %d" % truncSize)
			shutil.copyfile(
				os.path.join(TEST_FILES_DIR, 'database_v1.db'), self.dbFilename)
			# produce currupt database:
			f = os.open(self.dbFilename, os.O_RDWR)
			os.ftruncate(f, truncSize)
			os.close(f)
			# test repair:
			try:
				self.db = Fail2BanDb(self.dbFilename)
				if truncSize == 14000: # restored:
					self.assertLogged("Repair seems to be successful",
						"Check integrity", "Database updated", all=True)
					self.assertEqual(self.db.getLogPaths(), set(['/tmp/Fail2BanDb_pUlZJh.log']))
					self.assertEqual(len(self.db.getJailNames()), 1)
				else: # recreated:
					self.assertLogged("Repair seems to be failed",
						"Check integrity", "New database created.", all=True)
					self.assertEqual(len(self.db.getLogPaths()), 0)
					self.assertEqual(len(self.db.getJailNames()), 0)
			finally:
				if self.db and self.db._dbFilename != ":memory:":
					os.remove(self.db._dbBackupFilename)
					self.db = None

	def testUpdateDb(self):
		self.db = None
		try:
			if self.dbFilename is None: # pragma: no cover
				_, self.dbFilename = tempfile.mkstemp(".db", "fail2ban_")
			shutil.copyfile(
				os.path.join(TEST_FILES_DIR, 'database_v1.db'), self.dbFilename)
			self.db = Fail2BanDb(self.dbFilename)
			self.assertEqual(self.db.getJailNames(), set(['DummyJail #29162448 with 0 tickets']))
			self.assertEqual(self.db.getLogPaths(), set(['/tmp/Fail2BanDb_pUlZJh.log']))
			ticket = FailTicket("127.0.0.1", 1388009242.26, [u"abc\n"])
			self.assertEqual(self.db.getBans()[0], ticket)

			self.assertEqual(self.db.updateDb(Fail2BanDb.__version__), Fail2BanDb.__version__)
			self.assertRaises(NotImplementedError, self.db.updateDb, Fail2BanDb.__version__ + 1)
			# check current bans (should find exactly 1 ticket after upgrade):
			tickets = self.db.getCurrentBans(fromtime=1388009242, correctBanTime=123456)
			self.assertEqual(len(tickets), 1)
			self.assertEqual(tickets[0].getBanTime(), 123456); # ban-time was unknown (normally updated from jail)
		finally:
			if self.db and self.db._dbFilename != ":memory:":
				os.remove(self.db._dbBackupFilename)

	def testUpdateDb2(self):
		self.db = None
		if self.dbFilename is None: # pragma: no cover
			_, self.dbFilename = tempfile.mkstemp(".db", "fail2ban_")
		shutil.copyfile(
			os.path.join(TEST_FILES_DIR, 'database_v2.db'), self.dbFilename)
		self.db = Fail2BanDb(self.dbFilename)
		self.assertEqual(self.db.getJailNames(), set(['pam-generic']))
		self.assertEqual(self.db.getLogPaths(), set(['/var/log/auth.log']))
		bans = self.db.getBans()
		self.assertEqual(len(bans), 2)
		# compare first ticket completely:
		ticket = FailTicket("1.2.3.7", 1417595494, [
			u'Dec  3 09:31:08 f2btest test:auth[27658]: pam_unix(test:auth): authentication failure; logname= uid=0 euid=0 tty=test ruser= rhost=1.2.3.7',
			u'Dec  3 09:31:32 f2btest test:auth[27671]: pam_unix(test:auth): authentication failure; logname= uid=0 euid=0 tty=test ruser= rhost=1.2.3.7',
			u'Dec  3 09:31:34 f2btest test:auth[27673]: pam_unix(test:auth): authentication failure; logname= uid=0 euid=0 tty=test ruser= rhost=1.2.3.7'
		])
		ticket.setAttempt(3)
		self.assertEqual(bans[0], ticket)
		# second ban found also:
		self.assertEqual(bans[1].getIP(), "1.2.3.8")
		# updated ?
		self.assertEqual(self.db.updateDb(Fail2BanDb.__version__), Fail2BanDb.__version__)
		# check current bans (should find 2 tickets after upgrade):
		self.jail = DummyJail(name='pam-generic')
		tickets = self.db.getCurrentBans(jail=self.jail, fromtime=1417595494)
		self.assertEqual(len(tickets), 2)
		self.assertEqual(tickets[0].getBanTime(), 600)
		# further update should fail:
		self.assertRaises(NotImplementedError, self.db.updateDb, Fail2BanDb.__version__ + 1)
		# clean:
		os.remove(self.db._dbBackupFilename)

	def testAddJail(self):
		self.jail = DummyJail()
		self.db.addJail(self.jail)
		self.assertTrue(
			self.jail.name in self.db.getJailNames(True),
			"Jail not added to database")

	def testAddLog(self):
		self.testAddJail() # Jail required

		_, filename = tempfile.mkstemp(".log", "Fail2BanDb_")
		self.fileContainer = FileContainer(filename, "utf-8")

		self.db.addLog(self.jail, self.fileContainer)

		self.assertIn(filename, self.db.getLogPaths(self.jail))
		os.remove(filename)

	def testUpdateLog(self):
		self.testAddLog() # Add log file

		# Write some text
		filename = self.fileContainer.getFileName()
		file_ = open(filename, "w")
		file_.write("Some text to write which will change md5sum\n")
		file_.close()
		self.fileContainer.open()
		self.fileContainer.readline()
		self.fileContainer.close()

		# Capture position which should be after line just written
		lastPos = self.fileContainer.getPos()
		self.assertTrue(lastPos > 0)
		self.db.updateLog(self.jail, self.fileContainer)

		# New FileContainer for file
		self.fileContainer = FileContainer(filename, "utf-8")
		self.assertEqual(self.fileContainer.getPos(), 0)

		# Database should return previous position in file
		self.assertEqual(
			self.db.addLog(self.jail, self.fileContainer), lastPos)

		# Change md5sum
		file_ = open(filename, "w") # Truncate
		file_.write("Some different text to change md5sum\n")
		file_.close()

		self.fileContainer = FileContainer(filename, "utf-8")
		self.assertEqual(self.fileContainer.getPos(), 0)

		# Database should be aware of md5sum change, such doesn't return
		# last position in file
		self.assertEqual(
			self.db.addLog(self.jail, self.fileContainer), None)
		os.remove(filename)

	def testAddBan(self):
		self.testAddJail()
		ticket = FailTicket("127.0.0.1", 0, ["abc\n"])
		self.db.addBan(self.jail, ticket)

		tickets = self.db.getBans(jail=self.jail)
		self.assertEqual(len(tickets), 1)
		self.assertTrue(
			isinstance(tickets[0], FailTicket))

	def testAddBanInvalidEncoded(self):
		self.testAddJail()
		# invalid + valid, invalid + valid unicode, invalid + valid dual converted (like in filter:readline by fallback) ...
		tickets = [
		  FailTicket("127.0.0.1", 0, ['user "test"', 'user "\xd1\xe2\xe5\xf2\xe0"', 'user "\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x9f"']),
		  FailTicket("127.0.0.2", 0, ['user "test"', u'user "\xd1\xe2\xe5\xf2\xe0"', u'user "\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x9f"']),
		  FailTicket("127.0.0.3", 0, ['user "test"', b'user "\xd1\xe2\xe5\xf2\xe0"', b'user "\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x9f"']),
		  FailTicket("127.0.0.4", 0, ['user "test"', 'user "\xd1\xe2\xe5\xf2\xe0"', u'user "\xe4\xf6\xfc\xdf"']),
		  FailTicket("127.0.0.5", 0, ['user "test"', 'unterminated \xcf']),
		  FailTicket("127.0.0.6", 0, ['user "test"', u'unterminated \xcf']),
		  FailTicket("127.0.0.7", 0, ['user "test"', b'unterminated \xcf'])
		]
		for ticket in tickets:
			self.db.addBan(self.jail, ticket)

		self.assertNotLogged("json dumps failed")

		readtickets = self.db.getBans(jail=self.jail)

		self.assertNotLogged("json loads failed")

		## all tickets available
		self.assertEqual(len(readtickets), 7)

		## too different to cover all possible constellations for python 2 and 3,
		## can replace/ignore some non-ascii chars by json dump/load (unicode/str),
		## so check ip and matches count only:
		for i, ticket in enumerate(tickets):
			DefLogSys.debug('readtickets[%d]: %r', i, readtickets[i].getData())
			DefLogSys.debug(' == tickets[%d]: %r', i, ticket.getData())
			self.assertEqual(readtickets[i].getIP(), ticket.getIP())
			self.assertEqual(len(readtickets[i].getMatches()), len(ticket.getMatches()))

		self.pruneLog('[test-phase 2] simulate errors')
		## simulate errors in dumps/loads:
		priorEnc = database.PREFER_ENC
		try:
			database.PREFER_ENC = 'f2b-test::non-existing-encoding'

			for ticket in tickets:
				self.db.addBan(self.jail, ticket)

			self.assertLogged("json dumps failed")

			readtickets = self.db.getBans(jail=self.jail)

			self.assertLogged("json loads failed")

			## despite errors all tickets written and loaded (check adapter-handlers are error-safe):
			self.assertEqual(len(readtickets), 14)
		finally:
			database.PREFER_ENC = priorEnc
		
		## check the database is still operable (not locked) after all the errors:
		self.pruneLog('[test-phase 3] still operable?')
		self.db.addBan(self.jail, FailTicket("127.0.0.8"))
		readtickets = self.db.getBans(jail=self.jail)
		self.assertEqual(len(readtickets), 15)
		self.assertNotLogged("json loads failed", "json dumps failed")

	def _testAdd3Bans(self):
		self.testAddJail()
		for i in (1, 2, 3):
			ticket = FailTicket(("192.0.2.%d" % i), 0, ["test\n"])
			self.db.addBan(self.jail, ticket)
		tickets = self.db.getBans(jail=self.jail)
		self.assertEqual(len(tickets), 3)
		return tickets

	def testDelBan(self):
		tickets = self._testAdd3Bans()
		# delete single IP:
		self.db.delBan(self.jail, tickets[0].getIP())
		self.assertEqual(len(self.db.getBans(jail=self.jail)), 2)
		# delete two IPs:
		self.db.delBan(self.jail, tickets[1].getIP(), tickets[2].getIP())
		self.assertEqual(len(self.db.getBans(jail=self.jail)), 0)

	def testFlushBans(self):
		self._testAdd3Bans()
		# flush all bans:
		self.db.delBan(self.jail)
		self.assertEqual(len(self.db.getBans(jail=self.jail)), 0)

	def testGetBansWithTime(self):
		self.testAddJail()
		self.db.addBan(
			self.jail, FailTicket("127.0.0.1", MyTime.time() - 60, ["abc\n"]))
		self.db.addBan(
			self.jail, FailTicket("127.0.0.1", MyTime.time() - 40, ["abc\n"]))
		self.assertEqual(len(self.db.getBans(jail=self.jail,bantime=50)), 1)
		self.assertEqual(len(self.db.getBans(jail=self.jail,bantime=20)), 0)
		# Negative values are for persistent bans, and such all bans should
		# be returned
		self.assertEqual(len(self.db.getBans(jail=self.jail,bantime=-1)), 2)

	def testGetBansMerged_MaxMatches(self):
		self.testAddJail()
		maxMatches = 2
		failures = [
			{"matches": ["abc\n"], "user": set(['test'])},
			{"matches": ["123\n"], "user": set(['test'])},
			{"matches": ["ABC\n"], "user": set(['test', 'root'])},
			{"matches": ["1234\n"], "user": set(['test', 'root'])},
		]
		matches2find = [f["matches"][0] for f in failures]
		# add failures sequential:
		i = 80
		for f in failures:
			i -= 10
			ticket = FailTicket("127.0.0.1", MyTime.time() - i, data=f)
			ticket.setAttempt(1)
			self.db.addBan(self.jail, ticket)
		# should retrieve 2 matches only, but count of all attempts:
		self.db.maxMatches = maxMatches;
		ticket = self.db.getBansMerged("127.0.0.1")
		self.assertEqual(ticket.getIP(), "127.0.0.1")
		self.assertEqual(ticket.getAttempt(), len(failures))
		self.assertEqual(len(ticket.getMatches()), maxMatches)
		self.assertEqual(ticket.getMatches(), matches2find[-maxMatches:])
    # add more failures at once:
		ticket = FailTicket("127.0.0.1", MyTime.time() - 10, matches2find,
			data={"user": set(['test', 'root'])})
		ticket.setAttempt(len(failures))
		self.db.addBan(self.jail, ticket)
		# should retrieve 2 matches only, but count of all attempts:
		ticket = self.db.getBansMerged("127.0.0.1")
		self.assertEqual(ticket.getAttempt(), 2 * len(failures))
		self.assertEqual(len(ticket.getMatches()), maxMatches)
		self.assertEqual(ticket.getMatches(), matches2find[-maxMatches:])
		# also using getCurrentBans:
		ticket = self.db.getCurrentBans(self.jail, "127.0.0.1", fromtime=MyTime.time()-100)
		self.assertTrue(ticket is not None)
		self.assertEqual(ticket.getAttempt(), len(failures))
		self.assertEqual(len(ticket.getMatches()), maxMatches)
		self.assertEqual(ticket.getMatches(), matches2find[-maxMatches:])
		# maxmatches of jail < dbmaxmatches (so read 1 match and 0 matches):
		ticket = self.db.getCurrentBans(self.jail, "127.0.0.1", fromtime=MyTime.time()-100,
			maxmatches=1)
		self.assertEqual(len(ticket.getMatches()), 1)
		self.assertEqual(ticket.getMatches(), failures[3]['matches'])
		ticket = self.db.getCurrentBans(self.jail, "127.0.0.1", fromtime=MyTime.time()-100,
			maxmatches=0)
		self.assertEqual(len(ticket.getMatches()), 0)
		# dbmaxmatches = 0, should retrieve 0 matches by last ban:
		ticket.setMatches(["1","2","3"])
		self.db.maxMatches = 0;
		self.db.addBan(self.jail, ticket)
		ticket = self.db.getCurrentBans(self.jail, "127.0.0.1", fromtime=MyTime.time()-100)
		self.assertTrue(ticket is not None)
		self.assertEqual(ticket.getAttempt(), len(failures))
		self.assertEqual(len(ticket.getMatches()), 0)

	def testGetBansMerged(self):
		self.testAddJail()

		jail2 = DummyJail(name='DummyJail-2')
		self.db.addJail(jail2)

		ticket = FailTicket("127.0.0.1", MyTime.time() - 40, ["abc\n"])
		ticket.setAttempt(10)
		self.db.addBan(self.jail, ticket)
		ticket = FailTicket("127.0.0.1", MyTime.time() - 30, ["123\n"])
		ticket.setAttempt(20)
		self.db.addBan(self.jail, ticket)
		ticket = FailTicket("127.0.0.2", MyTime.time() - 20, ["ABC\n"])
		ticket.setAttempt(30)
		self.db.addBan(self.jail, ticket)
		ticket = FailTicket("127.0.0.1", MyTime.time() - 10, ["ABC\n"])
		ticket.setAttempt(40)
		self.db.addBan(jail2, ticket)

		# All for IP 127.0.0.1
		ticket = self.db.getBansMerged("127.0.0.1")
		self.assertEqual(ticket.getIP(), "127.0.0.1")
		self.assertEqual(ticket.getAttempt(), 70)
		self.assertEqual(ticket.getMatches(), ["abc\n", "123\n", "ABC\n"])

		# All for IP 127.0.0.1 for single jail
		ticket = self.db.getBansMerged("127.0.0.1", jail=self.jail)
		self.assertEqual(ticket.getIP(), "127.0.0.1")
		self.assertEqual(ticket.getAttempt(), 30)
		self.assertEqual(ticket.getMatches(), ["abc\n", "123\n"])

		# Should cache result if no extra bans added
		self.assertEqual(
			id(ticket),
			id(self.db.getBansMerged("127.0.0.1", jail=self.jail)))

		newTicket = FailTicket("127.0.0.2", MyTime.time() - 20, ["ABC\n"])
		ticket.setAttempt(40)
		# Add ticket, but not for same IP, so cache still valid
		self.db.addBan(self.jail, newTicket)
		self.assertEqual(
			id(ticket),
			id(self.db.getBansMerged("127.0.0.1", jail=self.jail)))

		newTicket = FailTicket("127.0.0.1", MyTime.time() - 10, ["ABC\n"])
		ticket.setAttempt(40)
		self.db.addBan(self.jail, newTicket)
		# Added ticket, so cache should have been cleared
		self.assertNotEqual(
			id(ticket),
			id(self.db.getBansMerged("127.0.0.1", jail=self.jail)))

		tickets = self.db.getBansMerged()
		self.assertEqual(len(tickets), 2)
		self.assertSortedEqual(
			list(set(ticket.getIP() for ticket in tickets)),
			[ticket.getIP() for ticket in tickets])

		tickets = self.db.getBansMerged(jail=jail2)
		self.assertEqual(len(tickets), 1)

		tickets = self.db.getBansMerged(bantime=25)
		self.assertEqual(len(tickets), 2)
		tickets = self.db.getBansMerged(bantime=15)
		self.assertEqual(len(tickets), 1)
		tickets = self.db.getBansMerged(bantime=5)
		self.assertEqual(len(tickets), 0)
		# Negative values are for persistent bans, and such all bans should
		# be returned
		tickets = self.db.getBansMerged(bantime=-1)
		self.assertEqual(len(tickets), 2)
		# getCurrentBans:
		tickets = self.db.getCurrentBans(jail=self.jail)
		self.assertEqual(len(tickets), 2)
		ticket = self.db.getCurrentBans(jail=None, ip="127.0.0.1");
		self.assertEqual(ticket.getIP(), "127.0.0.1")
		
		# positive case (1 ticket not yet expired):
		tickets = self.db.getCurrentBans(jail=self.jail, forbantime=15,
			fromtime=MyTime.time())
		self.assertEqual(len(tickets), 1)
		# negative case (all are expired in 1year):
		tickets = self.db.getCurrentBans(jail=self.jail, forbantime=15,
			fromtime=MyTime.time() + MyTime.str2seconds("1year"))
		self.assertEqual(len(tickets), 0)
		# persistent bantime (-1), so never expired (but no persistent tickets):
		tickets = self.db.getCurrentBans(jail=self.jail, forbantime=-1,
			fromtime=MyTime.time() + MyTime.str2seconds("1year"))
		self.assertEqual(len(tickets), 0)
		# add persistent one:
		ticket.setBanTime(-1)
		self.db.addBan(self.jail, ticket)
		# persistent bantime (-1), so never expired (but jail has other max bantime now):
		tickets = self.db.getCurrentBans(jail=self.jail, forbantime=-1,
			fromtime=MyTime.time() + MyTime.str2seconds("1year"))
		# no tickets should be found (max ban time = 600):
		self.assertEqual(len(tickets), 0)
		self.assertLogged("ignore ticket (with new max ban-time %r)" % self.jail.getMaxBanTime())
		# change jail to persistent ban and try again (1 persistent ticket):
		self.jail.actions.setBanTime(-1)
		tickets = self.db.getCurrentBans(jail=self.jail, forbantime=-1,
			fromtime=MyTime.time() + MyTime.str2seconds("1year"))
		self.assertEqual(len(tickets), 1)
		self.assertEqual(tickets[0].getBanTime(), -1); # current jail ban time.

	def testActionWithDB(self):
		# test action together with database functionality
		self.testAddJail() # Jail required
		self.jail.database = self.db
		actions = Actions(self.jail)
		actions.add(
			"action_checkainfo",
			os.path.join(TEST_FILES_DIR, "action.d/action_checkainfo.py"),
			{})
		ticket = FailTicket("1.2.3.4")
		ticket.setAttempt(5)
		ticket.setMatches(['test', 'test'])
		self.jail.putFailTicket(ticket)
		actions._Actions__checkBan()
		self.assertLogged("ban ainfo %s, %s, %s, %s" % (True, True, True, True))

	def testDelAndAddJail(self):
		self.testAddJail() # Add jail
		# Delete jail (just disabled it):
		self.db.delJail(self.jail)
		jails = self.db.getJailNames()
		self.assertIn(len(jails) == 1 and self.jail.name, jails)
		jails = self.db.getJailNames(enabled=False)
		self.assertIn(len(jails) == 1 and self.jail.name, jails)
		jails = self.db.getJailNames(enabled=True)
		self.assertTrue(len(jails) == 0)
		# Add it again - should just enable it:
		self.db.addJail(self.jail)
		jails = self.db.getJailNames()
		self.assertIn(len(jails) == 1 and self.jail.name, jails)
		jails = self.db.getJailNames(enabled=True)
		self.assertIn(len(jails) == 1 and self.jail.name, jails)
		jails = self.db.getJailNames(enabled=False)
		self.assertTrue(len(jails) == 0)

	def testPurge(self):
		self.testAddJail() # Add jail

		self.db.purge() # Jail enabled by default so shouldn't be purged
		self.assertEqual(len(self.db.getJailNames()), 1)

		self.db.delJail(self.jail)
		self.db.purge() # Should remove jail
		self.assertEqual(len(self.db.getJailNames()), 0)

		self.testAddBan()
		self.db.delJail(self.jail)
		self.db.purge() # Purge should remove all bans
		self.assertEqual(len(self.db.getJailNames()), 0)
		self.assertEqual(len(self.db.getBans(jail=self.jail)), 0)

		# Should leave jail
		self.testAddJail()
		self.db.addBan(
			self.jail, FailTicket("127.0.0.1", MyTime.time(), ["abc\n"]))
		self.db.delJail(self.jail)
		self.db.purge() # Should leave jail as ban present
		self.assertEqual(len(self.db.getJailNames()), 1)
		self.assertEqual(len(self.db.getBans(jail=self.jail)), 1)
