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
from ..server.actions import Actions
from .dummyjail import DummyJail
try:
	from ..server.database import Fail2BanDb as Fail2BanDb
except ImportError: # pragma: no cover
	Fail2BanDb = None
from .utils import LogCaptureTestCase

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
		self.db = getFail2BanDb(self.dbFilename)

	def tearDown(self):
		"""Call after every test case."""
		super(DatabaseTest, self).tearDown()
		if Fail2BanDb is None: # pragma: no cover
			return
		# Cleanup
		if self.dbFilename is not None:
			os.remove(self.dbFilename)

	def testGetFilename(self):
		if Fail2BanDb is None or self.db.filename == ':memory:': # pragma: no cover
			return
		self.assertEqual(self.dbFilename, self.db.filename)

	def testPurgeAge(self):
		if Fail2BanDb is None: # pragma: no cover
			return
		self.assertEqual(self.db.purgeage, 86400)
		self.db.purgeage = '1y6mon15d5h30m'
		self.assertEqual(self.db.purgeage, 48652200)
		self.db.purgeage = '2y 12mon 30d 10h 60m'
		self.assertEqual(self.db.purgeage, 48652200*2)

	def testCreateInvalidPath(self):
		if Fail2BanDb is None: # pragma: no cover
			return
		self.assertRaises(
			sqlite3.OperationalError,
			Fail2BanDb,
			"/this/path/should/not/exist")

	def testCreateAndReconnect(self):
		if Fail2BanDb is None or self.db.filename == ':memory:': # pragma: no cover
			return
		self.testAddJail()
		# Reconnect...
		self.db = Fail2BanDb(self.dbFilename)
		# and check jail of same name still present
		self.assertTrue(
			self.jail.name in self.db.getJailNames(),
			"Jail not retained in Db after disconnect reconnect.")

	def testUpdateDb(self):
		if Fail2BanDb is None: # pragma: no cover
			return
		self.db = None
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
		os.remove(self.db._dbBackupFilename)

	def testAddJail(self):
		if Fail2BanDb is None: # pragma: no cover
			return
		self.jail = DummyJail()
		self.db.addJail(self.jail)
		self.assertTrue(
			self.jail.name in self.db.getJailNames(True),
			"Jail not added to database")

	def testAddLog(self):
		if Fail2BanDb is None: # pragma: no cover
			return
		self.testAddJail() # Jail required

		_, filename = tempfile.mkstemp(".log", "Fail2BanDb_")
		self.fileContainer = FileContainer(filename, "utf-8")

		self.db.addLog(self.jail, self.fileContainer)

		self.assertIn(filename, self.db.getLogPaths(self.jail))
		os.remove(filename)

	def testUpdateLog(self):
		if Fail2BanDb is None: # pragma: no cover
			return
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
		if Fail2BanDb is None: # pragma: no cover
			return
		self.testAddJail()
		ticket = FailTicket("127.0.0.1", 0, ["abc\n"])
		self.db.addBan(self.jail, ticket)

		self.assertEqual(len(self.db.getBans(jail=self.jail)), 1)
		self.assertTrue(
			isinstance(self.db.getBans(jail=self.jail)[0], FailTicket))

	def testAddBanInvalidEncoded(self):
		if Fail2BanDb is None: # pragma: no cover
			return
		self.testAddJail()
		# invalid + valid, invalid + valid unicode, invalid + valid dual converted (like in filter:readline by fallback) ...
		tickets = [
		  FailTicket("127.0.0.1", 0, ['user "\xd1\xe2\xe5\xf2\xe0"', 'user "\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x9f"']),
		  FailTicket("127.0.0.2", 0, ['user "\xd1\xe2\xe5\xf2\xe0"', u'user "\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x9f"']),
		  FailTicket("127.0.0.3", 0, ['user "\xd1\xe2\xe5\xf2\xe0"', b'user "\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x9f"'.decode('utf-8', 'replace')])
		]
		self.db.addBan(self.jail, tickets[0])
		self.db.addBan(self.jail, tickets[1])
		self.db.addBan(self.jail, tickets[2])

		readtickets = self.db.getBans(jail=self.jail)
		self.assertEqual(len(readtickets), 3)
		## python 2 or 3 :
		invstr = u'user "\ufffd\ufffd\ufffd\ufffd\ufffd"'.encode('utf-8', 'replace')
		self.assertTrue(
			   readtickets[0] == FailTicket("127.0.0.1", 0, [invstr, 'user "\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x9f"'])
			or readtickets[0] == tickets[0]
		)
		self.assertTrue(
			   readtickets[1] == FailTicket("127.0.0.2", 0, [invstr, u'user "\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x9f"'.encode('utf-8', 'replace')])
			or readtickets[1] == tickets[1]
		)
		self.assertTrue(
			   readtickets[2] == FailTicket("127.0.0.3", 0, [invstr, 'user "\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x9f"'])
			or readtickets[2] == tickets[2]
		)

	def testDelBan(self):
		self.testAddBan()
		ticket = self.db.getBans(jail=self.jail)[0]
		self.db.delBan(self.jail, ticket.getIP())
		self.assertEqual(len(self.db.getBans(jail=self.jail)), 0)

	def testGetBansWithTime(self):
		if Fail2BanDb is None: # pragma: no cover
			return
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

	def testGetBansMerged_MaxEntries(self):
		if Fail2BanDb is None: # pragma: no cover
			return
		self.testAddJail()
		maxEntries = 2
		failures = ["abc\n", "123\n", "ABC\n", "1234\n"]
		# add failures sequential:
		i = 80
		for f in failures:
			i -= 10
			ticket = FailTicket("127.0.0.1", MyTime.time() - i, [f])
			ticket.setAttempt(1)
			self.db.addBan(self.jail, ticket)
		# should retrieve 2 matches only, but count of all attempts:
		self.db.maxEntries = maxEntries;
		ticket = self.db.getBansMerged("127.0.0.1")
		self.assertEqual(ticket.getIP(), "127.0.0.1")
		self.assertEqual(ticket.getAttempt(), len(failures))
		self.assertEqual(len(ticket.getMatches()), maxEntries)
		self.assertEqual(ticket.getMatches(), failures[len(failures) - maxEntries:])
    # add more failures at once:
		ticket = FailTicket("127.0.0.1", MyTime.time() - 10, failures)
		ticket.setAttempt(len(failures))
		self.db.addBan(self.jail, ticket)
		# should retrieve 2 matches only, but count of all attempts:
		self.db.maxEntries = maxEntries;
		ticket = self.db.getBansMerged("127.0.0.1")
		self.assertEqual(ticket.getAttempt(), 2 * len(failures))
		self.assertEqual(len(ticket.getMatches()), maxEntries)
		self.assertEqual(ticket.getMatches(), failures[len(failures) - maxEntries:])

	def testGetBansMerged(self):
		if Fail2BanDb is None: # pragma: no cover
			return
		self.testAddJail()

		jail2 = DummyJail()
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
		self.assertEqual(
			sorted(list(set(ticket.getIP() for ticket in tickets))),
			sorted([ticket.getIP() for ticket in tickets]))

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

	def testActionWithDB(self):
		# test action together with database functionality
		self.testAddJail() # Jail required
		self.jail.database = self.db
		actions = Actions(self.jail)
		actions.add(
			"action_checkainfo",
			os.path.join(TEST_FILES_DIR, "action.d/action_checkainfo.py"),
			{})
		ticket = FailTicket("1.2.3.4", MyTime.time(), ['test', 'test'])
		ticket.setAttempt(5)
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
		if Fail2BanDb is None: # pragma: no cover
			return
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
