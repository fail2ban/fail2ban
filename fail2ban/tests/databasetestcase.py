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
import unittest
import tempfile
import sqlite3
import shutil

from fail2ban.server.database import Fail2BanDb
from fail2ban.server.filter import FileContainer
from fail2ban.server.mytime import MyTime
from fail2ban.server.ticket import FailTicket
from fail2ban.tests.dummyjail import DummyJail

class DatabaseTest(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""
		_, self.dbFilename = tempfile.mkstemp(".db", "fail2ban_")
		self.db = Fail2BanDb(self.dbFilename)

	def tearDown(self):
		"""Call after every test case."""
		# Cleanup
		os.remove(self.dbFilename)

	def getFilename(self):
		self.assertEqual(self.dbFilename, self.db.getFilename())

	def testCreateInvalidPath(self):
		self.assertRaises(
			sqlite3.OperationalError,
			Fail2BanDb,
			"/this/path/should/not/exist")

	def testCreateAndReconnect(self):
		self.testAddJail()
		# Reconnect...
		self.db = Fail2BanDb(self.dbFilename)
		# and check jail of same name still present
		self.assertTrue(
			self.jail.getName() in self.db.getJailNames(),
			"Jail not retained in Db after disconnect reconnect.")

	def testUpdateDb(self):
		shutil.copyfile('fail2ban/tests/files/database_v1.db', self.dbFilename)
		self.db = Fail2BanDb(self.dbFilename)
		self.assertEqual(self.db.getJailNames(), set(['DummyJail #29162448 with 0 tickets']))
		self.assertEqual(self.db.getLogPaths(), {'/tmp/Fail2BanDb_pUlZJh.log'})
		ticket = FailTicket("127.0.0.1", 1388009242.26, [u"abc\n"])
		self.assertEqual(self.db.getBans()[0], ticket)

		self.assertEqual(self.db.updateDb(Fail2BanDb.__version__), Fail2BanDb.__version__)
		self.assertRaises(NotImplementedError, self.db.updateDb, Fail2BanDb.__version__ + 1)
		os.remove(self.db.dbBackupFilename)

	def testAddJail(self):
		self.jail = DummyJail()
		self.db.addJail(self.jail)
		self.assertTrue(
			self.jail.getName() in self.db.getJailNames(),
			"Jail not added to database")

	def testAddLog(self):
		self.testAddJail() # Jail required

		_, filename = tempfile.mkstemp(".log", "Fail2BanDb_")
		self.fileContainer = FileContainer(filename, "utf-8")

		self.db.addLog(self.jail, self.fileContainer)

		self.assertTrue(filename in self.db.getLogPaths(self.jail))
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

		self.assertEquals(len(self.db.getBans(jail=self.jail)), 1)
		self.assertTrue(
			isinstance(self.db.getBans(jail=self.jail)[0], FailTicket))

	def testGetBansMerged(self):
		self.testAddJail()

		jail2 = DummyJail()
		self.db.addJail(jail2)

		ticket = FailTicket("127.0.0.1", 10, ["abc\n"])
		ticket.setAttempt(10)
		self.db.addBan(self.jail, ticket)
		ticket = FailTicket("127.0.0.1", 20, ["123\n"])
		ticket.setAttempt(20)
		self.db.addBan(self.jail, ticket)
		ticket = FailTicket("127.0.0.2", 30, ["ABC\n"])
		ticket.setAttempt(30)
		self.db.addBan(self.jail, ticket)
		ticket = FailTicket("127.0.0.1", 40, ["ABC\n"])
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

		newTicket = FailTicket("127.0.0.1", 40, ["ABC\n"])
		ticket.setAttempt(40)
		self.db.addBan(self.jail, newTicket)
		# Added ticket, so cache should have been cleared
		self.assertNotEqual(
			id(ticket),
			id(self.db.getBansMerged("127.0.0.1", jail=self.jail)))

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
