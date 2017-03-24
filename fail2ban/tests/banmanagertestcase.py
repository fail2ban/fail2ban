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

import unittest

from ..server.banmanager import BanManager
from ..server.ticket import BanTicket

class AddFailure(unittest.TestCase):
	def setUp(self):
		"""Call before every test case."""
		super(AddFailure, self).setUp()
		self.__ticket = BanTicket('193.168.0.128', 1167605999.0)
		self.__banManager = BanManager()

	def tearDown(self):
		"""Call after every test case."""
		super(AddFailure, self).tearDown()

	def testAdd(self):
		self.assertTrue(self.__banManager.addBanTicket(self.__ticket))
		self.assertEqual(self.__banManager.size(), 1)
		self.assertEqual(self.__banManager.getBanTotal(), 1)
		self.__banManager.setBanTotal(0)
		self.assertEqual(self.__banManager.getBanTotal(), 0)
	
	def testAddDuplicate(self):
		self.assertTrue(self.__banManager.addBanTicket(self.__ticket))
		self.assertFalse(self.__banManager.addBanTicket(self.__ticket))
		self.assertEqual(self.__banManager.size(), 1)

	def testAddDuplicateWithTime(self):
		defBanTime = self.__banManager.getBanTime()
		prevEndOfBanTime = 0
		# add again a duplicate :
		#   0) with same start time and the same (default) ban time
		#   1) with newer start time and the same (default) ban time
		#   2) with same start time and longer ban time
    #   3) with permanent ban time (-1)
		for tnew, btnew in (
			(1167605999.0,       None),
			(1167605999.0 + 100, None),
			(1167605999.0,       24*60*60),
			(1167605999.0,       -1),
		):
			ticket1 = BanTicket('193.168.0.128', 1167605999.0)
			ticket2 = BanTicket('193.168.0.128', tnew)
			if btnew is not None:
				ticket2.setBanTime(btnew)
			self.assertTrue(self.__banManager.addBanTicket(ticket1))
			self.assertFalse(self.__banManager.addBanTicket(ticket2))
			self.assertEqual(self.__banManager.size(), 1)
			# pop ticket and check it was prolonged :
			banticket = self.__banManager.getTicketByID(ticket2.getID())
			self.assertEqual(banticket.getEndOfBanTime(defBanTime), ticket2.getEndOfBanTime(defBanTime))
			self.assertTrue(banticket.getEndOfBanTime(defBanTime) > prevEndOfBanTime)
			prevEndOfBanTime = ticket1.getEndOfBanTime(defBanTime)
			# but the start time should not be changed (+ 100 is ignored):
			self.assertEqual(banticket.getTime(), 1167605999.0)
			# if prolong to permanent, it should also have permanent ban time:
			if btnew == -1:
				self.assertEqual(banticket.getBanTime(defBanTime), -1)

	def testInListOK(self):
		self.assertTrue(self.__banManager.addBanTicket(self.__ticket))
		ticket = BanTicket('193.168.0.128', 1167605999.0)
		self.assertTrue(self.__banManager._inBanList(ticket))

	def testInListNOK(self):
		self.assertTrue(self.__banManager.addBanTicket(self.__ticket))
		ticket = BanTicket('111.111.1.111', 1167605999.0)
		self.assertFalse(self.__banManager._inBanList(ticket))

	def testUnban(self):
		btime = self.__banManager.getBanTime()
		stime = self.__ticket.getTime()
		self.assertTrue(self.__banManager.addBanTicket(self.__ticket))
		self.assertTrue(self.__banManager._inBanList(self.__ticket))
		self.assertEqual(self.__banManager.unBanList(stime), [])
		self.assertEqual(self.__banManager.unBanList(stime + btime + 1), [self.__ticket])
		self.assertEqual(self.__banManager.size(), 0)
		## again, but now we will prolong ban-time and then try to unban again (1st too early):
		self.assertTrue(self.__banManager.addBanTicket(self.__ticket))
		# prolong ban:
		ticket = BanTicket(self.__ticket.getID(), stime + 600)
		self.assertFalse(self.__banManager.addBanTicket(ticket))
		# try unban too early:
		self.assertEqual(len(self.__banManager.unBanList(stime + btime + 1)), 0)
		# try unban using correct time:
		self.assertEqual(len(self.__banManager.unBanList(stime + btime + 600 + 1)), 1)
		## again, but now we test removing tickets particular (to test < 2/3-rule):
		for i in range(5):
			ticket = BanTicket('193.168.0.%s' % i, stime)
			ticket.setBanTime(ticket.getBanTime(btime) + i*10)
			self.assertTrue(self.__banManager.addBanTicket(ticket))
		self.assertEqual(len(self.__banManager.unBanList(stime + btime + 1*10 + 1)), 2)
		self.assertEqual(len(self.__banManager.unBanList(stime + btime + 5*10 + 1)), 3)
		self.assertEqual(self.__banManager.size(), 0)

	def testUnbanPermanent(self):
		btime = self.__banManager.getBanTime()
		self.__banManager.setBanTime(-1)
		try:
			self.assertTrue(self.__banManager.addBanTicket(self.__ticket))
			self.assertTrue(self.__banManager._inBanList(self.__ticket))
			self.assertEqual(self.__banManager.unBanList(self.__ticket.getTime() + btime + 1), [])
			self.assertEqual(self.__banManager.size(), 1)
		finally:
			self.__banManager.setBanTime(btime)


class StatusExtendedCymruInfo(unittest.TestCase):
	def setUp(self):
		"""Call before every test case."""
		super(StatusExtendedCymruInfo, self).setUp()
		unittest.F2B.SkipIfNoNetwork()
		self.__ban_ip = "93.184.216.34"
		self.__asn = "15133"
		self.__country = "EU"
		self.__rir = "ripencc"
		ticket = BanTicket(self.__ban_ip, 1167605999.0)
		self.__banManager = BanManager()
		self.assertTrue(self.__banManager.addBanTicket(ticket))

	def tearDown(self):
		"""Call after every test case."""
		super(StatusExtendedCymruInfo, self).tearDown()

	available = True, None

	def _getBanListExtendedCymruInfo(self):
		tc = StatusExtendedCymruInfo
		if tc.available[0]:
			cymru_info = self.__banManager.getBanListExtendedCymruInfo(
				timeout=(2 if unittest.F2B.fast else 20))
		else:
			cymru_info = tc.available[1]
		if cymru_info.get("error"): # pragma: no cover - availability
			tc.available = False, cymru_info
			raise unittest.SkipTest('Skip test because service is not available: %s' % cymru_info["error"])
		return cymru_info


	def testCymruInfo(self):
		cymru_info = self._getBanListExtendedCymruInfo()
		self.assertDictEqual(cymru_info,
						  {"asn": [self.__asn],
						   "country": [self.__country],
						   "rir": [self.__rir]})

	def testCymruInfoASN(self):
		self.assertEqual(
			self.__banManager.geBanListExtendedASN(self._getBanListExtendedCymruInfo()),
			[self.__asn])

	def testCymruInfoCountry(self):
		self.assertEqual(
			self.__banManager.geBanListExtendedCountry(self._getBanListExtendedCymruInfo()),
			[self.__country])

	def testCymruInfoRIR(self):
		self.assertEqual(
			self.__banManager.geBanListExtendedRIR(self._getBanListExtendedCymruInfo()),
			[self.__rir])

	def testCymruInfoNxdomain(self):
		self.__banManager = BanManager()

		# non-existing IP
		ticket = BanTicket("0.0.0.0", 1167605999.0)
		self.assertTrue(self.__banManager.addBanTicket(ticket))
		cymru_info = self._getBanListExtendedCymruInfo()
		self.assertDictEqual(cymru_info,
						  {"asn": ["nxdomain"],
						   "country": ["nxdomain"],
						   "rir": ["nxdomain"]})

		# even for private IPs ASNs defined
		# Since it outputs for all active tickets we would get previous results
		# and new ones
		ticket = BanTicket("10.0.0.0", 1167606000.0)
		self.assertTrue(self.__banManager.addBanTicket(ticket))
		cymru_info = self._getBanListExtendedCymruInfo()
		self.assertDictEqual(dict((k, sorted(v)) for k, v in cymru_info.iteritems()),
						  {"asn": sorted(["nxdomain", "4565",]),
						   "country": sorted(["nxdomain", "unknown"]),
						   "rir": sorted(["nxdomain", "other"])})
