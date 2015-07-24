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
		self.__ticket = BanTicket('193.168.0.128', 1167605999.0)
		self.__banManager = BanManager()

	def tearDown(self):
		"""Call after every test case."""
		pass

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
		# add again a duplicate :
		#   1) with newer start time and the same ban time
		#   2) with same start time and longer ban time
    #   3) with permanent ban time (-1)
		for tnew, btnew in (
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
			banticket = self.__banManager.getTicketByIP(ticket2.getIP())
			self.assertEqual(banticket.getTime(), ticket2.getTime())
			self.assertEqual(banticket.getTime(), ticket2.getTime())
			self.assertEqual(banticket.getBanTime(), ticket2.getBanTime(self.__banManager.getBanTime()))

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
		self.assertTrue(self.__banManager.addBanTicket(self.__ticket))
		self.assertTrue(self.__banManager._inBanList(self.__ticket))
		self.assertEqual(self.__banManager.unBanList(self.__ticket.getTime() + btime + 1), [self.__ticket])
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
		pass

	def testCymruInfo(self):
		cymru_info = self.__banManager.getBanListExtendedCymruInfo()
		if "assertDictEqual" in dir(self):
			self.assertDictEqual(cymru_info, {"asn": [self.__asn],
											  "country": [self.__country],
											  "rir": [self.__rir]})
		else:
			# Python 2.6 does not support assertDictEqual()
			self.assertEqual(cymru_info["asn"], [self.__asn])
			self.assertEqual(cymru_info["country"], [self.__country])
			self.assertEqual(cymru_info["rir"], [self.__rir])

	def testCymruInfoASN(self):
		self.assertEqual(
			self.__banManager.geBanListExtendedASN(self.__banManager.getBanListExtendedCymruInfo()),
			[self.__asn])

	def testCymruInfoCountry(self):
		self.assertEqual(
			self.__banManager.geBanListExtendedCountry(self.__banManager.getBanListExtendedCymruInfo()),
			[self.__country])

	def testCymruInfoRIR(self):
		self.assertEqual(
			self.__banManager.geBanListExtendedRIR(self.__banManager.getBanListExtendedCymruInfo()),
			[self.__rir])

	def testCymruInfoNxdomain(self):
		ticket = BanTicket("10.0.0.0", 1167605999.0)
		self.__banManager = BanManager()
		self.assertTrue(self.__banManager.addBanTicket(ticket))
		cymru_info = self.__banManager.getBanListExtendedCymruInfo()
		if "assertDictEqual" in dir(self):
			self.assertDictEqual(cymru_info, {"asn": ["nxdomain"],
											  "country": ["nxdomain"],
											  "rir": ["nxdomain"]})
		else:
			# Python 2.6 does not support assertDictEqual()
			self.assertEqual(cymru_info["asn"], ["nxdomain"])
			self.assertEqual(cymru_info["country"], ["nxdomain"])
			self.assertEqual(cymru_info["rir"], ["nxdomain"])
