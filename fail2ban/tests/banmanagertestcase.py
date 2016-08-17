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
from .utils import assert_dict_equal

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
		
	def testBanTimeIncr(self):
		ticket = BanTicket(self.__ticket.getIP(), self.__ticket.getTime())
		## increase twice and at end permanent:
		for i in (1000, 2000, -1):
			self.__banManager.addBanTicket(self.__ticket)
			ticket.setBanTime(i)
			self.assertFalse(self.__banManager.addBanTicket(ticket))
			self.assertEqual(str(self.__banManager.getTicketByIP(ticket.getIP())), 
				"BanTicket: ip=%s time=%s bantime=%s bancount=0 #attempts=0 matches=[]" % (ticket.getIP(), ticket.getTime(), i))
		## after permanent, it should remain permanent ban time (-1):
		self.__banManager.addBanTicket(self.__ticket)
		ticket.setBanTime(-1)
		self.assertFalse(self.__banManager.addBanTicket(ticket))
		ticket.setBanTime(1000)
		self.assertFalse(self.__banManager.addBanTicket(ticket))
		self.assertEqual(str(self.__banManager.getTicketByIP(ticket.getIP())), 
			"BanTicket: ip=%s time=%s bantime=%s bancount=0 #attempts=0 matches=[]" % (ticket.getIP(), ticket.getTime(), -1))

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
		assert_dict_equal(cymru_info,
						  {"asn": [self.__asn],
						   "country": [self.__country],
						   "rir": [self.__rir]})

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
		self.__banManager = BanManager()

		# non-existing IP
		ticket = BanTicket("0.0.0.0", 1167605999.0)
		self.assertTrue(self.__banManager.addBanTicket(ticket))
		cymru_info = self.__banManager.getBanListExtendedCymruInfo()
		assert_dict_equal(cymru_info,
						  {"asn": ["nxdomain"],
						   "country": ["nxdomain"],
						   "rir": ["nxdomain"]})

		# even for private IPs ASNs defined
		# Since it outputs for all active tickets we would get previous results
		# and new ones
		ticket = BanTicket("10.0.0.0", 1167606000.0)
		self.assertTrue(self.__banManager.addBanTicket(ticket))
		cymru_info = self.__banManager.getBanListExtendedCymruInfo()
		assert_dict_equal(cymru_info,
						  {"asn": ["nxdomain", "4565",],
						   "country": ["nxdomain", "unknown"],
						   "rir": ["nxdomain", "other"]})
