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
		self.assertTrue(self.__banManager.addBanTicket(self.__ticket))

	def tearDown(self):
		"""Call after every test case."""
		pass

	def testAdd(self):
		self.assertEqual(self.__banManager.size(), 1)

	def testAddDuplicate(self):
		self.assertFalse(self.__banManager.addBanTicket(self.__ticket))
		self.assertEqual(self.__banManager.size(), 1)

	def testInListOK(self):
		ticket = BanTicket('193.168.0.128', 1167605999.0)
		self.assertTrue(self.__banManager._inBanList(ticket))

	def testInListNOK(self):
		ticket = BanTicket('111.111.1.111', 1167605999.0)
		self.assertFalse(self.__banManager._inBanList(ticket))


class StatusExtendedCymruInfo(unittest.TestCase):
	def setUp(self):
		"""Call before every test case."""
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

		# Since it outputs for all active tickets we would get previous results
		# and new ones
		ticket = BanTicket("8.0.0.0", 1167606000.0)
		self.assertTrue(self.__banManager.addBanTicket(ticket))
		cymru_info = self.__banManager.getBanListExtendedCymruInfo()
		assert_dict_equal(cymru_info,
						  {"asn": ["nxdomain", "3356",],
						   "country": ["nxdomain", "US"],
						   "rir": ["nxdomain", "arin"]})
