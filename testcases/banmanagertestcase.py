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
# $Revision$

__author__ = "Cyril Jaquier"
__version__ = "$Revision$"
__date__ = "$Date$"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import unittest
from server.banmanager import BanManager
from server.ticket import BanTicket, FailTicket
from server.mytime import MyTime
import socket

class AddFailure(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""
		self.__ticket = BanTicket('193.168.0.128', socket.AF_INET, 1167605999.0)
		self.__banManager = BanManager(debugtest=True)
		self.__ticket_v6 = BanTicket('2001:620:618:1a6:1:80b2:a60a:2', socket.AF_INET6, 1167605999.0)
		self.assertTrue(self.__banManager.addBanTicket(self.__ticket))
		self.assertTrue(self.__banManager.addBanTicket(self.__ticket_v6))

	def tearDown(self):
		"""Call after every test case."""
	
	def testAdd(self):
		self.assertEqual(self.__banManager.size(), 2)
	
	def testAddDuplicate(self):
		self.assertFalse(self.__banManager.addBanTicket(self.__ticket))
		self.assertEqual(self.__banManager.size(), 2)
		
	def testInListOK(self):
		ticket = BanTicket('193.168.0.128', socket.AF_INET, 1167605999.0)
		self.assertTrue(self.__banManager.inBanList(ticket))
		self.assertEqual(self.__banManager.getBanTotal(),2)
		self.__banManager.setBanTime(-1)
		self.assertEqual(self.__banManager.unBanList(1167605999.0 + 300), [])
		self.__banManager.setBanTime(200)
		self.assertEqual(self.__banManager.getTicketByIP('193.168.0.128'), self.__ticket)
		self.assertEqual(self.__banManager.getTicketByIP('193.168.0.128'), None)
		# getTicket by IP removes it from list
		self.assertEqual(self.__banManager.flushBanList(), [self.__ticket_v6])
		self.assertEqual(self.__banManager.flushBanList(), [])
	
	def testInListOK_v6(self):
		ticket = BanTicket('2001:620:618:1a6:1:80b2:a60a:2', socket.AF_INET6, 1167605999.0)
		self.assertTrue(self.__banManager.inBanList(ticket))
		self.assertEqual(self.__banManager.getBanList(), ['193.168.0.128', '2001:620:618:1a6:1:80b2:a60a:2'])
		self.assertEqual(self.__banManager.getBanTotal(), 2)
		self.__banManager.setBanTotal(0)
		self.assertEqual(self.__banManager.getBanTotal(),0)
		self.assertEqual(self.__banManager.getTicketByIP('2001:620:618:1a6:1:80b2:a60a:2'), self.__ticket_v6)
		# getTicket by IP removes it from list
		self.assertEqual(self.__banManager.unBanList(1167605999.0 + self.__banManager.getBanTime()), [])
		self.assertEqual(self.__banManager.unBanList(1167605999.0 + self.__banManager.getBanTime() + 1),
						[self.__ticket])

	def testInListNOK(self):
		ticket = BanTicket('111.111.1.111', socket.AF_INET, 1167605999.0)
		self.assertFalse(self.__banManager.inBanList(ticket))
		
	def testInListNOK_v6(self):
		ticket = BanTicket('2005:620:618:1a6:1:80b2:a60a:2', socket.AF_INET6, 1167605999.0)
		self.assertFalse(self.__banManager.inBanList(ticket))

	def testGettersAndSetters(self):
		self.__banManager.setBanTime(5)
		self.assertEqual(self.__banManager.getBanTime(),5)
		self.__banManager.setBanTime("15")
		self.assertEqual(self.__banManager.getBanTime(),15)

	def testCreateBanTicket(self):
		ft = FailTicket('192.168.3.3', socket.AF_INET, 1124013541.0, matches=['hi','o'], prefix=96)
		ft.setAttempt(7)
		bt = BanManager.createBanTicket(ft)
		self.assertEqual(bt.getFamily(), socket.AF_INET)
		self.assertEqual(bt.getIP(), '192.168.3.3')
		self.assertEqual(bt.getTime(), MyTime.time())
		self.assertEqual(str(bt), 'server.ticket.BanTicket: ip=192.168.3.3 family=2 time=%d #attempts=7' % MyTime.time())
		self.assertEqual(bt.getMatches(), ['hi','o'])
		self.assertEqual(bt.getAttempt(), 7)
		self.assertEqual(bt.getPrefix(), 96)
