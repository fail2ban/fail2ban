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
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

# Author: Cyril Jaquier
# 
# $Revision$

__author__ = "Cyril Jaquier"
__version__ = "$Revision$"
__date__ = "$Date$"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import unittest, socket, time, pickle
from server.banmanager import BanManager
from server.banticket import BanTicket

class AddFailure(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""
		self.ticket = BanTicket('193.168.0.128', 1167605999.0)
		self.banManager = BanManager()
		self.assertTrue(self.banManager.addBanTicket(self.ticket))

	def tearDown(self):
		"""Call after every test case."""
	
	def testAdd(self):
		self.assertEqual(self.banManager.size(), 1)
	
	def testAddDuplicate(self):
		self.assertFalse(self.banManager.addBanTicket(self.ticket))
		self.assertEqual(self.banManager.size(), 1)
		
	def _testInListOK(self):
		ticket = BanTicket('193.168.0.128', 1167605999.0)
		self.assertTrue(self.banManager.inBanList(ticket))
	
	def _testInListNOK(self):
		ticket = BanTicket('111.111.1.111', 1167605999.0)
		self.assertFalse(self.banManager.inBanList(ticket))
		