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
# $Revision: 731 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 731 $"
__date__ = "$Date: 2009-02-09 23:08:21 +0100 (Mon, 09 Feb 2009) $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import unittest, socket, time, pickle
from server.failmanager import FailManager, FailManagerEmpty
from server.ticket import FailTicket

class AddFailure(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""
		self.__items = [['193.168.0.128', 1167605999.0],
					    ['193.168.0.128', 1167605999.0],
					    ['193.168.0.128', 1167605999.0],
					    ['193.168.0.128', 1167605999.0],
					    ['193.168.0.128', 1167605999.0],
					    ['87.142.124.10', 1167605999.0],
					    ['87.142.124.10', 1167605999.0],
					    ['87.142.124.10', 1167605999.0],
					    ['100.100.10.10', 1000000000.0],
					    ['100.100.10.10', 1000000500.0],
					    ['100.100.10.10', 1000001000.0],
					    ['100.100.10.10', 1000001500.0],
					    ['100.100.10.10', 1000002000.0]]
		
		self.__failManager = FailManager()
		for i in self.__items:
			self.__failManager.addFailure(FailTicket(i[0], i[1]))

	def tearDown(self):
		"""Call after every test case."""
	
	def testAdd(self):
		self.assertEqual(self.__failManager.size(), 3)
	
	def _testDel(self):
		self.__failManager.delFailure('193.168.0.128')
		self.__failManager.delFailure('111.111.1.111')
		
		self.assertEqual(self.__failManager.size(), 1)
		
	def testCleanupOK(self):
		timestamp = 1167606999.0
		self.__failManager.cleanup(timestamp)
		self.assertEqual(self.__failManager.size(), 0)
		
	def testCleanupNOK(self):
		timestamp = 1167605990.0
		self.__failManager.cleanup(timestamp)
		self.assertEqual(self.__failManager.size(), 2)
	
	def testbanOK(self):
		self.__failManager.setMaxRetry(5)
		#ticket = FailTicket('193.168.0.128', None)
		ticket = self.__failManager.toBan()
		self.assertEqual(ticket.getIP(), "193.168.0.128")
	
	def testbanNOK(self):
		self.__failManager.setMaxRetry(10)
		self.assertRaises(FailManagerEmpty, self.__failManager.toBan)

	def testWindow(self):
		ticket = self.__failManager.toBan()
		self.assertNotEqual(ticket.getIP(), "100.100.10.10")
		ticket = self.__failManager.toBan()
		self.assertNotEqual(ticket.getIP(), "100.100.10.10")
		self.assertRaises(FailManagerEmpty, self.__failManager.toBan)
