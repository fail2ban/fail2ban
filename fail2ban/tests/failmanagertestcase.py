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

from ..server.failmanager import FailManager, FailManagerEmpty
from ..server.ticket import FailTicket


class AddFailure(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""
		self.__items = [[u'193.168.0.128', 1167605999.0],
					    [u'193.168.0.128', 1167605999.0],
					    [u'193.168.0.128', 1167605999.0],
					    [u'193.168.0.128', 1167605999.0],
					    [u'193.168.0.128', 1167605999.0],
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
	
	def testFailManagerAdd(self):
		self.assertEqual(self.__failManager.size(), 3)
		self.assertEqual(self.__failManager.getFailTotal(), 13)
		self.__failManager.setFailTotal(0)
		self.assertEqual(self.__failManager.getFailTotal(), 0)
		self.__failManager.setFailTotal(13)
	
	def testFailManagerMaxTime(self):
		self.assertEqual(self.__failManager.getMaxTime(), 600)
		self.__failManager.setMaxTime(13)
		self.assertEqual(self.__failManager.getMaxTime(), 13)
		self.__failManager.setMaxTime(600)

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
		self.assertTrue(isinstance(ticket.getIP(), str))

		# finish with rudimentary tests of the ticket
		# verify consistent str
		ticket_str = str(ticket)
		ticket_repr = repr(ticket)
		self.assertEqual(
			ticket_str,
			'FailTicket: ip=193.168.0.128 time=1167605999.0 #attempts=5 matches=[]')
		self.assertEqual(
			ticket_repr,
			'FailTicket: ip=193.168.0.128 time=1167605999.0 #attempts=5 matches=[]')
		self.assertFalse(not ticket)
		# and some get/set-ers otherwise not tested
		ticket.setTime(1000002000.0)
		self.assertEqual(ticket.getTime(), 1000002000.0)
		# and str() adjusted correspondingly
		self.assertEqual(
			str(ticket),
			'FailTicket: ip=193.168.0.128 time=1000002000.0 #attempts=5 matches=[]')
	
	def testbanNOK(self):
		self.__failManager.setMaxRetry(10)
		self.assertRaises(FailManagerEmpty, self.__failManager.toBan)

	def testWindow(self):
		ticket = self.__failManager.toBan()
		self.assertNotEqual(ticket.getIP(), "100.100.10.10")
		ticket = self.__failManager.toBan()
		self.assertNotEqual(ticket.getIP(), "100.100.10.10")
		self.assertRaises(FailManagerEmpty, self.__failManager.toBan)
