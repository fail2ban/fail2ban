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

from ..server import failmanager
from ..server.failmanager import FailManager, FailManagerEmpty
from ..server.ipdns import IPAddr
from ..server.ticket import FailTicket


class AddFailure(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""
		super(AddFailure, self).setUp()
		self.__items = None
		self.__failManager = FailManager()

	def tearDown(self):
		"""Call after every test case."""
		super(AddFailure, self).tearDown()
		
	def _addDefItems(self):
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
		for i in self.__items:
			self.__failManager.addFailure(FailTicket(i[0], i[1]))

	def testFailManagerAdd(self):
		self._addDefItems()
		self.assertEqual(self.__failManager.size(), 3)
		self.assertEqual(self.__failManager.getFailTotal(), 13)
		self.__failManager.setFailTotal(0)
		self.assertEqual(self.__failManager.getFailTotal(), 0)
		self.__failManager.setFailTotal(13)
	
	def testFailManagerAdd_MaxEntries(self):
		maxEntries = 2
		self.__failManager.maxEntries = maxEntries
		failures = ["abc\n", "123\n", "ABC\n", "1234\n"]
		# add failures sequential:
		i = 80
		for f in failures:
			i -= 10
			ticket = FailTicket("127.0.0.1", 1000002000 - i, [f])
			ticket.setAttempt(1)
			self.__failManager.addFailure(ticket)
		#
		manFailList = self.__failManager._FailManager__failList
		self.assertEqual(len(manFailList), 1)
		ticket = manFailList["127.0.0.1"]
		# should retrieve 2 matches only, but count of all attempts (4):
		self.assertEqual(ticket.getAttempt(), len(failures))
		self.assertEqual(len(ticket.getMatches()), maxEntries)
		self.assertEqual(ticket.getMatches(), failures[len(failures) - maxEntries:])
    # add more failures at once:
		ticket = FailTicket("127.0.0.1", 1000002000 - 10, failures)
		ticket.setAttempt(len(failures))
		self.__failManager.addFailure(ticket)
		#
		manFailList = self.__failManager._FailManager__failList
		self.assertEqual(len(manFailList), 1)
		ticket = manFailList["127.0.0.1"]
		# should retrieve 2 matches only, but count of all attempts (8):
		self.assertEqual(ticket.getAttempt(), 2 * len(failures))
		self.assertEqual(len(ticket.getMatches()), maxEntries)
		self.assertEqual(ticket.getMatches(), failures[len(failures) - maxEntries:])
		# add self ticket again:
		self.__failManager.addFailure(ticket)
		#
		manFailList = self.__failManager._FailManager__failList
		self.assertEqual(len(manFailList), 1)
		ticket = manFailList["127.0.0.1"]
		# same matches, but +1 attempt (9)
		self.assertEqual(ticket.getAttempt(), 2 * len(failures) + 1)
		self.assertEqual(len(ticket.getMatches()), maxEntries)
		self.assertEqual(ticket.getMatches(), failures[len(failures) - maxEntries:])
	
	def testFailManagerMaxTime(self):
		self._addDefItems()
		self.assertEqual(self.__failManager.getMaxTime(), 600)
		self.__failManager.setMaxTime(13)
		self.assertEqual(self.__failManager.getMaxTime(), 13)
		self.__failManager.setMaxTime(600)

	def testDel(self):
		self._addDefItems()
		self.__failManager.delFailure('193.168.0.128')
		self.__failManager.delFailure('111.111.1.111')
		
		self.assertEqual(self.__failManager.size(), 2)
		
	def testCleanupOK(self):
		self._addDefItems()
		timestamp = 1167606999.0
		self.__failManager.cleanup(timestamp)
		self.assertEqual(self.__failManager.size(), 0)
		
	def testCleanupNOK(self):
		self._addDefItems()
		timestamp = 1167605990.0
		self.__failManager.cleanup(timestamp)
		self.assertEqual(self.__failManager.size(), 2)
	
	def testbanOK(self):
		self._addDefItems()
		self.__failManager.setMaxRetry(5)
		#ticket = FailTicket('193.168.0.128', None)
		ticket = self.__failManager.toBan()
		self.assertEqual(ticket.getIP(), "193.168.0.128")
		self.assertTrue(isinstance(ticket.getIP(), (str, IPAddr)))

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
		self._addDefItems()
		self.__failManager.setMaxRetry(10)
		self.assertRaises(FailManagerEmpty, self.__failManager.toBan)

	def testWindow(self):
		self._addDefItems()
		ticket = self.__failManager.toBan()
		self.assertNotEqual(ticket.getIP(), "100.100.10.10")
		ticket = self.__failManager.toBan()
		self.assertNotEqual(ticket.getIP(), "100.100.10.10")
		self.assertRaises(FailManagerEmpty, self.__failManager.toBan)

	def testBgService(self):
		bgSvc = self.__failManager._FailManager__bgSvc
		failManager2nd = FailManager()
		# test singleton (same object):
		bgSvc2 = failManager2nd._FailManager__bgSvc
		self.assertTrue(id(bgSvc) == id(bgSvc2))
		bgSvc2 = None
		# test service :
		self.assertTrue(bgSvc.service(True, True))
		self.assertFalse(bgSvc.service())
		# bypass threshold and time:
		for i in range(1, bgSvc._BgService__threshold):
			self.assertFalse(bgSvc.service())
		# bypass time check:
		bgSvc._BgService__serviceTime = -0x7fffffff
		self.assertTrue(bgSvc.service())
		# bypass threshold and time:
		bgSvc._BgService__serviceTime = -0x7fffffff
		for i in range(1, bgSvc._BgService__threshold):
			self.assertFalse(bgSvc.service())
		self.assertTrue(bgSvc.service(False, True))
		self.assertFalse(bgSvc.service(False, True))


class FailmanagerComplex(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""
		super(FailmanagerComplex, self).setUp()
		self.__failManager = FailManager()
		# down logging level for all this tests, because of extremely large failure count (several GB on heavydebug)
		self.__saved_ll = failmanager.logLevel
		failmanager.logLevel = 3

	def tearDown(self):
		super(FailmanagerComplex, self).tearDown()
		# restore level
		failmanager.logLevel = self.__saved_ll

	@staticmethod
	def _ip_range(maxips):
		class _ip(list):
			def __str__(self):
				return '.'.join(map(str, self))
			def __repr__(self):
				return str(self)
			def __key__(self):
				return str(self)
			def __hash__(self):
				#return (int)(struct.unpack('I', struct.pack("BBBB",*self))[0])
				return (int)(self[0] << 24 | self[1] << 16 | self[2] << 8 | self[3])
		i = 0
		c = [127,0,0,0]
		while i < maxips:
			for n in range(3,0,-1):
				if c[n] < 255:
					c[n] += 1
					break
				c[n] = 0
			yield (i, _ip(c))
			i += 1

	def testCheckIPGenerator(self):
		for i, ip in self._ip_range(65536 if not unittest.F2B.fast else 1000):
			if i == 254:
				self.assertEqual(str(ip), '127.0.0.255')
			elif i == 255:
				self.assertEqual(str(ip), '127.0.1.0')
			elif i == 1000:
				self.assertEqual(str(ip), '127.0.3.233')
			elif i == 65534:
				self.assertEqual(str(ip), '127.0.255.255')
			elif i == 65535:
				self.assertEqual(str(ip), '127.1.0.0')

