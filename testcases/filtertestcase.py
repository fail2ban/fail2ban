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
# $Revision: 728 $

__author__ = "Cyril Jaquier"
__version__ = "$Revision: 728 $"
__date__ = "$Date: 2009-02-08 18:31:24 +0100 (Sun, 08 Feb 2009) $"
__copyright__ = "Copyright (c) 2004 Cyril Jaquier"
__license__ = "GPL"

import unittest
from server.filterpoll import FilterPoll
from server.filter import FileFilter
from server.failmanager import FailManager
from server.failmanager import FailManagerEmpty

class IgnoreIP(unittest.TestCase):

	def setUp(self):
		"""Call before every test case."""
		self.__filter = FileFilter(None)

	def tearDown(self):
		"""Call after every test case."""

	def testIgnoreIPOK(self):
		ipList = "127.0.0.1", "192.168.0.1", "255.255.255.255", "99.99.99.99"
		for ip in ipList:
			self.__filter.addIgnoreIP(ip)
			self.assertTrue(self.__filter.inIgnoreIPList(ip))
		# Test DNS
		self.__filter.addIgnoreIP("www.epfl.ch")
		self.assertTrue(self.__filter.inIgnoreIPList("128.178.50.12"))
	
	def testIgnoreIPNOK(self):
		ipList = "", "999.999.999.999", "abcdef", "192.168.0."
		for ip in ipList:
			self.__filter.addIgnoreIP(ip)
			self.assertFalse(self.__filter.inIgnoreIPList(ip))
		# Test DNS
		self.__filter.addIgnoreIP("www.epfl.ch")
		self.assertFalse(self.__filter.inIgnoreIPList("127.177.50.10"))


class LogFile(unittest.TestCase):

	FILENAME = "testcases/files/testcase01.log"

	def setUp(self):
		"""Call before every test case."""
		self.__filter = FilterPoll(None)
		self.__filter.addLogPath(LogFile.FILENAME)

	def tearDown(self):
		"""Call after every test case."""
		
	#def testOpen(self):
	#	self.__filter.openLogFile(LogFile.FILENAME)
	
	def testIsModified(self):
		self.assertTrue(self.__filter.isModified(LogFile.FILENAME))


class GetFailures(unittest.TestCase):

	FILENAME_01 = "testcases/files/testcase01.log"
	FILENAME_02 = "testcases/files/testcase02.log"
	FILENAME_03 = "testcases/files/testcase03.log"
	FILENAME_04 = "testcases/files/testcase04.log"

	def setUp(self):
		"""Call before every test case."""
		self.__filter = FileFilter(None)
		self.__filter.setActive(True)
		# TODO Test this
		#self.__filter.setTimeRegex("\S{3}\s{1,2}\d{1,2} \d{2}:\d{2}:\d{2}")
		#self.__filter.setTimePattern("%b %d %H:%M:%S")

	def tearDown(self):
		"""Call after every test case."""
		
	def testGetFailures01(self):
		output = ('193.168.0.128', 3, 1124013599.0)
		
		self.__filter.addLogPath(GetFailures.FILENAME_01)
		self.__filter.addFailRegex("(?:(?:Authentication failure|Failed [-/\w+]+) for(?: [iI](?:llegal|nvalid) user)?|[Ii](?:llegal|nvalid) user|ROOT LOGIN REFUSED) .*(?: from|FROM) <HOST>")

		self.__filter.getFailures(GetFailures.FILENAME_01)
		
		ticket = self.__filter.failManager.toBan()

		attempts = ticket.getAttempt()
		date = ticket.getTime()
		ip = ticket.getIP()
		found = (ip, attempts, date)
		
		self.assertEqual(found, output)
	
	def testGetFailures02(self):
		output = ('141.3.81.106', 4, 1124013539.0)

		self.__filter.addLogPath(GetFailures.FILENAME_02)
		self.__filter.addFailRegex("Failed .* from <HOST>")
		
		self.__filter.getFailures(GetFailures.FILENAME_02)
		
		ticket = self.__filter.failManager.toBan()

		attempts = ticket.getAttempt()
		date = ticket.getTime()
		ip = ticket.getIP()
		found = (ip, attempts, date)
		
		self.assertEqual(found, output)

	def testGetFailures03(self):
		output = ('203.162.223.135', 6, 1124013544.0)

		self.__filter.addLogPath(GetFailures.FILENAME_03)
		self.__filter.addFailRegex("error,relay=<HOST>,.*550 User unknown")
		
		self.__filter.getFailures(GetFailures.FILENAME_03)
		
		ticket = self.__filter.failManager.toBan()
		
		attempts = ticket.getAttempt()
		date = ticket.getTime()
		ip = ticket.getIP()
		found = (ip, attempts, date)
		
		self.assertEqual(found, output)	

	def testGetFailures04(self):
		output = [('212.41.96.186', 4, 1124013600.0),
				  ('212.41.96.185', 4, 1124013598.0)]

		self.__filter.addLogPath(GetFailures.FILENAME_04)
		self.__filter.addFailRegex("Invalid user .* <HOST>")
		
		self.__filter.getFailures(GetFailures.FILENAME_04)

		try:
			for i in range(2):
				ticket = self.__filter.failManager.toBan()		
				attempts = ticket.getAttempt()
				date = ticket.getTime()
				ip = ticket.getIP()
				found = (ip, attempts, date)
				self.assertEqual(found, output[i])
		except FailManagerEmpty:
			pass
		
	def testGetFailuresMultiRegex(self):
		output = ('141.3.81.106', 8, 1124013541.0)

		self.__filter.addLogPath(GetFailures.FILENAME_02)
		self.__filter.addFailRegex("Failed .* from <HOST>")
		self.__filter.addFailRegex("Accepted .* from <HOST>")
		
		self.__filter.getFailures(GetFailures.FILENAME_02)
		
		ticket = self.__filter.failManager.toBan()

		attempts = ticket.getAttempt()
		date = ticket.getTime()
		ip = ticket.getIP()
		found = (ip, attempts, date)
		
		self.assertEqual(found, output)
	
	def testGetFailuresIgnoreRegex(self):
		output = ('141.3.81.106', 8, 1124013541.0)

		self.__filter.addLogPath(GetFailures.FILENAME_02)
		self.__filter.addFailRegex("Failed .* from <HOST>")
		self.__filter.addFailRegex("Accepted .* from <HOST>")
		self.__filter.addIgnoreRegex("for roehl")
		
		self.__filter.getFailures(GetFailures.FILENAME_02)
		
		self.assertRaises(FailManagerEmpty, self.__filter.failManager.toBan)
