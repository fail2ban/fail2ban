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

# Fail2Ban developers

__copyright__ = "Copyright (c) 2004 Cyril Jaquier; 2012 Yaroslav Halchenko"
__license__ = "GPL"

import unittest
import time

from server.filterpoll import FilterPoll
from server.filter import FileFilter, DNSUtils
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
		pass

	#def testOpen(self):
	#	self.__filter.openLogFile(LogFile.FILENAME)

	def testIsModified(self):
		self.assertTrue(self.__filter.isModified(LogFile.FILENAME))


class GetFailures(unittest.TestCase):

	FILENAME_01 = "testcases/files/testcase01.log"
	FILENAME_02 = "testcases/files/testcase02.log"
	FILENAME_03 = "testcases/files/testcase03.log"
	FILENAME_04 = "testcases/files/testcase04.log"
	FILENAME_USEDNS = "testcases/files/testcase-usedns.log"

	def setUp(self):
		"""Call before every test case."""
		self.__filter = FileFilter(None)
		self.__filter.setActive(True)
		# TODO Test this
		#self.__filter.setTimeRegex("\S{3}\s{1,2}\d{1,2} \d{2}:\d{2}:\d{2}")
		#self.__filter.setTimePattern("%b %d %H:%M:%S")

	def tearDown(self):
		"""Call after every test case."""

	def _assertEqualEntries(self, found, output):
		"""Little helper to unify comparisons with the target entries

		and report helpful failure reports instead of millions of seconds ;)
		"""
		self.assertEqual(found[:2], output[:2])
		found_time, output_time = \
					time.localtime(found[2]),\
					time.localtime(output[2])
		self.assertEqual(found_time, output_time)
		if len(output) > 3:				# match matches
			self.assertEqual(repr(found[3]), repr(output[3]))

	def _assertCorrectLastAtempt(self, filter_, output):
		"""Additional helper to wrap most common test case

		Test filter to contain target ticket
		"""
		ticket = filter_.failManager.toBan()

		attempts = ticket.getAttempt()
		date = ticket.getTime()
		ip = ticket.getIP()
		matches = ticket.getMatches()
		found = (ip, attempts, date, matches)

		self._assertEqualEntries(found, output)


	def testGetFailures01(self):
		output = ('193.168.0.128', 3, 1124013599.0,
				  ['Aug 14 11:59:59 [sshd] error: PAM: Authentication failure for kevin from 193.168.0.128\n']*3)

		self.__filter.addLogPath(GetFailures.FILENAME_01)
		self.__filter.addFailRegex("(?:(?:Authentication failure|Failed [-/\w+]+) for(?: [iI](?:llegal|nvalid) user)?|[Ii](?:llegal|nvalid) user|ROOT LOGIN REFUSED) .*(?: from|FROM) <HOST>")
		self.__filter.getFailures(GetFailures.FILENAME_01)
		self._assertCorrectLastAtempt(self.__filter, output)


	def testGetFailures02(self):
		output = ('141.3.81.106', 4, 1124013539.0,
				  ['Aug 14 11:%d:59 i60p295 sshd[12365]: Failed publickey for roehl from ::ffff:141.3.81.106 port 51332 ssh2\n'
				   % m for m in 53, 54, 57, 58])

		self.__filter.addLogPath(GetFailures.FILENAME_02)
		self.__filter.addFailRegex("Failed .* from <HOST>")
		self.__filter.getFailures(GetFailures.FILENAME_02)
		self._assertCorrectLastAtempt(self.__filter, output)

	def testGetFailures03(self):
		output = ('203.162.223.135', 6, 1124013544.0)

		self.__filter.addLogPath(GetFailures.FILENAME_03)
		self.__filter.addFailRegex("error,relay=<HOST>,.*550 User unknown")
		self.__filter.getFailures(GetFailures.FILENAME_03)
		self._assertCorrectLastAtempt(self.__filter, output)

	def testGetFailures04(self):
		output = [('212.41.96.186', 4, 1124013600.0),
				  ('212.41.96.185', 4, 1124013598.0)]

		self.__filter.addLogPath(GetFailures.FILENAME_04)
		self.__filter.addFailRegex("Invalid user .* <HOST>")
		self.__filter.getFailures(GetFailures.FILENAME_04)

		try:
			for i, out in enumerate(output):
				self._assertCorrectLastAtempt(self.__filter, out)
		except FailManagerEmpty:
			pass

	def testGetFailuresUseDNS(self):
		# We should still catch failures with usedns = no ;-)
		output_yes = ('192.0.43.10', 2, 1124013539.0,
					  ['Aug 14 11:54:59 i60p295 sshd[12365]: Failed publickey for roehl from example.com port 51332 ssh2\n',
					   'Aug 14 11:58:59 i60p295 sshd[12365]: Failed publickey for roehl from ::ffff:192.0.43.10 port 51332 ssh2\n'])

		output_no = ('192.0.43.10', 1, 1124013539.0,
					  ['Aug 14 11:58:59 i60p295 sshd[12365]: Failed publickey for roehl from ::ffff:192.0.43.10 port 51332 ssh2\n'])

		# Actually no exception would be raised -- it will be just set to 'no'
		#self.assertRaises(ValueError,
		#				  FileFilter, None, useDns='wrong_value_for_useDns')

		for useDns, output in (('yes',  output_yes),
							   ('no',   output_no),
							   ('warn', output_yes)):
			filter_ = FileFilter(None, useDns=useDns)
			filter_.setActive(True)
			filter_.failManager.setMaxRetry(1)	# we might have just few failures

			filter_.addLogPath(GetFailures.FILENAME_USEDNS)
			filter_.addFailRegex("Failed .* from <HOST>")
			filter_.getFailures(GetFailures.FILENAME_USEDNS)
			self._assertCorrectLastAtempt(filter_, output)



	def testGetFailuresMultiRegex(self):
		output = ('141.3.81.106', 8, 1124013541.0)

		self.__filter.addLogPath(GetFailures.FILENAME_02)
		self.__filter.addFailRegex("Failed .* from <HOST>")
		self.__filter.addFailRegex("Accepted .* from <HOST>")
		self.__filter.getFailures(GetFailures.FILENAME_02)
		self._assertCorrectLastAtempt(self.__filter, output)

	def testGetFailuresIgnoreRegex(self):
		output = ('141.3.81.106', 8, 1124013541.0)

		self.__filter.addLogPath(GetFailures.FILENAME_02)
		self.__filter.addFailRegex("Failed .* from <HOST>")
		self.__filter.addFailRegex("Accepted .* from <HOST>")
		self.__filter.addIgnoreRegex("for roehl")

		self.__filter.getFailures(GetFailures.FILENAME_02)

		self.assertRaises(FailManagerEmpty, self.__filter.failManager.toBan)

class DNSUtilsTests(unittest.TestCase):

	def testUseDns(self):
		res = DNSUtils.textToIp('www.example.com', 'no')
		self.assertEqual(res, [])
		res = DNSUtils.textToIp('www.example.com', 'warn')
		self.assertEqual(res, ['192.0.43.10'])
		res = DNSUtils.textToIp('www.example.com', 'yes')
		self.assertEqual(res, ['192.0.43.10'])

	def testTextToIp(self):
		# Test hostnames
		hostnames = [
			'www.example.com',
			'doh1.2.3.4.buga.xxxxx.yyy.invalid',
			'1.2.3.4.buga.xxxxx.yyy.invalid',
			]
		for s in hostnames:
			res = DNSUtils.textToIp(s, 'yes')
			if s == 'www.example.com':
				self.assertEqual(res, ['192.0.43.10'])
			else:
				self.assertEqual(res, [])
